import { InferenceError } from "./inference.mjs";
import { peerBytes } from "./attestation.mjs";
import { signGrant, canonical } from "./grants.mjs";
import { unhex } from "../../dstack-compat/secret-release/policy.mjs";

const need = (ok, code, message, status = 400) => {
  if (!ok) throw new InferenceError(code, message, status);
};
const id = (value) => typeof value === "string" && /^[0-9a-f]{32}$/.test(value);

// A session reserves guest time from the same wallet ledger as encrypted model
// calls. Only the receipt key bound by the guest attestation can charge usage.
export class AgentSessions {
  constructor(broker) { this.b = broker; }
  async save(fields) {
    const p = this.b.payments, next = { ...p.state, ...fields };
    await p.save(next); p.state = next;
  }
  async releaseUnused() {
    const sessions = this.b.payments.state.agentSessions ?? {};
    const unused = Object.entries(sessions).filter(([, s]) => !s.final && !s.receiptSeen && s.grant.expires_at <= this.b.now());
    if (!unused.length) return;
    const next = { ...sessions };
    for (const [key, s] of unused) next[key] = { ...s, final: true, reservedNanoUsd: "0", closedReason: "unused-grant-expired" };
    await this.save({ agentSessions: next });
  }
  view(s) {
    return {
      sessionId: s.grant.grant_id, conversationId: s.conversationId,
      node: s.node, seconds: s.grant.seconds, grant: s.grant,
      guestSeconds: s.guestSeconds, rateNanoUsdPerSecond: s.rateNanoUsdPerSecond,
      active: !s.final && s.grant.expires_at > this.b.now(),
      endRequested: !!s.endRequested, usageUnresolved: !s.final && s.grant.expires_at <= this.b.now(), credit: this.b.inference.summary(s.wallet),
    };
  }
  async open(r) {
    const b = this.b, wallet = await b.inference.authorized(r, "agent-open");
    need(typeof r.conversationId === "string" && r.conversationId.length > 0 && r.conversationId.length <= 128,
      "BAD_REQUEST", "conversation ID required");
    need(peerBytes(r.client_peer).length === 38, "BAD_REQUEST", "inline Ed25519 browser identity required");
    return await b.payments.serial(async () => {
      await this.releaseUnused();
      const existing = Object.values(b.payments.state.agentSessions ?? {});
      need(!existing.some((s) => s.wallet === wallet && !s.final && s.grant.expires_at > b.now()), "SESSION_ACTIVE", "end the wallet's held guest first", 409);
      const node = b.live().find((n) => n.kind === "compute" && n.relay_peer === r.node_peer);
      need(node?.receipt_key && /^[0-9a-f]{64}$/.test(node.receipt_key), "NODE_NOT_LIVE", "attested guest is unavailable", 404);
      need(!existing.some((s) => s.node.relay_peer === node.relay_peer && !s.final && s.grant.expires_at > b.now()), "GUEST_BUSY", "guest is held by another conversation", 409);
      const rate = BigInt(b.cfg.agent?.nanoUsdPerSecond ?? "10000");
      need(rate > 0n, "BAD_CONFIG", "guest second price must be positive", 503);
      const available = BigInt(b.inference.summary(wallet).remainingNanoUsd);
      // Keep at least half the available account for the browser's model loop.
      const seconds = Math.min(1800, Number(available / (2n * rate)),
        Math.max(0, (node.admit_until ?? b.now() + 1800) - b.now()));
      need(seconds >= 1, "CREDIT_EXHAUSTED", "wallet cannot cover a guest second", 402);
      const grant = await signGrant(b.key, { client_peer: r.client_peer,
        relay_peer: node.relay_peer, unit: "seconds", seconds, expires_at: b.now() + seconds });
      const s = { wallet, conversationId: r.conversationId, node,
        grant, guestSeconds: 0, rateNanoUsdPerSecond: String(rate),
        reservedNanoUsd: String(BigInt(seconds) * rate), final: false, openedAt: b.now() };
      await this.save({ agentSessions: { ...b.payments.state.agentSessions, [grant.grant_id]: s } });
      return this.view(s);
    });
  }
  async status(r, end = false) {
    const b = this.b, wallet = await b.inference.authorized(r, end ? "agent-end" : "agent-status");
    need(id(r.sessionId), "BAD_REQUEST", "session ID required");
    return await b.payments.serial(async () => {
      await this.releaseUnused();
      let s = b.payments.state.agentSessions?.[r.sessionId];
      need(s?.wallet === wallet, "SESSION_OWNER", "session belongs to another wallet", 403);
      if (end && !s.final) {
        s = { ...s, endRequested: true };
        await this.save({ agentSessions: { ...b.payments.state.agentSessions, [r.sessionId]: s } });
      }
      return this.view(s);
    });
  }
  async receipt(r) {
    const b = this.b, { sig, ...body } = r;
    need(Object.keys(body).sort().join() === "final,guestSeconds,node_peer,sessionId" && id(r.sessionId) &&
      Number.isSafeInteger(r.guestSeconds) && r.guestSeconds >= 0 && typeof r.final === "boolean" &&
      typeof sig === "string" && /^[0-9a-f]{128}$/.test(sig), "BAD_REQUEST", "guest receipt fields required");
    return await b.payments.serial(async () => {
      const s = b.payments.state.agentSessions?.[r.sessionId];
      need(s && s.node.relay_peer === r.node_peer, "SESSION_UNKNOWN", "session or guest mismatch", 403);
      const key = await crypto.subtle.importKey("raw", unhex(s.node.receipt_key), "Ed25519", false, ["verify"]);
      need(await crypto.subtle.verify("Ed25519", key, unhex(sig), new TextEncoder().encode(canonical(body))),
        "GUEST_SIGNATURE", "receipt is not signed by the attested guest", 403);
      need(r.guestSeconds >= s.guestSeconds && r.guestSeconds <= s.grant.seconds,
        "GUEST_USAGE", "guest seconds must be monotonic and within the grant", 409);
      need(!s.final || (r.final && r.guestSeconds === s.guestSeconds), "SESSION_CLOSED", "session receipt is already final", 409);
      const charge = BigInt(r.guestSeconds - s.guestSeconds) * BigInt(s.rateNanoUsdPerSecond);
      const account = b.inference.account(s.wallet);
      const updated = { ...s, receiptSeen: true, guestSeconds: r.guestSeconds, final: r.final,
        reservedNanoUsd: r.final ? "0" : String(BigInt(s.reservedNanoUsd) - charge) };
      await this.save({
        inferenceCredit: { ...b.payments.state.inferenceCredit, [s.wallet]: {
          ...account, spentNanoUsd: String(BigInt(account.spentNanoUsd) + charge),
          guestSeconds: String(BigInt(account.guestSeconds ?? "0") + BigInt(r.guestSeconds - s.guestSeconds)),
        } },
        agentSessions: { ...b.payments.state.agentSessions, [r.sessionId]: updated },
      });
      return { stop: !!updated.endRequested || updated.final, guestSeconds: updated.guestSeconds };
    });
  }
}
