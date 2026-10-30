import { InferenceError } from "./inference.mjs";
import { rankNodes } from "./scheduler.mjs";
import { peerBytes } from "./attestation.mjs";
import { signGrant, canonical } from "./grants.mjs";
import { unhex } from "../../dstack-compat/secret-release/policy.mjs";

const need = (ok, code, message, status = 400) => {
  if (!ok) throw new InferenceError(code, message, status);
};
const id = (value) => typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
const activeWindowSeconds = 30;

// A session reserves guest time from the same wallet ledger as encrypted model
// calls. Only the receipt key bound by the guest attestation can charge usage.
export class AgentSessions {
  /** @param {any} broker @param {() => Promise<any[]>} readFleet */
  constructor(broker, readFleet = async () => []) { this.b = broker; this.readFleet = readFleet; }
  active(s) {
    return !s.final && s.grant.expires_at > this.b.now() &&
      (s.receiptSeen || (s.setupUntil ?? s.grant.expires_at) > this.b.now());
  }
  /** @param {any} node @param {{publisher: string, slot_id: number} | undefined} placement */
  available(node, placement = undefined) {
    return !node.telemetry?.busy && !Object.values(this.b.payments?.state.agentSessions ?? {})
      .some(s => this.active(s) &&
        (s.node.relay_peer === node.relay_peer || (placement && s.placement?.publisher === placement.publisher &&
          s.placement.slot_id === placement.slot_id)));
  }
  async save(fields) {
    const p = this.b.payments, next = { ...p.state, ...fields };
    await p.save(next); p.state = next;
  }
  async releaseUnused() {
    const sessions = this.b.payments.state.agentSessions ?? {};
    const unused = Object.entries(sessions).filter(([, s]) => !s.final && !s.receiptSeen && (s.setupUntil ?? s.grant.expires_at) <= this.b.now());
    if (!unused.length) return;
    const next = { ...sessions };
    for (const [key, s] of unused) next[key] = { ...s, final: true, activeBudgetSeconds: s.guestSeconds, reservedNanoUsd: "0", closedReason: "unused-grant-expired" };
    await this.save({ agentSessions: next });
  }
  view(s) {
    return {
      sessionId: s.grant.grant_id, conversationId: s.conversationId,
      node: s.node, placement: s.placement, handoverAt: s.node.admit_until, setupUntil: s.setupUntil,
      closedReason: s.closedReason ?? s.stopReason, seconds: s.grant.seconds, grant: s.grant,
      guestSeconds: s.guestSeconds, activeBudgetSeconds: s.activeBudgetSeconds ?? s.grant.seconds,
      stopReason: s.stopReason, rateNanoUsdPerSecond: s.rateNanoUsdPerSecond,
      active: this.active(s),
      endRequested: !!s.endRequested, usageUnresolved: !s.final && !!s.receiptSeen && s.grant.expires_at <= this.b.now(), credit: this.b.inference.summary(s.wallet),
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
      need(!existing.some((s) => s.wallet === wallet && this.active(s)), "SESSION_ACTIVE", "end the wallet's held guest first", 409);
      const node = b.live().find((n) => n.kind === "compute" && n.relay_peer === r.node_peer);
      need(node?.receipt_key && /^[0-9a-f]{64}$/.test(node.receipt_key), "NODE_NOT_LIVE", "attested guest is unavailable", 404);
      // Read the signed heartbeat and recheck occupancy inside the same ledger
      // transaction that reserves credit. Client placement hints are ignored.
      const ranked = rankNodes(b.live().filter(n => n.kind === "compute"), await this.readFleet(),
        (candidate, placement) => this.available(candidate, placement), { now: b.now() });
      const offered = ranked.find(candidate => candidate.relay_peer === node.relay_peer && candidate.available);
      need(offered, "GUEST_BUSY", "guest logical slot is busy or no longer offered", 409);
      const placement = offered.placement;
      const rate = BigInt(b.cfg.agent?.nanoUsdPerSecond ?? "10000");
      need(rate > 0n, "BAD_CONFIG", "guest second price must be positive", 503);
      const available = BigInt(b.inference.summary(wallet).remainingNanoUsd);
      // Wall lifetime belongs to the guest. A small rolling reservation funds
      // active tool seconds without locking model credit for the whole stay.
      const expires = Math.min(b.now() + 3600,
        node.payments?.runExpires ? node.payments.runExpires - 120 : node.admit_until ?? b.now() + 3600);
      const seconds = Math.max(0, expires - b.now());
      const activeBudgetSeconds = Math.min(activeWindowSeconds, seconds, Number(available / rate));
      need(activeBudgetSeconds >= 1, "CREDIT_EXHAUSTED", "wallet cannot cover a guest second", 402);
      const grant = await signGrant(b.key, { client_peer: r.client_peer,
        relay_peer: node.relay_peer, unit: "seconds", seconds, expires_at: expires });
      const s = { wallet, conversationId: r.conversationId, node, placement,
        grant, guestSeconds: 0, activeBudgetSeconds, rateNanoUsdPerSecond: String(rate),
        reservedNanoUsd: String(BigInt(activeBudgetSeconds) * rate), final: false, openedAt: b.now(), setupUntil: Math.min(b.now() + 90, expires) };
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
        // Execution cannot start before its trusted receipt is accepted. Close
        // an unadmitted grant now; any later start receipt will be refused.
        s = { ...s, endRequested: true, ...(!s.receiptSeen
          ? { final: true, activeBudgetSeconds: s.guestSeconds, reservedNanoUsd: "0", closedReason: "unused-grant-ended" }
          : {}) };
        await this.save({ agentSessions: { ...b.payments.state.agentSessions, [r.sessionId]: s } });
      }
      return this.view(s);
    });
  }
  async receipt(r) {
    const b = this.b, { sig, ...body } = r;
    const keys = Object.keys(body).sort().join();
    need((keys === "final,guestSeconds,node_peer,sessionId" ||
      (r.final === true && keys === "closedReason,final,guestSeconds,node_peer,sessionId" &&
        ["idle", "drain", "credit", "owner", "finished"].includes(r.closedReason))) && id(r.sessionId) &&
      Number.isSafeInteger(r.guestSeconds) && r.guestSeconds >= 0 && typeof r.final === "boolean" &&
      typeof sig === "string" && /^[0-9a-f]{128}$/.test(sig), "BAD_REQUEST", "guest receipt fields required");
    return await b.payments.serial(async () => {
      await this.releaseUnused();
      const s = b.payments.state.agentSessions?.[r.sessionId];
      need(s && s.node.relay_peer === r.node_peer, "SESSION_UNKNOWN", "session or guest mismatch", 403);
      const key = await crypto.subtle.importKey("raw", unhex(s.node.receipt_key), "Ed25519", false, ["verify"]);
      need(await crypto.subtle.verify("Ed25519", key, unhex(sig), new TextEncoder().encode(canonical(body))),
        "GUEST_SIGNATURE", "receipt is not signed by the attested guest", 403);
      need(r.guestSeconds >= s.guestSeconds && r.guestSeconds <= s.grant.seconds &&
        r.guestSeconds <= (s.activeBudgetSeconds ?? s.grant.seconds),
        "GUEST_USAGE", "guest seconds must be monotonic and within the active reserved budget", 409);
      need(!s.final || (r.final && r.guestSeconds === s.guestSeconds), "SESSION_CLOSED", "session receipt is already final", 409);
      // Existing records without a rolling limit already authorized and
      // reserved their whole signed grant. Settle those original receipts as-is.
      const legacyReservation = s.activeBudgetSeconds === undefined;
      const rate = BigInt(s.rateNanoUsdPerSecond), charge = BigInt(r.guestSeconds - s.guestSeconds) * rate;
      const account = b.inference.account(s.wallet);
      const left = BigInt(s.reservedNanoUsd) - charge;
      need(left >= 0n, "GUEST_USAGE", "guest charge exceeds its reservation", 409);
      const stopReason = s.stopReason ?? (s.endRequested ? "owner" :
        s.grant.expires_at <= b.now() ? "drain" : r.final ? (r.closedReason ?? "finished") : undefined);
      let reserved = r.final ? 0n : left;
      if (!r.final && !stopReason && !legacyReservation) {
        const free = BigInt(b.inference.summary(s.wallet).remainingNanoUsd);
        const cap = BigInt(Math.min(activeWindowSeconds, s.grant.seconds - r.guestSeconds)) * rate;
        const affordable = left + (free > 0n ? free : 0n);
        reserved = (cap < affordable ? cap : affordable) / rate * rate;
      }
      const activeBudgetSeconds = r.final ? (s.activeBudgetSeconds ?? s.grant.seconds) : r.guestSeconds + Number(reserved / rate);
      const reason = stopReason ?? (activeBudgetSeconds <= r.guestSeconds ? "credit" : undefined);
      const updated = { ...s, receiptSeen: true, guestSeconds: r.guestSeconds, final: r.final,
        ...(legacyReservation ? {} : { activeBudgetSeconds }), reservedNanoUsd: String(reserved), stopReason: reason,
        ...(r.final ? { closedReason: s.closedReason ?? reason ?? "finished" } : {}) };
      await this.save({
        inferenceCredit: { ...b.payments.state.inferenceCredit, [s.wallet]: {
          ...account, spentNanoUsd: String(BigInt(account.spentNanoUsd) + charge),
          guestSeconds: String(BigInt(account.guestSeconds ?? "0") + BigInt(r.guestSeconds - s.guestSeconds)),
        } },
        agentSessions: { ...b.payments.state.agentSessions, [r.sessionId]: updated },
      });
      return { stop: !!updated.stopReason || updated.final, reason: updated.stopReason,
        guestSeconds: updated.guestSeconds, activeBudgetSeconds: updated.activeBudgetSeconds ?? updated.grant.seconds };
    });
  }
}
