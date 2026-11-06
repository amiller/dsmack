import { InferenceError } from "./inference.mjs";
import { rankNodes } from "./scheduler.mjs";
import { peerBytes } from "./attestation.mjs";
import { signGrant } from "./grants.mjs";
import { receiptSigner } from "../payments/schema.mjs";
import { accrue } from "./payments.mjs";

const need = (ok, code, message, status = 400) => {
  if (!ok) throw new InferenceError(code, message, status);
};
const id = (value) => typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
const activeWindowSeconds = 60;

// A session reserves guest time from the same wallet ledger as encrypted model
// calls. Only the receipt key bound by the guest attestation can charge usage.
export class AgentSessions {
  /** @param {any} broker @param {() => Promise<any[]>} readFleet */
  constructor(broker, readFleet = async () => []) {
    this.b = broker; this.readFleet = readFleet;
    need((broker.cfg.payments?.prices?.S1?.minimumSeconds ?? 60) === 60,
      "BAD_CONFIG", "S1 minimum must be 60 seconds", 503);
    this.maxActiveSessionsPerWallet = broker.cfg.agent?.maxActiveSessionsPerWallet ?? 1;
    need(Number.isSafeInteger(this.maxActiveSessionsPerWallet) && this.maxActiveSessionsPerWallet > 0,
      "BAD_CONFIG", "maxActiveSessionsPerWallet must be a positive integer", 503);
  }
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
      // An expired stay can still be sealing its workspace before its final
      // receipt. Its successor must restore that completed head, even when a
      // different browser opens the conversation after the wall deadline.
      if (existing.some(s => s.wallet === wallet && s.conversationId === r.conversationId &&
        s.receiptSeen && !s.final && s.grant.expires_at <= b.now())) {
        throw new InferenceError("SESSION_SAVING", "workspace is still being saved; retry in 5 seconds", 409, 5);
      }
      const held = existing.filter(s => s.wallet === wallet && this.active(s));
      need(held.length < this.maxActiveSessionsPerWallet, "SESSION_ACTIVE",
        `wallet active guest limit (${this.maxActiveSessionsPerWallet}) reached; end an existing session: ${held.map(s => s.grant.grant_id).join(", ")}`, 409);
      const node = b.live().find((n) => n.kind === "compute" && n.relay_peer === r.node_peer);
      need(node?.payments?.receiptSigner && node.attestation?.nodeBinding?.binding.receiptSigner?.toLowerCase() === node.payments.receiptSigner.toLowerCase(), "NODE_NOT_LIVE", "attested guest is unavailable", 404);
      // Read the signed heartbeat and recheck occupancy inside the same ledger
      // transaction that reserves credit. Client placement hints are ignored.
      const ranked = rankNodes(b.live().filter(n => n.kind === "compute"), await this.readFleet(),
        (candidate, placement) => this.available(candidate, placement), { now: b.now() });
      const offered = ranked.find(candidate => candidate.relay_peer === node.relay_peer && candidate.available);
      need(offered, "GUEST_BUSY", "guest logical slot is busy or no longer offered", 409);
      const placement = offered.placement;
      const rate = BigInt(b.cfg.payments?.prices?.S1?.nanoUsdPerSecond ?? "15000");
      need(rate > 0n, "BAD_CONFIG", "guest second price must be positive", 503);
      const available = BigInt(b.inference.summary(wallet).remainingNanoUsd);
      // Wall lifetime belongs to the guest. A small rolling reservation funds
      // active tool seconds without locking model credit for the whole stay.
      const expires = Math.min(b.now() + 3600,
        node.payments?.runExpires ? node.payments.runExpires - 120 : node.admit_until ?? b.now() + 3600);
      const seconds = Math.max(0, expires - b.now());
      const activeBudgetSeconds = Math.min(activeWindowSeconds, seconds, Number(available / rate));
      need(activeBudgetSeconds >= 60, "CREDIT_EXHAUSTED", "wallet cannot cover the 60 second minimum", 402);
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
    const b = this.b;
    let signer;
    try { signer = receiptSigner(b.payments.cfg.escrow, r); }
    catch { throw new InferenceError("GUEST_SIGNATURE", "valid v5 guest receipt required", 403); }
    const receipt = r.receipt;
    const sessionId = BigInt(receipt.purchaseId).toString(16).padStart(32, "0");
    need(id(sessionId) && receipt.unit === 1 && BigInt(receipt.used) <= 3600n,
      "BAD_REQUEST", "guest seconds receipt required");
    const session = b.payments.state.agentSessions?.[sessionId];
    need(session, "SESSION_UNKNOWN", "unknown guest session", 403);
    need(signer.toLowerCase() === session.node.payments.receiptSigner.toLowerCase(),
      "GUEST_SIGNATURE", "receipt is not signed by the attested guest", 403);
    await b.payments.syncBalance(session.wallet);
    return await b.payments.serial(async () => {
      await this.releaseUnused();
      const s = b.payments.state.agentSessions?.[sessionId];
      need(s, "SESSION_UNKNOWN", "unknown guest session", 403);
      if (s.receipt && Object.keys(receipt).every(k => receipt[k] === s.receipt[k])) {
        return { stop: !!s.stopReason || s.final, reason: s.stopReason, guestSeconds: s.guestSeconds,
          activeBudgetSeconds: s.activeBudgetSeconds };
      }
      const used = Number(receipt.used), final = receipt.finalReceipt;
      need(receipt.endedAt >= (s.receipt?.endedAt ?? s.openedAt) && receipt.endedAt <= b.now() &&
        receipt.endedAt <= s.grant.expires_at && receipt.sequence > (s.receipt?.sequence ?? 0),
        "GUEST_USAGE", "receipt time or sequence regressed", 409);
      need(used >= s.guestSeconds && used <= s.grant.seconds && used <= s.activeBudgetSeconds,
        "GUEST_USAGE", "guest seconds must be monotonic and within the active reserved budget", 409);
      need(!s.final, "SESSION_CLOSED", "session receipt is already final", 409);
      const rate = BigInt(s.rateNanoUsdPerSecond), billed = Math.max(60, used), charge = BigInt(billed - (s.billedSeconds ?? 0)) * rate;
      const account = b.inference.account(s.wallet);
      const left = BigInt(s.reservedNanoUsd) - charge;
      need(left >= 0n, "GUEST_USAGE", "guest charge exceeds its reservation", 409);
      const stopReason = s.stopReason ?? (account.exitRequestedAt ? "credit" : s.endRequested ? "owner" :
        s.grant.expires_at <= b.now() ? "drain" : final ? "finished" : undefined);
      let reserved = final ? 0n : left;
      if (!final && !stopReason) {
        const free = BigInt(b.inference.summary(s.wallet).remainingNanoUsd);
        const cap = BigInt(Math.max(0, Math.min(used + activeWindowSeconds, s.grant.seconds) - billed)) * rate;
        const affordable = left + (free > 0n ? free : 0n);
        reserved = (cap < affordable ? cap : affordable) / rate * rate;
      }
      const activeBudgetSeconds = final ? s.activeBudgetSeconds : Math.min(s.grant.seconds, billed + Number(reserved / rate));
      const reason = stopReason ?? (activeBudgetSeconds <= used ? "credit" : undefined);
      const allocation = accrue(b.payments.state, s.wallet, s.node.payments.operator, charge, b.now());
      const updated = { ...s, receipt, signedReceipt: r, billedSeconds: billed, receiptSeen: true, guestSeconds: used, final: final,
        activeBudgetSeconds, reservedNanoUsd: String(reserved), stopReason: reason,
        ...(final ? { closedReason: s.closedReason ?? reason ?? "finished" } : {}) };
      await this.save({
        ...(allocation.operatorAccruals ? { operatorAccruals: allocation.operatorAccruals } : {}),
        inferenceCredit: { ...b.payments.state.inferenceCredit, [s.wallet]: {
          ...account, ...(allocation.prepaidSpentNanoUsd ? { prepaidSpentNanoUsd: allocation.prepaidSpentNanoUsd } : {}), spentNanoUsd: String(BigInt(account.spentNanoUsd) + charge),
          guestSeconds: String(BigInt(account.guestSeconds ?? "0") + BigInt(used - s.guestSeconds)),
        } },
        agentSessions: { ...b.payments.state.agentSessions, [sessionId]: updated },
      });
      return { stop: !!updated.stopReason || updated.final, reason: updated.stopReason,
        guestSeconds: updated.guestSeconds, activeBudgetSeconds: updated.activeBudgetSeconds ?? updated.grant.seconds };
    });
  }
}
