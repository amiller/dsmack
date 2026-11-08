import { InferenceError } from "./inference.mjs";
import { rankNodes } from "./scheduler.mjs";
import { peerBytes } from "./attestation.mjs";
import { canonical, signGrant } from "./grants.mjs";
import { receiptSigner } from "../payments/schema.mjs";
import { accrue } from "./payments.mjs";
import { couchTerms, fundedGuestStay, verifyGuestCheckpoint } from "./guest-stay.mjs";

const need = (ok, code, message, status = 400) => {
  if (!ok) throw new InferenceError(code, message, status);
};
const id = (value) => typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
const activeWindowSeconds = 60;
const receiptClockSkewSeconds = 5;
const BROWSE = ["none", "named", "open"];
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;

// The stay names how open its couch's browser is; the host's signed heartbeat policy (operator.json "browse") bounds it.
// A host without a browse policy allows none. Package and operator hosts are always open and are not part of these terms.
export function browseTerms(host = { default: "none", max: "none" }, ask = { mode: host.default, hosts: [] }) {
  need(ask && BROWSE.includes(ask.mode) && Array.isArray(ask.hosts) && ask.hosts.length <= 64 && ask.hosts.every(h => HOST.test(h)) &&
    (ask.mode === "named" || ask.hosts.length === 0), "BAD_REQUEST", "browse must be {mode: none|named|open, hosts: [lowercase hostnames]} (hosts only for named)");
  need(BROWSE.indexOf(ask.mode) <= BROWSE.indexOf(host.max), "BROWSE_REFUSED", `this host allows browse up to ${host.max}`, 403);
  return { mode: ask.mode, hosts: ask.hosts, nanoUsdPerSecond: String(browseRate(host, ask)) };
}

// Pricing hook (the amin's pricing replaces this): the host's posted surcharge for widening past its default.
export function browseRate(host, ask) {
  const price = host.price ?? {};
  if (ask.mode === "open" && host.default !== "open") return BigInt(price.open_nano_usd_per_second ?? 0);
  if (ask.mode === "named") return BigInt(price.named_host_nano_usd_per_second ?? 0) * BigInt(ask.hosts.length);
  return 0n;
}

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
  serving(s) {
    // A session the owner asked to end, or on a guest that is no longer live, does not hold the wallet's slot.
    // It still reserves its Mac slot (see available): the old VM may run until its hour ends.
    return this.active(s) && !s.endRequested && this.b.live().some(n => n.kind === "compute" && n.relay_peer === s.grant.relay_peer);
  }
  /** @param {{publisher: string, slot_id: number}} [placement] */
  available(node, placement = undefined) {
    // A draining broker offers no new stays; running ones continue to their end.
    return !this.b.draining && !node.telemetry?.busy && !Object.values(this.b.payments?.state.agentSessions ?? {})
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
    // A started stay whose guest stopped registering (host asleep or gone; Broker.gone) is closed at its last signed receipt: the buyer
    // keeps what was never served and the reservation is released. Seconds after that receipt are not paid.
    const unused = Object.entries(sessions).filter(([, s]) => !s.final && (s.receiptSeen
      ? this.b.gone(s.node.relay_peer)
      : (s.setupUntil ?? s.grant.expires_at) <= this.b.now()));
    if (!unused.length) return;
    const next = { ...sessions };
    for (const [key, s] of unused) next[key] = { ...s, final: true, activeBudgetSeconds: s.guestSeconds, reservedNanoUsd: "0",
      closedReason: s.receiptSeen ? "guest-unreachable" : "unused-grant-expired" };
    await this.save({ agentSessions: next });
  }
  view(s) {
    return {
      sessionId: s.grant.grant_id, conversationId: s.conversationId,
      node: s.node, placement: s.placement, handoverAt: s.node.admit_until, setupUntil: s.setupUntil,
      closedReason: s.closedReason ?? s.stopReason, seconds: s.grant.seconds, grant: s.grant,
      guestSeconds: s.guestSeconds, activeBudgetSeconds: s.activeBudgetSeconds ?? s.grant.seconds,
      ...(s.maxSpendNanoUsd !== undefined ? { maxSpendNanoUsd: s.maxSpendNanoUsd, operationId: s.operationId } : {}),
      stopReason: s.stopReason, rateNanoUsdPerSecond: s.rateNanoUsdPerSecond, browse: s.browse,
      active: this.active(s),
      endRequested: !!s.endRequested, usageUnresolved: !s.final && !!s.receiptSeen && s.grant.expires_at <= this.b.now(), ...(s.escrow ? { escrow: s.escrow, claim: s.claim, rateLaycPerSecond: s.rateLaycPerSecond } : { credit: this.b.inference.summary(s.wallet) }),
    };
  }
  async open(r) {
    const b = this.b, wallet = await b.inference.authorized(r, "agent-open");
    need(typeof r.conversationId === "string" && r.conversationId.length > 0 && r.conversationId.length <= 128,
      "BAD_REQUEST", "conversation ID required");
    need(peerBytes(r.client_peer).length === 38, "BAD_REQUEST", "inline Ed25519 browser identity required");
    const capped = r.maxSpendNanoUsd !== undefined || r.operationId !== undefined;
    need(!capped || (typeof r.maxSpendNanoUsd === "string" && /^[1-9][0-9]{0,38}$/.test(r.maxSpendNanoUsd) &&
      typeof r.operationId === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(r.operationId)),
      "BAD_REQUEST", "spend cap requires positive decimal maxSpendNanoUsd and operation UUID");
    const constraints = capped ? canonical({ conversationId: r.conversationId, client_peer: r.client_peer,
      node_peer: r.node_peer, browse: r.browse ?? null, maxSpendNanoUsd: r.maxSpendNanoUsd }) : undefined;
    return await b.payments.serial(async () => {
      const prior = capped && Object.values(b.payments.state.agentSessions ?? {}).find(s => s.wallet === wallet && s.operationId === r.operationId);
      if (prior) {
        need(prior.openConstraints === constraints, "OPERATION_CONFLICT", "operation already names different session constraints", 409);
        return this.view(prior);
      }
      await this.releaseUnused();
      const existing = Object.values(b.payments.state.agentSessions ?? {});
      // An expired stay can still be sealing its workspace before its final
      // receipt. Its successor must restore that completed head, even when a
      // different browser opens the conversation after the wall deadline.
      if (existing.some(s => s.wallet === wallet && s.conversationId === r.conversationId &&
        s.receiptSeen && !s.final && s.grant.expires_at <= b.now())) {
        throw new InferenceError("SESSION_SAVING", "workspace is still being saved; retry in 5 seconds", 409, 5);
      }
      const held = existing.filter(s => s.wallet === wallet && this.serving(s));
      need(held.length < this.maxActiveSessionsPerWallet, "SESSION_ACTIVE",
        `wallet active guest limit (${this.maxActiveSessionsPerWallet}) reached; end an existing session: ${held.map(s => s.grant.grant_id).join(", ")}`, 409);
      const node = b.live().find((n) => n.kind === "compute" && n.relay_peer === r.node_peer);
      need(node?.payments?.receiptSigner && node.attestation?.nodeBinding?.binding.receiptSigner?.toLowerCase() === node.payments.receiptSigner.toLowerCase(), "NODE_NOT_LIVE", "attested guest is unavailable", 404);
      // Read the signed heartbeat and recheck occupancy inside the same ledger
      // transaction that reserves credit. Client placement hints are ignored.
      const fleet = await this.readFleet();
      const ranked = rankNodes(b.live().filter(n => n.kind === "compute"), fleet,
        (candidate, placement) => this.available(candidate, placement), { now: b.now() });
      const offered = ranked.find(candidate => candidate.relay_peer === node.relay_peer && candidate.available);
      need(offered, "GUEST_BUSY", "guest logical slot is busy or no longer offered", 409);
      const placement = offered.placement;
      if (r.acceptedTerms !== undefined) {
        need(r.maxSpendNanoUsd === undefined && r.operationId === undefined, "BAD_REQUEST", "GuestEscrow stays use the accepted LAYC cap");
        const escrow = couchTerms(r.acceptedTerms, wallet, node, placement, r.conversationId);
        need(!existing.some(s => s.wallet === wallet && s.escrow?.termsHash === escrow.termsHash),
          "TERMS_ALREADY_USED", "use fresh accepted terms for each stay", 409);
        const t = JSON.parse(escrow.terms);
        const { nanoUsdPerSecond: _legacyBrowsePrice, ...policy } =
          browseTerms(fleet.find(m => m.publisher === placement.publisher)?.config?.browse, r.browse);
        const browse = { ...policy, token: crypto.randomUUID().replaceAll("-", "") };
        const agreedBrowse = { mode: t.browse?.mode ?? t.browse?.default ?? "none", hosts: t.browse?.hosts ?? [] };
        need(browse.mode === agreedBrowse.mode && canonical({ hosts: browse.hosts }) === canonical({ hosts: agreedBrowse.hosts }),
          "BROWSE_REFUSED", "browse policy differs from accepted terms");
        const postedRate = fleet.find(m => m.publisher === placement.publisher)?.config?.rate_layc_per_second;
        need(Number.isSafeInteger(postedRate) && postedRate > 0 && t.rate_layc_per_second === postedRate,
          "RATE_CHANGED", "accepted LAYC rate differs from the host's signed offer", 409);
        const verifiedBlock = await fundedGuestStay(b, escrow, node);
        const seconds = t.minutes * 60;
        const expires = b.now() + seconds;
        need(expires <= (node.payments.runExpires ?? 0) - 120 && expires <= (node.admit_until ?? expires),
          "NODE_NOT_LIVE", "guest must outlive the accepted stay", 409);
        const grant = await signGrant(b.key, { client_peer: r.client_peer, relay_peer: node.relay_peer,
          unit: "seconds", seconds, expires_at: expires, escrow });
        const s = { wallet, conversationId: r.conversationId, node, placement, browse, escrow, verifiedBlock,
          grant, guestSeconds: 0, activeBudgetSeconds: seconds, rateLaycPerSecond: t.rate_layc_per_second,
          reservedNanoUsd: "0", final: false, openedAt: b.now(), setupUntil: Math.min(b.now() + 90, expires) };
        await this.save({ agentSessions: { ...b.payments.state.agentSessions, [grant.grant_id]: s } });
        return this.view(s);
      }
      const base = BigInt(b.cfg.payments?.prices?.S1?.nanoUsdPerSecond ?? "15000");
      need(base > 0n, "BAD_CONFIG", "guest second price must be positive", 503);
      const browse = { ...browseTerms(fleet.find(m => m.publisher === placement.publisher)?.config?.browse, r.browse),
        token: crypto.randomUUID().replaceAll("-", "") };
      const rate = base + BigInt(browse.nanoUsdPerSecond);
      const available = BigInt(b.inference.summary(wallet).remainingNanoUsd);
      const cap = capped ? BigInt(r.maxSpendNanoUsd) : undefined;
      need(cap === undefined || cap >= 60n * rate, "BUDGET_TOO_SMALL", "spend cap cannot cover the actual rate and 60 second minimum", 402);
      // Wall lifetime belongs to the guest. A small rolling reservation funds
      // active tool seconds without locking model credit for the whole stay.
      const expires = Math.min(b.now() + 3600,
        node.payments?.runExpires ? node.payments.runExpires - 120 : node.admit_until ?? b.now() + 3600);
      const seconds = Math.max(0, expires - b.now());
      const activeBudgetSeconds = Math.min(activeWindowSeconds, seconds, Number(available / rate));
      need(activeBudgetSeconds >= 60, "CREDIT_EXHAUSTED", "wallet cannot cover the 60 second minimum", 402);
      const grant = await signGrant(b.key, { client_peer: r.client_peer,
        relay_peer: node.relay_peer, unit: "seconds", seconds, expires_at: expires });
      const s = { wallet, conversationId: r.conversationId, node, placement, browse,
        ...(capped ? { maxSpendNanoUsd: r.maxSpendNanoUsd, operationId: r.operationId, openConstraints: constraints } : {}),
        grant, guestSeconds: 0, activeBudgetSeconds, rateNanoUsdPerSecond: String(rate),
        reservedNanoUsd: String(BigInt(activeBudgetSeconds) * rate), final: false, openedAt: b.now(), setupUntil: Math.min(b.now() + 90, expires) };
      await this.save({ agentSessions: { ...b.payments.state.agentSessions, [grant.grant_id]: s } });
      return this.view(s);
    });
  }
  // The Mac's CONNECT proxy asks which policy a stay's browse token carries. It answers only for a stay placed on that
  // Mac and only while the stay is active, so a token works neither on another host nor after its stay ends.
  browsePolicy(token, publisher) {
    need(id(token) && typeof publisher === "string", "BAD_REQUEST", "browse token and publisher required");
    const s = Object.values(this.b.payments.state.agentSessions ?? {}).find(v => v.browse?.token === token);
    need(s && s.placement?.publisher.toLowerCase() === publisher.toLowerCase() && this.active(s) && !s.endRequested,
      "BROWSE_UNKNOWN", "no active stay on this Mac holds this browse token", 404);
    return { mode: s.browse.mode, hosts: s.browse.hosts, expires_at: s.grant.expires_at };
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
  async guestClaim(r) {
    const b = this.b;
    return b.payments.serial(async () => {
      const s = b.payments.state.agentSessions?.[r.sessionId];
      need(s?.escrow, "SESSION_UNKNOWN", "unknown GuestEscrow stay", 403);
      if (s.checkpoint && canonical(s.checkpoint) === canonical(r)) {
        return { stop: !!s.endRequested || s.final, guestSeconds: s.guestSeconds, activeBudgetSeconds: s.grant.seconds };
      }
      need(!s.final, "SESSION_CLOSED", "stay is already final", 409);
      await verifyGuestCheckpoint(r, s);
      need(Number.isSafeInteger(r.endedAt) && r.endedAt >= (s.checkpoint?.endedAt ?? s.openedAt - receiptClockSkewSeconds) &&
        r.endedAt <= b.now() + receiptClockSkewSeconds && r.endedAt <= s.grant.expires_at,
        "GUEST_USAGE", "guest checkpoint timestamp outside stay", 409);
      const stop = s.endRequested || r.final || b.now() >= s.grant.expires_at;
      const next = { ...s, checkpoint: r, claim: r.claim, receiptSeen: true, guestSeconds: r.guestSeconds,
        final: r.final, ...(r.final ? { closedReason: s.endRequested ? "owner" : "finished" } : {}) };
      // Store and relay the guest's original claim. No credit debit or operator accrual.
      await this.save({ agentSessions: { ...b.payments.state.agentSessions, [r.sessionId]: next } });
      return { stop: !!stop, reason: s.endRequested ? "owner" : undefined, guestSeconds: next.guestSeconds,
        activeBudgetSeconds: s.grant.seconds };
    });
  }
  async receipt(r) {
    const b = this.b;
    if (r.claim !== undefined) return this.guestClaim(r);
    let signer;
    try { signer = receiptSigner(b.payments.cfg.escrow, r); }
    catch { throw new InferenceError("GUEST_SIGNATURE", "valid v5 guest receipt required", 403); }
    const receipt = r.receipt;
    const sessionId = BigInt(receipt.purchaseId).toString(16).padStart(32, "0");
    need(id(sessionId) && receipt.unit === 1 && BigInt(receipt.used) <= 3600n,
      "BAD_REQUEST", "guest seconds receipt required");
    const session = b.payments.state.agentSessions?.[sessionId];
    need(session, "SESSION_UNKNOWN", "unknown guest session", 403);
    need(!session.escrow, "GUEST_SIGNATURE", "GuestEscrow stay requires a guest claim", 403);
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
      need(receipt.sequence > (s.receipt?.sequence ?? 0),
        "GUEST_USAGE", "receipt sequence regressed", 409);
      // Guest and broker clocks are independent. Keep guest-to-guest ordering
      // strict, but allow small skew against the broker's wall clock. Usage is
      // signed separately and remains bounded by the reserved active budget.
      need(receipt.endedAt >= (s.receipt?.endedAt ?? s.openedAt - receiptClockSkewSeconds) &&
        receipt.endedAt <= b.now() + receiptClockSkewSeconds && receipt.endedAt <= s.grant.expires_at,
        "GUEST_USAGE", "receipt timestamp outside stay bounds or regressed", 409);
      need(used >= s.guestSeconds && used <= s.grant.seconds && used <= s.activeBudgetSeconds,
        "GUEST_USAGE", "guest seconds must be monotonic and within the active reserved budget", 409);
      need(!s.final, "SESSION_CLOSED", "session receipt is already final", 409);
      const rate = BigInt(s.rateNanoUsdPerSecond), billed = Math.max(60, used), charge = BigInt(billed - (s.billedSeconds ?? 0)) * rate;
      const capSeconds = s.maxSpendNanoUsd === undefined ? s.grant.seconds : Number(BigInt(s.maxSpendNanoUsd) / rate > BigInt(s.grant.seconds)
        ? BigInt(s.grant.seconds) : BigInt(s.maxSpendNanoUsd) / rate);
      need(billed <= capSeconds, "GUEST_USAGE", "guest charge exceeds signed session cap", 409);
      const account = b.inference.account(s.wallet);
      const left = BigInt(s.reservedNanoUsd) - charge;
      need(left >= 0n, "GUEST_USAGE", "guest charge exceeds its reservation", 409);
      const stopReason = s.stopReason ?? (account.exitRequestedAt ? "credit" : s.endRequested ? "owner" :
        s.grant.expires_at <= b.now() ? "drain" : final ? "finished" : undefined);
      let reserved = final ? 0n : left;
      if (!final && !stopReason) {
        const free = BigInt(b.inference.summary(s.wallet).remainingNanoUsd);
        const cap = BigInt(Math.max(0, Math.min(used + activeWindowSeconds, capSeconds) - billed)) * rate;
        const affordable = left + (free > 0n ? free : 0n);
        reserved = (cap < affordable ? cap : affordable) / rate * rate;
      }
      const activeBudgetSeconds = final ? s.activeBudgetSeconds : Math.min(capSeconds, billed + Number(reserved / rate));
      const reason = stopReason ?? (activeBudgetSeconds <= used ? (s.maxSpendNanoUsd !== undefined && used >= capSeconds ? "budget" : "credit") : undefined);
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
