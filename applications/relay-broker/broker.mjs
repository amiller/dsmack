import { peerBytes, verifyRelay } from "./attestation.mjs";
import { signGrant, verifyRequest } from "./grants.mjs";
import { nodeStatus } from "./node-status.mjs";

export class Refused extends Error {
  constructor(message, status = 403) { super(message); this.status = status; }
}
const require = (ok, message, status) => { if (!ok) throw new Refused(message, status); };
// The free Mac pool registers its approved compute tuples without paid admission.
async function registerDiagnostic(b, r) {
  const checked = await verifyRelay(r, { ...b.cfg, workloads: b.cfg.sandboxDiagnosticWorkloads }, b.chain, b.now());
  require(Number.isSafeInteger(r.admit_until) && r.admit_until > 0, "diagnostic_admission_deadline");
  const keys = ["relay_peer", "relay_maddr", "manifest_sha256", "os_image_hash", "cdhash", "receipt_key", "secret_key", "admit_until"];
  const out = { ...Object.fromEntries(keys.filter((k) => r[k] !== undefined).map((k) => [k, r[k]])), kind: "compute", proof: r.attestation,
    attestation: { status: "verified", ...checked }, expires_at: b.now() + limits.compute_lease_seconds, operator_diagnostic: true };
  b.relays.set(r.relay_peer, out);
  return out;
}

export const limits = { relay_lease_seconds: 60, compute_lease_seconds: 120, grant_seconds: 300, max_seconds: 1800, max_bytes: 64 * 1024 * 1024, grants_per_hour: 4 };

export class Broker {
  constructor({ cfg, chain, key, credits = {}, saveCredits, payments, inference, providerEnvironment, now = () => Math.floor(Date.now() / 1000) }) {
    this.payments = payments;
    this.inference = inference;
    this.providerEnvironment = providerEnvironment;
    this.cfg = cfg; this.chain = chain; this.key = key;
    this.credits = credits; this.saveCredits = saveCredits; this.now = now;
    this.relays = new Map();
    this.pending = Promise.resolve();
  }

  live() {
    const now = this.now();
    for (const [id, r] of this.relays) if (r.expires_at <= now) this.relays.delete(id);
    return [...this.relays.values()].filter((r) => !r.admit_until || r.admit_until > now);
  }

  async register(r) {
    const now = this.now();
    const telemetry = await nodeStatus(r, now);
    if(!r.payments && r.kind==='compute' && this.cfg.sandboxDiagnosticWorkloads?.some(w=>['manifest_sha256','os_image_hash','cdhash'].every(k=>w[k]===r[k]))) {
      const out = await registerDiagnostic(this,r);
      if (telemetry) out.telemetry = telemetry;
      return out;
    }
    require(!r.payments || this.payments, "paid admission is not configured");
    require(!this.payments || r.payments, "paid broker requires receipt key admission");
    const attestation = r.payments ? await this.payments.register(r,this.cfg) : await verifyRelay(r, this.cfg, this.chain, now);
    const out = Object.fromEntries(["relay_peer", "relay_maddr", "manifest_sha256", "os_image_hash", "cdhash"].map((k) => [k, r[k]]));
    Object.assign(out, { attestation: { status: "verified", ...attestation }, expires_at: now + (r.kind === "compute" ? limits.compute_lease_seconds : limits.relay_lease_seconds) });
    Object.assign(out, { kind: r.kind ?? "relay", receipt_key: r.receipt_key, proof: r.attestation });
    if (r.payments) out.payments = r.payments;
    if (telemetry) out.telemetry = telemetry;
    if (r.kind === "compute") {
      out.secret_key = r.secret_key;
      if (r.admit_until !== undefined) {
        require(Number.isSafeInteger(r.admit_until) && r.admit_until > 0, "node admission deadline");
        out.admit_until = r.admit_until;
      }
    }
    this.relays.set(r.relay_peer, out);
    return out;
  }

  grant(r) {
    // Serialize quota writes so concurrent requests cannot overspend the same client credit.
    const result = this.pending.then(() => this.issue(r));
    this.pending = result.then(() => {}, () => {});
    return result;
  }

  async issue(r) {
    require(!this.payments, "paid broker requires /payments/grant", 402);
    const now = this.now();
    const fields = await verifyRequest(r, peerBytes);
    const { unit, amount } = fields;
    require(unit === "bytes" || unit === "seconds", "unit must be bytes or seconds", 400);
    const maximum = unit === "bytes" ? limits.max_bytes : limits.max_seconds;
    require(Number.isSafeInteger(amount) && amount > 0 && amount <= maximum, unit + " must be 1.." + maximum, 400);
    const relay = this.live().find((x) => x.relay_peer === r.relay_peer);
    require(relay, "relay is not live and attestation-verified", 404);
    require((relay.kind === "compute") === (unit === "seconds"), "grant unit does not match node kind", 400);
    const previous = this.credits[r.client_peer];
    const credit = previous && now < previous.start + 3600 ? previous : { start: now, count: 0, bytes: 0, seconds: 0, nonces: previous?.nonces ?? [] };
    require(!(credit.nonces ?? []).includes(r.nonce), "grant request nonce replay", 409);
    require(credit.count < limits.grants_per_hour && (credit[unit] ?? 0) + amount <= maximum, "free testnet credit exhausted for this client_peer", 429);
    const grant = await signGrant(this.key, { relay_peer: r.relay_peer, client_peer: r.client_peer,
      unit, [unit]: amount, expires_at: unit === "bytes" ? Math.min(now + limits.grant_seconds, relay.expires_at) : now + limits.grant_seconds });
    // Commit quota before returning a signed grant. Disk failure must fail the request.
    const next = { ...this.credits };
    next[r.client_peer] = { ...credit, count: credit.count + 1, [unit]: (credit[unit] ?? 0) + amount,
      nonces: [...(credit.nonces ?? []), r.nonce] };
    await this.saveCredits(next);
    this.credits = next;
    return grant;
  }
}
