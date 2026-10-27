import { peerBytes, verifyRelay } from "./attestation.mjs";
import { signGrant } from "./grants.mjs";

export class Refused extends Error {
  constructor(message, status = 403) { super(message); this.status = status; }
}
const require = (ok, message, status) => { if (!ok) throw new Refused(message, status); };
export const limits = { relay_lease_seconds: 60, grant_seconds: 300, max_bytes: 64 * 1024 * 1024, grants_per_hour: 4 };

// PAYMENT CHECK INSERTION POINT: replace free testnet authorization here.
// Per-client credit accounting below applies to every successful authorization.
export async function authorizePayment(_request) { return { credit: "free testnet" }; }

export class Broker {
  constructor({ cfg, chain, key, credits = {}, saveCredits, now = () => Math.floor(Date.now() / 1000) }) {
    this.cfg = cfg; this.chain = chain; this.key = key;
    this.credits = credits; this.saveCredits = saveCredits; this.now = now;
    this.relays = new Map();
    this.pending = Promise.resolve();
  }

  live() {
    const now = this.now();
    for (const [id, r] of this.relays) if (r.expires_at <= now) this.relays.delete(id);
    return [...this.relays.values()];
  }

  async register(r) {
    const now = this.now();
    const attestation = await verifyRelay(r, this.cfg, this.chain, now);
    const out = Object.fromEntries(["relay_peer", "relay_maddr", "manifest_sha256", "os_image_hash", "cdhash"].map((k) => [k, r[k]]));
    Object.assign(out, { attestation: { status: "verified", ...attestation }, expires_at: now + limits.relay_lease_seconds });
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
    const now = this.now();
    peerBytes(r.client_peer);
    require(Number.isSafeInteger(r.bytes) && r.bytes > 0 && r.bytes <= limits.max_bytes, "bytes must be 1..67108864", 400);
    const relay = this.live().find((x) => x.relay_peer === r.relay_peer);
    require(relay, "relay is not live and attestation-verified", 404);
    const previous = this.credits[r.client_peer];
    const credit = previous && now < previous.start + 3600 ? previous : { start: now, count: 0, bytes: 0 };
    require(credit.count < limits.grants_per_hour && credit.bytes + r.bytes <= limits.max_bytes, "free testnet credit exhausted for this client_peer", 429);
    await authorizePayment(r);
    const grant = await signGrant(this.key, { relay_peer: r.relay_peer, client_peer: r.client_peer,
      bytes: r.bytes, expires_at: Math.min(now + limits.grant_seconds, relay.expires_at) });
    // Commit quota before returning a signed grant. Disk failure must fail the request.
    const next = Object.fromEntries(Object.entries(this.credits).filter(([, c]) => now < c.start + 3600));
    next[r.client_peer] = { start: credit.start, count: credit.count + 1, bytes: credit.bytes + r.bytes };
    await this.saveCredits(next);
    this.credits = next;
    return grant;
  }
}
