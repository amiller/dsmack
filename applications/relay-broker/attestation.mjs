import { cat, checkAssertion, decodeAttestation, hex, sha256, unhex } from "../../dstack-compat/secret-release/policy.mjs";

const enc = new TextEncoder();
const require = (ok, message) => { if (!ok) throw new Error("refused: " + message); };
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// libp2p's base58btc PeerId string -> multihash bytes used by ReportData.
export function peerBytes(peer) {
  require(typeof peer === "string" && peer.length >= 32 && peer.length <= 100, "PeerId");
  let n = 0n;
  for (const c of peer) {
    const d = alphabet.indexOf(c);
    require(d >= 0, "PeerId base58");
    n = n * 58n + BigInt(d);
  }
  let h = n.toString(16); if (h.length % 2) h = "0" + h;
  const b = cat(new Uint8Array(peer.match(/^1*/)[0].length), unhex(h));
  // The relay/client generate Ed25519 identity-multihashes; hashed PeerIds are also valid.
  require((b.length === 38 && hex(b.slice(0, 6)) === "002408011220") ||
    (b.length === 34 && b[0] === 0x12 && b[1] === 32), "PeerId multihash");
  return b;
}

export async function verifyRelay(r, cfg, chain, now) {
  const peer = peerBytes(r.relay_peer);
  const workload = cfg.workloads.find((w) => ["manifest_sha256", "os_image_hash", "cdhash"].every((k) => w[k] === r[k]));
  require(workload, "workload is not admitted");
  require(typeof r.relay_maddr === "string" && r.relay_maddr.length <= 512 &&
    /^\/(ip4|ip6|dns4|dns6)\/[a-zA-Z0-9.:-]+\/tcp\/[0-9]+\/p2p\/[1-9A-HJ-NP-Za-km-z]+\/p2p-circuit\/p2p\/[1-9A-HJ-NP-Za-km-z]+$/.test(r.relay_maddr) &&
    r.relay_maddr.endsWith("/p2p-circuit/p2p/" + r.relay_peer), "circuit address must target relay_peer");
  require(typeof r.attestation === "string" && r.attestation.length <= 131072, "attestation hex required");
  const a = await decodeAttestation(unhex(r.attestation));
  require(hex(a.manifest_sha256) === r.manifest_sha256, "manifest mismatch");
  require(hex(a.os_image_hash) === r.os_image_hash, "image mismatch");
  require(hex(a.caller) === hex(await sha256(enc.encode(workload.service))), "caller is not the relay service");
  require(typeof r.receipt_key === "string" && /^[0-9a-f]{64}$/.test(r.receipt_key), "receipt key must be Ed25519 hex");
  require(r.kind === undefined || r.kind === "relay" || r.kind === "compute", "node kind");
  let legacyReport;
  if (r.kind === "compute") {
    require(typeof r.secret_key === "string" && /^[0-9a-f]{128}$/.test(r.secret_key), "P-256 secret public key");
    legacyReport = cat(await sha256(cat(enc.encode("dsmack-compute-node/1"), peer, unhex(r.secret_key), unhex(r.receipt_key))), new Uint8Array(32));
  } else {
    legacyReport = cat(await sha256(cat(enc.encode("dsmack-libp2p-peer/1"), peer)), unhex(r.receipt_key));
  }
  if (r.payments) {
    require(/^[0-9a-f]{64}$/.test(r.payments.challenge), "payment admission challenge");
    const { binding } = await import("../payments/schema.mjs");
    const expected = cat(unhex(binding(r.payments, r.relay_peer, r.manifest_sha256, r.os_image_hash).slice(2)),
      await sha256(cat(legacyReport, unhex(r.payments.challenge))));
    require(hex(a.report_data) === hex(expected), "paid receipt key and challenge binding");
  } else if(r.kind === "compute") require(hex(a.report_data) === hex(legacyReport), "compute key binding");
  else {
    require(hex(a.report_data.slice(0,32))===hex(legacyReport.slice(0,32)), "PeerId binding");
    require(hex(a.report_data.slice(32))===hex(legacyReport.slice(32)), "receipt key binding");
  }
  // checkAssertion verifies the signature, enrollment lifetime, approved build, counter and canary.
  // Capture the authenticated CDHash during its category/authenticator check.
  let cdhash;
  const checkedChain = { ...chain, rpIdHash: async (cd) => { cdhash = hex(cd); return chain.rpIdHash(cd); } };
  await checkAssertion(a, checkedChain, now * 1000);
  require(cdhash === r.cdhash, "CDHash mismatch");
  const build_id = r.payments ? hex(await chain.buildId()) : undefined;
  return { build_id, run: hex(a.run), head: hex(a.head), key_id: hex(a.key_id), receipt_key: r.receipt_key, cdhash, verified_at: now };
}

// Optional off-chain enrollment, produced by enroll.py's Apple-root verification.
// Build approval and burn checks still use the configured live chain.
export function withEnrollment(chain, pins) {
  if (!pins) return chain;
  return { ...chain, key: async (kid) => {
    const p = pins.find((p) => p.kid === hex(kid));
    require(p, "unknown Apple enrollment");
    return { x: unhex(p.x), y: unhex(p.y), expires: p.expires, counter: 0, enrolled: true };
  } };
}
