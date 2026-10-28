import { cat, hex, unhex } from "../../dstack-compat/secret-release/policy.mjs";

export const canonical = (o) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]])));
export const grantBytes = (g) => new TextEncoder().encode(canonical(g));

// The libp2p identity multihash contains the protobuf Ed25519 public key.
export async function verifyRequest(r, peerBytes) {
  const pub = peerBytes(r.client_peer);
  if (pub.length !== 38 || hex(pub.slice(0, 6)) !== "002408011220") throw new Error("refused: inline Ed25519 client key required");
  if (!/^[0-9a-f]{32}$/.test(r.nonce) || !/^[0-9a-f]{128}$/.test(r.sig)) throw new Error("refused: signed nonce required");
  const key = await crypto.subtle.importKey("raw", pub.slice(6), "Ed25519", false, ["verify"]);
  const fields = { amount: r.amount ?? r.bytes, client_peer: r.client_peer, nonce: r.nonce,
    relay_peer: r.relay_peer, unit: r.unit ?? "bytes" };
  if (!await crypto.subtle.verify("Ed25519", key, unhex(r.sig), grantBytes(fields))) throw new Error("refused: client signature");
  return fields;
}

// The seed is the project-scoped Ed25519 value returned by dstack GetKey.
export async function signingKey(seed) {
  if (!/^[0-9a-f]{64}$/.test(seed)) throw new Error("GRANT_SEED must be 32 bytes from dstack GetKey");
  const priv = await crypto.subtle.importKey("pkcs8", cat(unhex("302e020100300506032b657004220420"), unhex(seed)), "Ed25519", true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  const public_key = hex(Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
  return { priv, public_key };
}

export async function signGrant(key, fields) {
  const g = { v: 1, grant_id: hex(crypto.getRandomValues(new Uint8Array(16))), ...fields };
  const sig = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", key.priv, grantBytes(g))));
  return { ...g, sig };
}
