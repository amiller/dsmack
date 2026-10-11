// macOS App Attest verification in JS, ported from edge-tee/ios-app-attest verifier/core.py (Apple's
// "Validating apps that connect to your server"): pinned Apple root, Mac key ACL, CDHash allowlist on the
// enrollment AND on every assertion, validation category, app id, and the nonce binding to our client data.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

const ROOT_SHA256 = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932";
const MAC_ACL = Buffer.concat([Buffer.from("3046a3440442", "hex"), Buffer.from("MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB", "base64")]);
const AAGUID = Buffer.concat([Buffer.from("appattest"), Buffer.alloc(7)]);
// Apple's attestation leaf is a timestamp (notBefore = issuance − 24 h, notAfter = +48 h). Enrollments older than
// MAX_AGE are refused, so evidence cannot be replayed for the leaf's whole life; peers re-enroll every 6 h.
export const MAX_AGE = 12 * 3600e3;
const sha = (...b) => crypto.createHash("sha256").update(Buffer.concat(b)).digest();
const must = (ok, reason) => { if (!ok) throw new Error(`✗ refused: App Attest: ${reason}`); };

// CBOR subset: unsigned/negative ints, byte and text strings, arrays, maps, simple values.
export function cbor(buf, i = 0) {
  const read = () => {
    const ib = buf[i++], mt = ib >> 5, ai = ib & 31;
    let n = ai;
    if (ai === 24) n = buf[i++];
    else if (ai === 25) { n = buf.readUInt16BE(i); i += 2; }
    else if (ai === 26) { n = buf.readUInt32BE(i); i += 4; }
    else if (ai === 27) { n = Number(buf.readBigUInt64BE(i)); i += 8; }
    else must(ai < 24, `unsupported CBOR item ${ib}`);
    if (mt === 0) return n;
    if (mt === 1) return -1 - n;
    if (mt === 2) { const v = buf.subarray(i, i + n); i += n; return v; }
    if (mt === 3) { const v = buf.subarray(i, i + n).toString("utf8"); i += n; return v; }
    if (mt === 4) return Array.from({ length: n }, read);
    if (mt === 5) { const m = {}; for (let k = 0; k < n; k++) { const key = read(); m[key] = read(); } return m; }
    must(mt === 7 && [20, 21, 22].includes(ai), `unsupported CBOR type ${mt}`);
    return ai === 21 ? true : ai === 20 ? false : null;
  };
  const value = read();
  return { value, end: i };
}

// The contents of an X.509 extension's extnValue OCTET STRING, by OID (DER walk from the OID TLV).
function extension(der, oid) {
  const parts = oid.split(".").map(Number), body = [40 * parts[0] + parts[1]];
  for (const p of parts.slice(2)) { const b = []; let v = p; do { b.unshift(v & 127); v >>= 7; } while (v); body.push(...b.map((x, j) => (j < b.length - 1 ? x | 128 : x))); }
  const tlv = Buffer.from([6, body.length, ...body]);
  let i = der.indexOf(tlv);
  must(i >= 0 && der.indexOf(tlv, i + 1) < 0, `extension ${oid} missing or repeated`);
  i += tlv.length;
  if (der[i] === 1) i += 3; // critical BOOLEAN
  must(der[i] === 4, `extension ${oid} malformed`);
  let len = der[i + 1], off = i + 2;
  if (len & 128) { const k = len & 127; len = der.readUIntBE(off, k); off += k; }
  return der.subarray(off, off + len);
}

function authenticator(data, policy, attestation) {
  must(data.length >= 37 && data.subarray(0, 32).equals(sha(Buffer.from(policy.appId))), "wrong app id");
  const flags = data[32], counter = data.readUInt32BE(33);
  must(!(flags & 0x3e), "unsupported authenticator flags");
  let off = 37, credential = null, cose = null;
  if (attestation) {
    must(flags & 0x40 && counter === 0 && data.subarray(37, 53).equals(AAGUID) && data.readUInt16BE(53) === 32, "bad attested credential data");
    credential = data.subarray(55, 87);
    const c = cbor(data, 87); cose = c.value; off = c.end;
  }
  let ext = {};
  if (flags & 0x80) ext = cbor(data, off).value;
  else must(data.length === off, "trailing authenticator data");
  const cd = ext.apple_cd_hash_hash_01, type = ext.apple_cd_hash_type_01;
  must(Buffer.isBuffer(type) && type.equals(Buffer.from([2])) && Buffer.isBuffer(cd) && cd.length === 32, "missing CDHash");
  must(policy.cdhashes.includes(cd.toString("hex")), `CDHash ${cd.toString("hex").slice(0, 16)}… is not admitted`);
  let cat = ext.apple_validation_category_01;
  if (Buffer.isBuffer(cat)) { must(cat.length === 4, "bad category"); cat = cat.readUInt32LE(0); }
  must(cat === policy.category, `validation category ${cat} is not ${policy.category}`);
  return { counter, credential, cose, cdhash: cd.toString("hex") };
}

const appleRoot = () => {
  const root = new crypto.X509Certificate(fs.readFileSync(path.join(ROOT, "trust/apple-app-attestation-root.pem")));
  must(sha(root.raw).toString("hex") === ROOT_SHA256, "Apple root fingerprint mismatch");
  return root;
};

// A fresh enrollment over clientData. Returns the attested P-256 public key (uncompressed point) and CDHash.
export function verifyAttestation(raw, keyId, clientData, policy, now = new Date()) {
  const o = cbor(raw).value;
  must(o.fmt === "apple-appattest" && o.attStmt?.x5c?.length === 2 && Buffer.isBuffer(o.attStmt.receipt), "wrong attestation format");
  const [leaf, inter] = o.attStmt.x5c.map((d) => new crypto.X509Certificate(d)), root = appleRoot();
  must(inter.ca && !leaf.ca && inter.verify(root.publicKey) && leaf.verify(inter.publicKey), "certificate chain does not reach the pinned Apple root");
  for (const c of [leaf, inter]) must(new Date(c.validFrom) <= now && now <= new Date(c.validTo), "certificate outside its validity period");
  must(new Date(leaf.validFrom).getTime() >= now.getTime() - 24 * 3600e3 - MAX_AGE, "enrollment is older than 12 h");
  const a = authenticator(o.authData, policy, true);
  const point = leaf.publicKey.export({ format: "jwk" });
  const pt = Buffer.concat([Buffer.from([4]), Buffer.from(point.x, "base64url"), Buffer.from(point.y, "base64url")]);
  const kid = Buffer.from(keyId, "base64");
  must(point.crv === "P-256" && kid.length === 32 && a.credential.equals(kid) && sha(pt).equals(kid), "key id does not match the attested key");
  must(a.cose[1] === 2 && a.cose[3] === -7 && a.cose[-1] === 1 && Buffer.from(a.cose[-2]).equals(pt.subarray(1, 33)) && Buffer.from(a.cose[-3]).equals(pt.subarray(33)), "COSE key mismatch");
  must(extension(leaf.raw, "1.2.840.113635.100.8.2").equals(Buffer.concat([Buffer.from("3024a1220420", "hex"), sha(o.authData, sha(clientData))])), "nonce does not bind our client data");
  must(extension(leaf.raw, "1.2.840.113635.100.8.6").equals(MAC_ACL), "key ACL is not the Mac SIP + Full Security ACL");
  return { publicKey: pt.toString("base64"), cdhash: a.cdhash };
}

// An assertion by that key over clientData; the CDHash is checked again, since modified code can reuse a key.
export function verifyAssertion(raw, clientData, publicKey, policy) {
  const o = cbor(raw).value;
  must(Buffer.isBuffer(o.signature) && Buffer.isBuffer(o.authenticatorData), "malformed assertion");
  const a = authenticator(o.authenticatorData, policy, false);
  must(a.counter > 0, "assertion counter is zero");
  const key = crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: Buffer.from(publicKey, "base64").subarray(1, 33).toString("base64url"), y: Buffer.from(publicKey, "base64").subarray(33).toString("base64url") }, format: "jwk" });
  must(crypto.verify("sha256", sha(o.authenticatorData, sha(clientData)), { key, dsaEncoding: "der" }, o.signature), "assertion signature does not verify");
  return { cdhash: a.cdhash, counter: a.counter };
}
