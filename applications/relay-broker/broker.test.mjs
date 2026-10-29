import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPublicKey, verify, generateKeyPairSync, sign, randomBytes } from "node:crypto";
import { test } from "node:test";
import { Broker, limits } from "./broker.mjs";
import { canonical, grantBytes, signingKey, signGrant } from "./grants.mjs";
import { withEnrollment } from "./attestation.mjs";
import { unhex } from "../../dstack-compat/secret-release/policy.mjs";

// Recorded public proof from the grant-aware relay; no private keys or guest secrets.
const f = JSON.parse(readFileSync(new URL("fixtures/relay.json", import.meta.url)));
const r = f.registration;
const cfg = { workloads: [{ ...r, service: "peer" }] };
const NOW = 1793120000;
const baseChain = () => ({ category: async () => 3, rpIdHash: async () => unhex(f.rp_id_hash),
  burnedImage: async () => false, burnedBuild: async () => false, buildId: async () => new Uint8Array(32) });
const chain = () => withEnrollment(baseChain(), [f.enrollment]);
const key = await signingKey("42".repeat(32));
function broker(options = {}) {
  return new Broker({ cfg, chain: chain(), key, now: () => NOW, saveCredits: async () => {}, ...options });
}
const client = generateKeyPairSync("ed25519");
const pub = client.publicKey.export({format:"der",type:"spki"}).subarray(-32);
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
let n = BigInt("0x002408011220" + pub.toString("hex")), encoded = "";
while (n) { encoded = alphabet[Number(n % 58n)] + encoded; n /= 58n; }
const clientPeer = "1" + encoded;
const request = { relay_peer: r.relay_peer, client_peer: clientPeer, bytes: 1024 };
function signed(r) {
  const fields = {amount:r.amount ?? r.bytes,client_peer:r.client_peer,nonce:randomBytes(16).toString("hex"),relay_peer:r.relay_peer,unit:r.unit ?? "bytes"};
  return {...fields,sig:sign(null,grantBytes(fields),client.privateKey).toString("hex")};
}

test("canonical grant bytes have sorted keys, UTF-8 and no spaces", () => {
  assert.equal(canonical({ v: 1, relay_peer: "peer", grant_id: "a", expires_at: 10, client_peer: "é", bytes: 4 }),
    '{"bytes":4,"client_peer":"é","expires_at":10,"grant_id":"a","relay_peer":"peer","v":1}');
});

test("GetKey seed survives reload and grants verify with independent Node Ed25519", async () => {
  assert.equal((await signingKey("42".repeat(32))).public_key, key.public_key);
  const g = await signGrant(key, { ...request, expires_at: NOW + 60 });
  assert.match(g.grant_id, /^[0-9a-f]{32}$/);
  assert.match(g.sig, /^[0-9a-f]{128}$/);
  const { sig, ...unsigned } = g;
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(key.public_key, "hex")]), format: "der", type: "spki" });
  assert(verify(null, grantBytes(unsigned), pub, Buffer.from(sig, "hex")));
  assert(!verify(null, grantBytes({ ...unsigned, bytes: unsigned.bytes + 1 }), pub, Buffer.from(sig, "hex")));
});

test("unregistered peers cannot get grants; the real signed relay proof admits them", async () => {
  const b = broker();
  await assert.rejects(b.grant(signed(request)), /not live/);
  const registered = await b.register(r);
  assert.equal(registered.attestation.status, "verified");
  assert.equal(registered.attestation.receipt_key, r.receipt_key);
  assert.equal(b.live().length, 1);
  const grant = await b.grant(signed(request));
  assert.equal(grant.expires_at, registered.expires_at);
});

test("a proof for another PeerId cannot enter discovery", async () => {
  const b = broker();
  const other = "12D3KooWPdcePFHp8pmoxdwpNC2ADNivvsCFYH8KPSfqutt7GWzA";
  await assert.rejects(b.register({ ...r, relay_peer: other, relay_maddr: r.relay_maddr.replace(r.relay_peer, other) }), /PeerId binding/);
  assert.equal(b.live().length, 0);
});

test("a substituted or missing receipt key cannot enter discovery", async () => {
  const b = broker();
  await assert.rejects(b.register({ ...r, receipt_key: "42".repeat(32) }), /receipt key binding/);
  await assert.rejects(b.register({ ...r, receipt_key: undefined }), /receipt key must/);
  assert.equal(b.live().length, 0);
});

test("unapproved measurements and wrong caller are rejected before listing", async () => {
  const b = broker({ cfg: { workloads: [] } });
  await assert.rejects(b.register(r), /not admitted/);
  const wrongService = broker({ cfg: { workloads: [{ ...r, service: "other-service" }] } });
  await assert.rejects(wrongService.register(r), /caller/);
  assert.equal(wrongService.live().length, 0);
});

test("untrusted or expired enrollment, invalid signature, wrong build and burns block registration", async () => {
  const unknown = broker({ chain: withEnrollment(baseChain(), []) });
  await assert.rejects(unknown.register(r), /unknown Apple enrollment/);
  const expired = broker({ now: () => f.enrollment.expires + 1 });
  await assert.rejects(expired.register(r), /expired/);
  const wrongKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", wrongKey.publicKey));
  const badSigner = broker({ chain: { ...chain(), key: async () => ({ x: raw.slice(1, 33), y: raw.slice(33), expires: NOW + 1000, counter: 0, enrolled: true }) } });
  await assert.rejects(badSigner.register(r), /assertion signature/);
  const wrongBuild = broker({ chain: { ...chain(), rpIdHash: async () => new Uint8Array(32) } });
  await assert.rejects(wrongBuild.register(r), /approved CDRegistry build/);
  const burned = broker({ chain: { ...chain(), burnedImage: async () => true } });
  await assert.rejects(burned.register(r), /canary burned/);
  assert.equal(badSigner.live().length, 0);
});

test("expired operator lease disappears and cannot authorize grants", async () => {
  let now = NOW;
  const b = broker({ now: () => now });
  await b.register(r);
  now += limits.relay_lease_seconds;
  assert.deepEqual(b.live(), []);
  await assert.rejects(b.grant(signed(request)), /not live/);
});

test("concurrent grants share one quota, quota persists and the window renews", async () => {
  let saved, now = NOW;
  const b = broker({ saveCredits: async (c) => { saved = c; } });
  await b.register(r);
  const results = await Promise.allSettled(Array.from({ length: 6 }, () => b.grant(signed(request))));
  assert.equal(results.filter((r) => r.status === "fulfilled").length, limits.grants_per_hour);
  assert(results.filter((r) => r.status === "rejected").every((r) => r.reason.status === 429));
  const restarted = broker({ credits: saved, now: () => now });
  await restarted.register(r);
  await assert.rejects(restarted.grant(signed(request)), /credit exhausted/);
  now += 3600;
  await restarted.register(r);
  await restarted.grant(signed(request));
});

test("byte quota and network byte-budget validation prevent oversize grants", async () => {
  const b = broker();
  await b.register(r);
  for (const bytes of [0, -1, 0.5, "1024", limits.max_bytes + 1]) await assert.rejects(b.grant(signed({ ...request, bytes })), /bytes must/);
  await b.grant(signed({ ...request, bytes: limits.max_bytes }));
  await assert.rejects(b.grant(signed(request)), /credit exhausted/);
});

test("a quota persistence failure returns no grant and later requests still run", async () => {
  const b = broker({ saveCredits: async () => { throw new Error("disk full"); } });
  await b.register(r);
  await assert.rejects(b.grant(signed(request)), /disk full/);
  b.saveCredits = async () => {};
  await b.grant(signed(request));
});

test("signed client cannot be impersonated and captured nonce cannot spend twice", async () => {
  const b = broker(); await b.register(r);
  await assert.rejects(b.grant(request), /signed nonce/);
  const req = signed(request);
  await assert.rejects(b.grant({...req, amount:2048}), /client signature/);
  await b.grant(req);
  await assert.rejects(b.grant(req), /nonce replay/);
});
test("seconds grants use independent compute quota and reject relay units", async () => {
  const b = broker(); await b.register(r);
  await assert.rejects(b.grant(signed({...request,unit:"seconds",amount:20})), /node kind/);
  b.relays.get(r.relay_peer).kind = "compute";
  const g = await b.grant(signed({...request,unit:"seconds",amount:20}));
  assert.equal(g.unit,"seconds"); assert.equal(g.seconds,20); assert.equal(g.bytes,undefined);
  await assert.rejects(b.grant(signed(request)), /node kind/);
});

test("signed nonce stays spent after quota window rollover and restart", async () => {
  let saved,now=NOW;const req=signed(request);
  const b=broker({now:()=>now,saveCredits:async v=>{saved=v;}});await b.register(r);await b.grant(req);
  now+=3600;const restarted=broker({now:()=>now,credits:saved});await restarted.register(r);
  await assert.rejects(restarted.grant(req),/nonce replay/);
  await restarted.grant(signed(request));
});

test("real compute assertion binds node identity, bundle key and receipt key", async () => {
  const compute=JSON.parse(readFileSync(new URL("fixtures/compute.json",import.meta.url)));
  const b=broker({cfg:{workloads:[{...compute,service:"node"}]}});
  const registered=await b.register(compute);
  assert.equal(registered.kind,"compute");assert.equal(registered.secret_key,compute.secret_key);
  await assert.rejects(b.register({...compute,secret_key:"42".repeat(64)}),/compute key binding/);
  await assert.rejects(b.register({...compute,receipt_key:"42".repeat(32)}),/compute key binding/);
  const g=await b.grant(signed({...request,relay_peer:compute.relay_peer,unit:"seconds",amount:30}));
  assert.equal(g.seconds,30);
});

test("draining compute nodes renew but are excluded from new job routing", async () => {
  const c = JSON.parse(readFileSync(new URL("fixtures/compute.json", import.meta.url)));
  let now = NOW;
  const b = broker({cfg:{workloads:[{...c,service:"node"}]},now:()=>now});
  await b.register({...c,admit_until:NOW+1});
  assert.equal(b.live().length,1);
  now+=2;
  assert.equal(b.live().length,0);
  await b.register({...c,admit_until:NOW+1});
  assert.equal(b.live().length,0);
  assert.equal(b.relays.size,1);
});
