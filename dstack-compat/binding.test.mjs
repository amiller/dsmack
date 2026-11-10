import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { reportData } from "./binding.mjs";
import { cat, hex, unhex, decodeAttestation, checkAssertion } from "./secret-release/policy.mjs";
import { peerBytes, verifyRelay, withEnrollment } from "../applications/relay-broker/attestation.mjs";
import { paidReceiptKey } from "../applications/compute-node/browser/payments.mjs";
import { Wallet } from "../applications/compute-node/browser/vendor/ethers-6.17.0.mjs";
const fixture = name => JSON.parse(readFileSync(new URL("../applications/relay-broker/fixtures/" + name + ".json", import.meta.url)));
const f = fixture("bind"), now = 1793120000;
const chain = enrollment => withEnrollment({ category: async () => 3, rpIdHash: async () => unhex(f.rp_id_hash),
  buildId: async () => new Uint8Array(32), burnedImage: async () => false, burnedBuild: async () => false }, [enrollment]);

test("recorded guest identities bind with the same bytes at the broker and browser", async () => {
  for (const r of [f.relay, f.compute]) {
    const a = await decodeAttestation(unhex(r.attestation));
    assert.equal(hex(await reportData(peerBytes(r.relay_peer), unhex(r.secret_key ?? ""), unhex(r.receipt_key))), hex(a.report_data));
    const verified = await verifyRelay(r, {workloads:[{...r, service:r.kind === "compute" ? "node" : "peer"}]}, chain(f.enrollment), now);
    assert.equal(verified.receipt_key, r.receipt_key);
  }
});

test("each key and the verifier nonce are bound; epoch is exactly the zero nonce", async () => {
  const peer = peerBytes(f.compute.relay_peer), seal = unhex(f.compute.secret_key), receipt = unhex(f.compute.receipt_key);
  const epoch = hex(await reportData(peer, seal, receipt));
  assert.equal(epoch, hex(await reportData(peer, seal, receipt, new Uint8Array(32))));
  assert.notEqual(epoch, hex(await reportData(peerBytes(f.relay.relay_peer), seal, receipt)));
  assert.notEqual(epoch, hex(await reportData(peer, new Uint8Array(64), receipt)));
  assert.notEqual(epoch, hex(await reportData(peer, seal, new Uint8Array(32))));
  assert.notEqual(epoch, hex(await reportData(peer, seal, receipt, new Uint8Array(32).fill(1))));
});

test("paid receipt public key must recover the advertised signer and joins the agent receipt key", async () => {
  const wallet = Wallet.createRandom();
  const p = {receiptPublicKey:wallet.signingKey.compressedPublicKey, receiptSigner:wallet.address};
  const paid = paidReceiptKey(p), peer = peerBytes(f.compute.relay_peer), seal = unhex(f.compute.secret_key), ed = unhex(f.compute.receipt_key);
  assert.equal(paid.length, 33);
  assert.notEqual(hex(await reportData(peer, seal, ed)), hex(await reportData(peer, seal, cat(ed, paid))));
  assert.throws(() => paidReceiptKey({...p, receiptSigner:Wallet.createRandom().address}), /key\/signer/);
  assert.throws(() => paidReceiptKey({receiptSigner:wallet.address}), /key\/signer/);
});

test("historical Apple signatures remain valid examples but old node layouts cannot be admitted", async () => {
  for (const name of ["relay", "compute"]) {
    const old = fixture(name), r = old.registration ?? old;
    const enrolled = chain(fixture("relay").enrollment);
    await checkAssertion(await decodeAttestation(unhex(r.attestation)), enrolled, now * 1000);
    await assert.rejects(verifyRelay(r, {workloads:[{...r, service:name === "compute" ? "node" : "peer"}]}, enrolled, now), /binding/);
  }
});

const evidence = process.env.PAYMENTS_EVIDENCE;
if (evidence) test("Go paid report matches the JavaScript verifier byte for byte", async () => {
 const g = JSON.parse(readFileSync(evidence + "/binding-interop.json"));
 assert.equal(hex(await reportData(peerBytes(g.peer), unhex(g.seal), cat(unhex(g.receipt), paidReceiptKey(g.payments)), unhex(g.challenge))), g.report_data);
});
