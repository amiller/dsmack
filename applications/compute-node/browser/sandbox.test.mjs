// verifyNode in on-chain mode against a key-free manifest: a guest is accepted under whichever App Attest key signs
// it, provided AppleAttestRegistry holds the key and a MacLink ties it to the payee. Run with deno test -A.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Wallet } from "../../payments/schema.mjs";
import { hex, sha256, unhex } from "../../../dstack-compat/secret-release/policy.mjs";
import { reportData } from "../../../dstack-compat/binding.mjs";
import { attest, deviceKey } from "../../relay-broker/fixtures/synthetic-guest.mjs";
import { APP_ID } from "./enrollment.mjs";
import { paymentRunId } from "./payments.mjs";
import { peerBytes, verifyNode } from "./sandbox.mjs";

const f = JSON.parse(readFileSync(new URL("../../relay-broker/fixtures/bind.json", import.meta.url)));
const manifest = readFileSync(new URL("../testdata/key-free-manifest.json", import.meta.url));
const m = JSON.parse(manifest), node = JSON.parse(m.docker_compose_file).services.node;
const pay = JSON.parse(node.environment.PAYMENTS_CONFIG), operator = pay.operator.toLowerCase();
const build = new Uint8Array(32).fill(0xdf), image = unhex(m.base_vm.os_image_hash), cdhash = unhex(node.command[5]);

async function setup() {
  const rp = await sha256(new TextEncoder().encode(APP_ID)), keys = new Map(), links = new Map();
  const chain = {
    key: async (kid) => keys.get(hex(kid)) ?? { x: new Uint8Array(32), y: new Uint8Array(32), expires: 0, counter: 0, enrolled: false },
    category: async () => 3, rpIdHash: async (cd) => hex(cd) === hex(cdhash) ? rp : new Uint8Array(32),
    buildId: async () => build, burnedImage: async () => false, burnedBuild: async () => false,
  };
  const enroll = (k) => keys.set(hex(k.kid), { x: k.x, y: k.y, expires: 1899590400, counter: 0, enrolled: true });
  const policy = { manifest, cdhash: node.command[5], brokerKey: node.command[4], grantSigner: pay.grantSigner, chain,
    operatorsOf: async (kid) => links.get(kid) ?? [] };
  const guest = async (key) => {
    const receipt = Wallet.createRandom(), runNonce = "0x" + hex(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = hex(crypto.getRandomValues(new Uint8Array(32)));
    const payments = { ...pay, buildId: "0x" + hex(build), runExpires: Math.floor(Date.now() / 1000) + 3600, runNonce,
      runId: paymentRunId("0x" + hex(key.kid), runNonce), receiptSigner: receipt.address,
      receiptPublicKey: receipt.signingKey.compressedPublicKey, challenge };
    const r = { kind: "compute", relay_peer: f.compute.relay_peer, relay_maddr: f.compute.relay_maddr, secret_key: f.compute.secret_key,
      receipt_key: f.compute.receipt_key, manifest_sha256: hex(await sha256(manifest)), os_image_hash: m.base_vm.os_image_hash,
      cdhash: node.command[5], payments };
    const report_data = await reportData(peerBytes(r.relay_peer), unhex(r.secret_key),
      unhex(r.receipt_key + payments.receiptPublicKey.slice(2)), unhex(challenge));
    r.attestation = await attest(key, { os_image_hash: image, manifest_sha256: await sha256(manifest), run: crypto.getRandomValues(new Uint8Array(32)),
      caller: await sha256(new TextEncoder().encode("node")), report_data, rp, cdhash, category: 3 });
    return { r, policy: { ...policy, challenge } };
  };
  return { enroll, link: (k, op) => links.set("0x" + hex(k.kid), [...(links.get("0x" + hex(k.kid)) ?? []), op]), guest };
}

test("the key-free manifest names no App Attest key", () => {
  assert.equal("enrollmentKeyId" in pay, false);
});

test("after a rotation the same manifest verifies under the new key once it is enrolled and linked", async () => {
  const { enroll, link, guest } = await setup();
  const old = await deviceKey(), fresh = await deviceKey();
  enroll(old); link(old, operator);
  let g = await guest(old);
  assert.equal(hex((await verifyNode(g.r, g.policy)).enrollment.kid), hex(old.kid));

  g = await guest(fresh);
  await assert.rejects(verifyNode(g.r, g.policy), /is not enrolled on chain/);
  enroll(fresh);
  g = await guest(fresh);
  await assert.rejects(verifyNode(g.r, g.policy), /has no MacLink to payment operator/);
  link(fresh, "0x" + "77".repeat(20));
  g = await guest(fresh);
  await assert.rejects(verifyNode(g.r, g.policy), /has no MacLink to payment operator/);
  link(fresh, operator);
  g = await guest(fresh);
  const v = await verifyNode(g.r, g.policy);
  assert.equal(hex(v.enrollment.kid), hex(fresh.kid));
  assert.equal(v.policy.manifestHash, hex(await sha256(manifest)));

  // A run bound to a key other than the attesting one.
  g = await guest(fresh);
  g.r.payments.runId = paymentRunId("0x" + hex(old.kid), g.r.payments.runNonce);
  await assert.rejects(verifyNode(g.r, g.policy), /not bound to the attesting key/);
});
