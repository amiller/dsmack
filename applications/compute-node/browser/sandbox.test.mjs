// verifyNode in on-chain mode against a key-free manifest: a guest is accepted under whichever App Attest key signs
// it, provided AppleAttestRegistry holds the key and a MacLink ties it to the payee, and under whichever registered
// copy of the approved runner the host signed with its own Apple team. Run with deno test -A.
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
import { heliosChain } from "./helios-chain.mjs";

const f = JSON.parse(readFileSync(new URL("../../relay-broker/fixtures/bind.json", import.meta.url)));
const manifest = readFileSync(new URL("../testdata/key-free-manifest.json", import.meta.url));
const m = JSON.parse(manifest), node = JSON.parse(m.docker_compose_file).services.node;
const pay = JSON.parse(node.environment.PAYMENTS_CONFIG), operator = pay.operator.toLowerCase();
const build = new Uint8Array(32).fill(0xdf), image = unhex(m.base_vm.os_image_hash), cdhash = unhex(node.command[5]);

async function setup() {
  const rp = await sha256(new TextEncoder().encode(APP_ID)), keys = new Map(), links = new Map();
  // CDRegistry.rpIdHash: the copies registered under the current build, each with its own application identifier.
  const copies = new Map([[hex(cdhash), rp]]);
  const chain = {
    key: async (kid) => keys.get(hex(kid)) ?? { x: new Uint8Array(32), y: new Uint8Array(32), expires: 0, counter: 0, enrolled: false },
    category: async () => 3, rpIdHash: async (cd) => copies.get(hex(cd)) ?? new Uint8Array(32),
    buildId: async () => build, burnedImage: async () => false, burnedBuild: async () => false,
  };
  const enroll = (k) => keys.set(hex(k.kid), { x: k.x, y: k.y, expires: 1899590400, counter: 0, enrolled: true });
  const policy = { manifest, cdhash: node.command[5], brokerKey: node.command[4], grantSigner: pay.grantSigner, chain,
    operatorsOf: async (kid) => links.get(kid) ?? [] };
  const guest = async (key, signed = { rp, cdhash }) => {
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
      caller: await sha256(new TextEncoder().encode("node")), report_data, ...signed, category: 3 });
    return { r, policy: { ...policy, challenge } };
  };
  return { enroll, link: (k, op) => links.set("0x" + hex(k.kid), [...(links.get("0x" + hex(k.kid)) ?? []), op]), guest, copies, chain };
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

test("a runner re-signed under the host's own Apple team verifies once CDRegistry resolves its copy", async () => {
  const { enroll, link, guest, copies } = await setup(), key = await deviceKey();
  enroll(key); link(key, operator);
  const own = { rp: await sha256(new TextEncoder().encode("TEAM123456.com.example.dsmack")), cdhash: new Uint8Array(32).fill(0xc0) };
  const approved = copies.get(node.command[5]);

  let g = await guest(key, own);
  await assert.rejects(verifyNode(g.r, g.policy), /assertion build c0c0.* is not a registered copy of CDRegistry's current build/);

  copies.set(hex(own.cdhash), own.rp);
  g = await guest(key, own);
  const v = await verifyNode(g.r, g.policy);
  assert.equal(v.cdhash, hex(own.cdhash), "the result names the copy that signed");
  assert.equal(v.registration.cdhash, node.command[5], "the guest still reports the CDHash its manifest names");


  // The RP ID must be the one this copy was registered with, not another registered copy's.
  g = await guest(key, { rp: approved, cdhash: own.cdhash });
  await assert.rejects(verifyNode(g.r, g.policy), /assertion app ID/);
  g = await guest(key, { rp: own.rp, cdhash });
  await assert.rejects(verifyNode(g.r, g.policy), /assertion app ID/);

  // The registry moved to another build: the host's copy resolves under it, the policy's CDHash no longer does.
  copies.delete(node.command[5]);
  g = await guest(key, own);
  await assert.rejects(verifyNode(g.r, g.policy), /policy build .* is not CDRegistry's current build/);
  copies.set(node.command[5], approved);
  g = await guest(key);
  assert.equal((await verifyNode(g.r, g.policy)).cdhash, node.command[5], "the approved team's own copy still verifies");
});

// 2026-11-10: verifyNode made ~13 serial unpinned chain-read calls, repeating key, category and rpIdHash. Helios took
// 5-25 s per cold read, so a stay opened before verification passed the broker's 90 s unused-stay window and was freed.
test("a Helios snapshot pins every read to one block, reads each once, and leaves only the guest's key for after the claim", async () => {
  const { enroll, link, guest, chain } = await setup(), key = await deviceKey();
  enroll(key); link(key, operator);
  const attestAddr = "0x" + "a1".repeat(20), canary = "0x" + "ca".repeat(20), registry = "0x" + "4e".repeat(20);
  const blocks = ["0x" + "b1".repeat(32), "0x" + "b2".repeat(32)], calls = [];
  let heads = 0, fail = "0xe62b7cbd";
  const word = (n) => BigInt(n).toString(16).padStart(64, "0");
  const answer = async (to, data) => {
    const sel = data.slice(0, 10), arg = unhex(data.slice(10));
    if (to === attestAddr && sel === "0xb4eb10ce") return word(registry);
    if (to === attestAddr && sel === "0xdde5b7a1") { const k = await chain.key(arg); return hex(k.x) + hex(k.y) + word(k.expires) + word(k.counter) + word(k.enrolled ? 1 : 0); }
    if (to === attestAddr && sel === "0x5523509a") return word(await chain.category());
    if (to === registry && sel === "0x65f4df9c") return hex(await chain.rpIdHash(arg));
    if (to === registry && sel === "0xb7b014b6") return hex(await chain.buildId());
    if (to === canary) return word(0);
    throw new Error("unexpected read " + to + data);
  };
  // A stand-in for chain-read: each snapshot is one block with chain-read's per-block cache of successful reads.
  const read = async (block, to, data) => {
    calls.push({ to, data, block, failed: data.startsWith(fail) });
    if (data.startsWith(fail)) { fail = undefined; throw new Error("eth_call failed on every source"); }
    return unhex(await answer(to, data));
  };
  const open = async () => ({ snapshot: async () => {
    const block = blocks[heads++], reads = new Map(), k = (to, data) => (to + data).toLowerCase();
    const call = (to, data) => {
      if (!reads.has(k(to, data))) { const p = read(block, to, data); reads.set(k(to, data), p); p.catch(() => reads.delete(k(to, data))); }
      return reads.get(k(to, data));
    };
    return { block, call, multicall: (cs) => Promise.all(cs.map(([to, data]) => call(to, data))) };
  } });
  const helios = heliosChain({ attest: attestAddr, canary, registry, cdhash: node.command[5], image: m.base_vm.os_image_hash }, { open });
  await assert.rejects(helios.snapshot(), /eth_call failed on every source/);
  const pinned = await helios.snapshot();
  assert.equal(heads, 2, "a failed read discards the snapshot; the next one pins a new block");
  const before = calls.length, g = await guest(key);
  await verifyNode(g.r, { ...g.policy, chain: pinned });
  await verifyNode(g.r, { ...g.policy, chain: await helios.snapshot() });
  assert.deepEqual(calls.slice(before).map((c) => c.data.slice(0, 10)), ["0xdde5b7a1"], "after the claim only the guest's key is read");
  assert.ok(calls.slice(before).every((c) => c.block === blocks[1]), "every read names the snapshot's block");
  const ok = calls.filter((c) => c.block === blocks[1]).map((c) => c.to + c.data);
  assert.equal(new Set(ok).size, ok.length, "no read is fetched twice within a snapshot");
});
