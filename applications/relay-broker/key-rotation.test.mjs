// A Mac's App Attest key rotates under one key-free guest manifest and one UsageEscrow class: the broker admits the
// new key's guests once the key is enrolled on AppleAttestRegistry and MacLinked to the class operator, with no
// change to the manifest, the class or the broker config.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { abi, keccak256, runNode, Wallet } from "../payments/schema.mjs";
import { HeliosReader } from "../payments/helios-reader.mjs";
import { hex, sha256, unhex } from "../../dstack-compat/secret-release/policy.mjs";
import { reportData } from "../../dstack-compat/binding.mjs";
import { Payments } from "./payments.mjs";
import { peerBytes } from "./attestation.mjs";
import { applyOwnership, ownershipDomain, ownershipState, ownershipTypes } from "./ownership.mjs";
import { attest, deviceKey } from "./fixtures/synthetic-guest.mjs";

const f = JSON.parse(readFileSync(new URL("fixtures/bind.json", import.meta.url)));
const NOW = 1793120000, escrow = "0x835a61a88cc8d750b5a971219aa8f9813b2067e6";
const word = (b) => hex(b).padStart(64, "0"), bytes32 = (n) => new Uint8Array(32).fill(n);
const ATTEST = "0x" + "a1".repeat(20), REGISTRY = "0x" + "a2".repeat(20), CANARY = "0x" + "a3".repeat(20);
const manifest = bytes32(0x99), image = bytes32(0x7c), cdhash = bytes32(0x0c), rp = bytes32(0x5e), build = bytes32(0xdf);
const node = "0x" + "3a".repeat(32), code = "0x6000";

// layover-chain over AppleAttestRegistry, CDRegistry, Canary and UsageEscrow; registry.keys is what enroll() would have
// stored. tamper(reply) lets a test corrupt what the service answers.
const CHAIN_READ = "https://chain.invalid/layover-chain", BLOCK = "0x" + "b1".repeat(32);
function layoverChain(registry, broker, operator, tamper = (j) => j) {
  const keys = (kid) => registry.get(kid) ?? { x: new Uint8Array(32), y: new Uint8Array(32), expires: 0, enrolled: false };
  const call = (to, data) => {
    const sel = data.slice(0, 10), arg = data.slice(10);
    if (to === ATTEST && sel === "0xdde5b7a1") { const k = keys(arg); return word(k.x) + word(k.y) + k.expires.toString(16).padStart(64, "0") + "0".repeat(64) + (k.enrolled ? "1" : "0").padStart(64, "0"); }
    if (to === ATTEST && sel === "0xb4eb10ce") return REGISTRY.slice(2).padStart(64, "0");
    if (to === ATTEST && sel === "0x5523509a") return "3".padStart(64, "0");
    if (to === REGISTRY && sel === "0x65f4df9c") return arg === hex(cdhash) ? hex(rp) : "0".repeat(64);
    if (to === REGISTRY && sel === "0xb7b014b6") return hex(build);
    if (to === CANARY) return "0".repeat(64);
    if (to === escrow && sel === abi.getFunction("brokerSigner").selector) return abi.encodeFunctionResult("brokerSigner", [broker.address]).slice(2);
    if (to === escrow && sel === abi.getFunction("getNode").selector) return abi.encodeFunctionResult("getNode", [arg === node.slice(2)
      ? [operator, 1, "0x" + hex(manifest), "0x" + hex(image)] : ["0x" + "00".repeat(20), 0, "0x" + "00".repeat(32), "0x" + "00".repeat(32)]]).slice(2);
    if (to === escrow && sel === abi.getFunction("deposits").selector) return abi.encodeFunctionResult("deposits", [5000000n]).slice(2);
    if (to === escrow && sel === abi.getFunction("exitRequestedAt").selector) return abi.encodeFunctionResult("exitRequestedAt", [0n]).slice(2);
    throw Error("unexpected eth_call " + to + " " + sel);
  };
  return async (url) => {
    const u = new URL(url), q = (k) => u.searchParams.get(k), pin = { block: 970, block_hash: BLOCK, head: 1000, head_age_s: 2, verified_by: "helios-opstack" };
    assert.ok(u.href.startsWith(CHAIN_READ));
    if (u.pathname.endsWith("/head")) return Response.json(tamper({ ...pin, depth: Number(q("depth")) }));
    assert.equal(q("block"), BLOCK);
    if (u.pathname.endsWith("/code")) return Response.json(tamper({ ...pin, code }));
    return Response.json(tamper({ ...pin, result: "0x" + call(q("to"), q("data")) }));
  };
}

// One registration from a fresh guest run whose attestation is signed by `key`. runKid is the key the guest bound its
// run to; a key-free guest always uses the attesting key.
async function guest(broker, key, operator, runKid = key.kid, extra = {}) {
  const receipt = Wallet.createRandom(), runNonce = "0x" + hex(crypto.getRandomValues(new Uint8Array(32)));
  const { challenge } = broker.challenge();
  const payments = { node, escrow, operator, grantSigner: broker.key.address, buildId: "0x" + hex(build),
    destinationPolicyHash: "0x" + "24".repeat(32), runSeconds: 3600, runExpires: NOW + 3600,
    runId: runNode("0x" + hex(runKid), runNonce), runNonce, receiptSigner: receipt.address,
    receiptPublicKey: receipt.signingKey.compressedPublicKey, challenge, ...extra };
  const r = { kind: "compute", relay_peer: f.compute.relay_peer, relay_maddr: f.compute.relay_maddr,
    secret_key: f.compute.secret_key, receipt_key: f.compute.receipt_key, manifest_sha256: hex(manifest),
    os_image_hash: hex(image), cdhash: hex(cdhash), payments };
  const report_data = await reportData(peerBytes(r.relay_peer), unhex(r.secret_key),
    unhex(r.receipt_key + payments.receiptPublicKey.slice(2)), unhex(challenge));
  r.attestation = await attest(key, { os_image_hash: image, manifest_sha256: manifest, run: crypto.getRandomValues(new Uint8Array(32)),
    caller: await sha256(new TextEncoder().encode("node")), report_data, rp, cdhash, category: 3 });
  return r;
}

async function setup() {
  const brokerKey = Wallet.createRandom(), operator = Wallet.createRandom(), publisher = Wallet.createRandom();
  const provisioner = Wallet.createRandom(), domain = ownershipDomain(escrow), registry = new Map();
  const state = ownershipState();
  const authorization = { operator: operator.address, provisioner: provisioner.address, nonce: "1" };
  const signedAuthorization = { authorization,
    signature: await operator.signTypedData(domain, { ProvisioningAuthorization: ownershipTypes.ProvisioningAuthorization }, authorization) };
  const link = async (key, nonce, who = publisher, op = operator.address, auth = signedAuthorization, by = provisioner) => {
    const value = { kid: "0x" + hex(key.kid), publisher: who.address, operator: op, nonce: String(nonce) };
    applyOwnership(state, domain, "link", { link: value, authorization: auth,
      publisherSignature: await who.signTypedData(domain, { MacLink: ownershipTypes.MacLink }, value),
      provisionerSignature: await by.signTypedData(domain, { MacLink: ownershipTypes.MacLink }, value) });
  };
  const enroll = (key) => registry.set(hex(key.kid), { x: key.x, y: key.y, expires: 1899590400, enrolled: true });
  const cfg = { escrow, destinationPolicyHash: "0x" + "24".repeat(32), attest: ATTEST, canary: CANARY,
    admissionCode: [ATTEST, REGISTRY, CANARY].map((address) => ({ address, codeHash: keccak256(code) })) };
  const brokerCfg = { workloads: [{ manifest_sha256: hex(manifest), os_image_hash: hex(image), cdhash: hex(cdhash), service: "node" }] };
  const broker = new Payments({ cfg, key: brokerKey, now: () => NOW, save: async () => {},
    chain: new HeliosReader({ escrow, codeHash: keccak256(code), chainRead: CHAIN_READ }), ownership: async () => state });
  globalThis.fetch = layoverChain(registry, brokerKey, operator.address);
  const tamper = (f) => { globalThis.fetch = layoverChain(registry, brokerKey, operator.address, f); };
  const admit = (r) => broker.register(r, brokerCfg);
  return { broker, operator, domain, state, link, enroll, admit, tamper };
}

test("a key rotation keeps the class: the new key is admitted once enrolled and linked, the old key no longer", async () => {
  const { broker, operator, link, enroll, admit } = await setup();
  const keyA = await deviceKey(), keyB = await deviceKey();
  enroll(keyA); await link(keyA, 1);
  const a = await admit(await guest(broker, keyA, operator.address));
  assert.equal(a.key_id, hex(keyA.kid));
  assert.equal(a.nodeBinding.binding.node, node);

  // keyA dies; the pool enrolls keyB and the provisioner links it. Same manifest, same class, same broker config.
  await assert.rejects(admit(await guest(broker, keyB, operator.address)), /not enrolled/);
  enroll(keyB);
  await assert.rejects(admit(await guest(broker, keyB, operator.address)), /has no MacLink to the class operator/);
  await link(keyB, 2);
  const b = await admit(await guest(broker, keyB, operator.address));
  assert.equal(b.key_id, hex(keyB.kid));
  assert.equal(b.nodeBinding.binding.node, a.nodeBinding.binding.node);
  assert.equal(b.nodeBinding.binding.composeHash, a.nodeBinding.binding.composeHash);
  // The publisher's link moved to keyB, so the old key (still enrolled on chain) no longer serves this operator.
  await assert.rejects(admit(await guest(broker, keyA, operator.address)), /has no MacLink to the class operator/);
});

test("the run binds to the attesting key, and a link to another operator or by a revoked provisioner does not count", async () => {
  const { broker, operator, link, enroll, admit, state, domain } = await setup();
  const key = await deviceKey(), other = await deviceKey();
  enroll(key); enroll(other); await link(key, 1);
  // A guest whose run names a different key than the one that signed its attestation.
  await assert.rejects(admit(await guest(broker, key, operator.address, other.kid)), /not bound to the attesting key/);
  // A pre-change guest still carrying enrollmentKeyId: admitted when its baked key is the attesting key.
  await admit(await guest(broker, key, operator.address, key.kid, { enrollmentKeyId: "0x" + hex(key.kid) }));

  // `other` is genuine and enrolled, but its Mac links it to someone else.
  const elsewhere = Wallet.createRandom(), mac2 = Wallet.createRandom(), prov2 = Wallet.createRandom();
  const auth2 = { operator: elsewhere.address, provisioner: prov2.address, nonce: "1" };
  await link(other, 1, mac2, elsewhere.address,
    { authorization: auth2, signature: await elsewhere.signTypedData(domain, { ProvisioningAuthorization: ownershipTypes.ProvisioningAuthorization }, auth2) }, prov2);
  await assert.rejects(admit(await guest(broker, other, operator.address)), /has no MacLink to the class operator/);

  // The operator revokes the provisioner that signed `key`'s link: the stored link stays, but no longer counts.
  const { authorization } = Object.values(state.links).find((r) => r.link.kid === "0x" + hex(key.kid)).authorization;
  const revocation = { operator: authorization.operator, provisioner: authorization.provisioner, nonce: "1" };
  applyOwnership(state, domain, "revoke-provisioner", { revocation,
    signature: await operator.signTypedData(domain, { ProvisionerRevocation: ownershipTypes.ProvisionerRevocation }, revocation) });
  await assert.rejects(admit(await guest(broker, key, operator.address)), /has no MacLink to the class operator/);

  // A forged stored record (operator swapped after signing) is an error, not a silent skip.
  const record = Object.values(state.links).find((r) => r.link.kid === "0x" + hex(other.kid));
  record.link = { ...record.link, operator: operator.address.toLowerCase() };
  await assert.rejects(admit(await guest(broker, other, operator.address)), /signature/);
});

test("admission reads only Helios-verified layover-chain answers for one pinned block, and fails closed", async () => {
  const { broker, operator, link, enroll, admit, tamper } = await setup();
  const key = await deviceKey();
  enroll(key); await link(key, 1);
  await admit(await guest(broker, key, operator.address));
  tamper((j) => j.result ? { ...j, verified_by: undefined } : j);
  await assert.rejects(admit(await guest(broker, key, operator.address)), /layover-chain \/call: HTTP 200/);
  tamper((j) => j.result ? { ...j, block_hash: "0x" + "b2".repeat(32) } : j);
  await assert.rejects(admit(await guest(broker, key, operator.address)), /answered for another block/);
  tamper((j) => j.depth === undefined ? j : { ...j, depth: 0, block: 1000 });
  await assert.rejects(admit(await guest(broker, key, operator.address)), /ignored depth 30/);
  tamper((j) => j.depth === undefined ? j : { ...j, block: 990 });
  await assert.rejects(admit(await guest(broker, key, operator.address)), /ignored depth 30/);
  tamper((j) => ({ ...j, head_age_s: 600 }));
  await assert.rejects(admit(await guest(broker, key, operator.address)), /Helios head is 600 s old/);
  tamper((j) => j.code ? { ...j, code: "0x6001" } : j);
  await assert.rejects(admit(await guest(broker, key, operator.address)), /code mismatch/);
});

test("deposit credit is minted only from a Helios-verified deposits() read", async () => {
  const { broker, tamper } = await setup();
  const wallet = Wallet.createRandom().address.toLowerCase();
  tamper((j) => j.result ? { ...j, verified_by: undefined } : j);
  await assert.rejects(broker.syncBalance(wallet), /layover-chain \/call: HTTP 200/);
  assert.equal(broker.state.inferenceCredit?.[wallet], undefined);
  tamper((j) => j);
  await broker.syncBalance(wallet);
  assert.equal(broker.state.inferenceCredit[wallet].grantedNanoUsd, "5000000000");
});
