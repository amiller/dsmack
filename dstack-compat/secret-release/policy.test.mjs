import assert from "node:assert/strict";
import fs from "node:fs";
import { test } from "node:test";
import * as p from "./policy.mjs";

const fx = (n) => JSON.parse(fs.readFileSync(new URL("fixtures/" + n, import.meta.url)));
const canary = fx("canary-run-2.json");
const NOW = Date.parse("2026-10-25T23:30:00Z");
const ATTEST = "0x00000000000000000000000000000000000a7e57", CDS = "0x0000000000000000000000000000000000000cd5";
const CANARY = "0x00000000000000000000000000000000000ca4a7";

// A JSON-RPC endpoint answering the policy's eth_calls from a fixture, so rpcChain's ABI decoding is exercised.
function fakeRpc(f, { rp = f.rp_id_hash, burned = false } = {}) {
  const w = (h) => h.padStart(64, "0"), kid = f.key_id, cdhash = f.cdhash;
  const answers = {
    [ATTEST + "0xdde5b7a1" + kid]: w(f.key.x) + w(f.key.y) + w(f.key.expires.toString(16)) + w("0") + w("1"),
    [ATTEST + "0xb4eb10ce"]: w(CDS.slice(2)),
    [ATTEST + "0x5523509a"]: w("3"),
    [CDS + "0x65f4df9c" + cdhash]: w(rp),
    [CDS + "0xb7b014b6"]: w("c930"),
  };
  return async (_, init) => {
    const { params: [{ to, data }] } = JSON.parse(init.body);
    const r = answers[to + data] ?? (to === CANARY ? w(burned ? "1" : "0") : w("0"));
    return { json: async () => ({ result: "0x" + r }) };
  };
}
const chain = () => p.rpcChain("http://rpc.invalid", ATTEST, CANARY);
const withRpc = async (rpc, f) => { const old = globalThis.fetch; globalThis.fetch = rpc; try { return await f(); } finally { globalThis.fetch = old; } };

// guest_attest.pack, enough to re-encode a mutated log.
function pack(o) {
  const head = (n, fix, wide) => n < 16 ? [fix | n] : [wide, n >> 8, n & 255];
  if (Array.isArray(o)) return [...head(o.length, 0x90, 0xdc), ...o.flatMap(pack)];
  if (typeof o === "object") return [...head(Object.keys(o).length, 0x80, 0xde), ...Object.entries(o).flatMap(([k, v]) => [...pack(k), ...pack(v)])];
  if (typeof o === "string") { const b = [...new TextEncoder().encode(o)]; return [...(b.length < 32 ? [0xa0 | b.length] : b.length < 256 ? [0xd9, b.length] : [0xda, b.length >> 8, b.length & 255]), ...b]; }
  return o < 128 ? [o] : [0xcc, o];
}
function relog(blobHex, f) {
  const a = p.unpack(p.unhex(blobHex))[0];
  a.stack.data.events = f(a.stack.data.events);
  return p.hex(Uint8Array.from(pack(a)));
}
test("the real canary run-2 assertion verifies against the enrolled key and the approved build", async () => {
  const a = await p.decodeAttestation(p.unhex(canary.attestation));
  assert.equal(p.hex(a.head), "a43646c833fa7dcc9ef7bf736ebd680c28c0ddcc8bdbed7d0de706ea84b1808c");
  await withRpc(fakeRpc(canary), () => p.checkAssertion(a, chain(), NOW));
});

test("wrong build: a cdhash CDRegistry no longer resolves is refused", async () => {
  const a = await p.decodeAttestation(p.unhex(canary.attestation));
  await withRpc(fakeRpc(canary, { rp: "0" }), () => assert.rejects(p.checkAssertion(a, chain(), NOW), /approved CDRegistry build/));
});

test("a canary-burned image is refused", async () => {
  const a = await p.decodeAttestation(p.unhex(canary.attestation));
  await withRpc(fakeRpc(canary, { burned: true }), () => assert.rejects(p.checkAssertion(a, chain(), NOW), /canary burned/));
});

test("event after seal: a log with an event past system-ready does not decode", async () => {
  const blob = relog(canary.attestation, (e) => [...e, { event: "secret-key", payload: btoa("x".repeat(64)) }]);
  await assert.rejects(p.decodeAttestation(p.unhex(blob)), /only system-ready/);
});

test("event after seal: a secret-key spliced in before system-ready breaks the assertion", async () => {
  const blob = relog(canary.attestation, (e) => [...e.slice(0, -1), { event: "secret-key", payload: btoa("x".repeat(64)) }, e.at(-1)]);
  const a = await p.decodeAttestation(p.unhex(blob));
  await withRpc(fakeRpc(canary), () => assert.rejects(p.checkAssertion(a, chain(), NOW), /assertion signature/));
});

test("a log without a secret-key is refused before any chain read", async () => {
  await assert.rejects(p.check({ task_id: "t", attestation: canary.attestation }, { manifest: "", images: [] }, null, NOW), /exactly one 64-byte secret-key/);
});

// A real Mac run of secret_workload.py: the log carries the agent's secret-key and report_data binds the task.
const run = fx("secret-run.json");
const TASK = { manifest: run.manifest, images: [run.os_image_hash] };
const req = { task_id: run.task_id, attestation: run.attestation };

test("the real secret run releases: the secret is sealed to its secret-key", async () => {
  const sealed = await withRpc(fakeRpc(run), () => p.release(req, TASK, p.unhex("5ec2e7"), chain(), NOW));
  const a = await p.decodeAttestation(p.unhex(run.attestation));
  assert.deepEqual(a.system_events.filter(([n]) => n === "secret-key").map(([, k]) => p.hex(k)), [run.secret_key]);
  assert.equal(sealed.epk.length, 128);
});

test("wrong manifest: another task's compose hash is refused", async () => {
  await withRpc(fakeRpc(run), () => assert.rejects(p.release(req, { ...TASK, manifest: "11".repeat(32) }, new Uint8Array(1), chain(), NOW), /compose hash/));
});

test("an attestation bound to another task id is refused", async () => {
  await withRpc(fakeRpc(run), () => assert.rejects(p.release({ ...req, task_id: "other" }, TASK, new Uint8Array(1), chain(), NOW), /report_data/));
});

test("the Lit wrapper releases a secret provisioned to the action key, and only for the task it was sealed under", async () => {
  const src = fs.readFileSync(new URL("policy.mjs", import.meta.url), "utf8").replace(/^export /gm, "")
    + fs.readFileSync(new URL("lit-action.js", import.meta.url), "utf8")
    + `\nconst POLICY = ${JSON.stringify({ rpc: "http://rpc.invalid", attest: ATTEST, canary: CANARY })};\nmain`;
  globalThis.Lit = { Actions: { getLitActionPrivateKey: async () => "0x" + "42".repeat(32) } };
  const main = (0, eval)(src);
  const { pub } = await main({ op: "publicKey" });
  const task = { id: run.task_id, ...TASK };
  const label = "dsmack.secret-release/lit-task/1" + JSON.stringify([task.id, task.manifest, task.images]);
  const wrapped = await p.seal(p.unhex(pub), p.unhex("5ec2e7"), label);
  await withRpc(fakeRpc(run), async () => {
    assert.equal((await main({ op: "release", task, wrapped, ...req })).epk.length, 128);
    await assert.rejects(main({ op: "release", task: { ...task, images: [...task.images, "00".repeat(32)] }, wrapped, ...req }));
  });
});
