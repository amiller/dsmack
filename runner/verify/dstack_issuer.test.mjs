import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ISSUER_DOMAIN, issuerReportData, issuerPossessionMessage, issuerPolicyHash,
  createDstackIssuerVerifier, createDstackIssuerVerifierForTesting, verifyDcapQuote } from "./dstack_issuer.mjs";

const peer = "12D3KooWTestOnlySyntheticIssuerPeer0001", otherPeer = "12D3KooWTestOnlySyntheticIssuerPeer0002";
const sha = (kind, data) => crypto.createHash(kind).update(data).digest();
const pair = crypto.generateKeyPairSync("ed25519"), publicKeyHex = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const compose = '{"name":"SYNTHETIC TEST ONLY","services":{}}';
const policy = { version: 2, challenge_ttl_ms: 1000, approved_measurements: [{
  compose_sha256: sha("sha256", compose).toString("hex"), mr_td: "01".repeat(48), rtmr0: "02".repeat(48), rtmr1: "03".repeat(48), rtmr2: "04".repeat(48),
  runtime_events: { "app-id": "05".repeat(20), "key-provider": "06".repeat(32), "os-image-hash": "07".repeat(32) },
}] };
const copy = (v) => JSON.parse(JSON.stringify(v));
const options = (p = policy) => ({ policy: p, expectedPolicySha256: issuerPolicyHash(p) });
function event(name, payload, version = 1) {
  const type = Buffer.from("01000008", "hex");
  const preimage = version === 1 ? Buffer.concat([type, Buffer.from(`:${name}:`), Buffer.from(payload, "hex")])
    : Buffer.from(JSON.stringify({ name, payload, type: 0x08000001 }));
  return { imr: 3, event_type: 0x08000001, event: name, event_payload: payload, digest: sha("sha384", preimage).toString("hex"),
    ...(version === 2 ? { version, preimage: preimage.toString("hex") } : {}) };
}
function fixture(binding, { version = 1, events } = {}) {
  const m = policy.approved_measurements[0];
  events ??= [event("compose-hash", m.compose_sha256, version), ...Object.entries(m.runtime_events).map(([k, v]) => event(k, v, version)), event("system-ready", "", version)];
  let mr = Buffer.alloc(48);
  for (const e of events) mr = sha("sha384", Buffer.concat([mr, Buffer.from(e.digest, "hex")]));
  const bundle = { domain: ISSUER_DOMAIN, binding, quote_hex: "00", event_log: JSON.stringify(events), app_compose: compose,
    possession_signature_hex: crypto.sign(null, issuerPossessionMessage(binding), pair.privateKey).toString("hex") };
  const quote = { quoteVersion: 4, reportType: "td10", status: "UpToDate", reportData: issuerReportData(binding).toString("hex"),
    tdAttributes: "0000001000000000", mrTd: m.mr_td, rtMr0: m.rtmr0, rtMr1: m.rtmr1, rtMr2: m.rtmr2, rtMr3: mr.toString("hex") };
  return { bundle, quote };
}
function setup({ p = policy, now = () => 1000, adapter } = {}) {
  let f, calls = 0;
  const verifier = createDstackIssuerVerifierForTesting({ ...options(p), now,
    syntheticQuoteVerifier: async (...args) => { calls++; return adapter ? adapter(...args) : f.quote; } });
  const binding = verifier.challenge({ remotePeer: peer, issuerPublicKeyHex: publicKeyHex });
  f = fixture(binding);
  return { verifier, f, calls: () => calls };
}

test("issuer64-byte canonical binding and possession match the Python collector", () => {
  const binding = { version: 2, peer_id: peer, public_key_hex: publicKeyHex, challenge_hex: "aa".repeat(32), policy_sha256: issuerPolicyHash(policy) };
  const py = spawnSync("python3", ["-c", "import json,sys; from experiments.coupon_redemption.dstack_issuer_identity import report_data; print(report_data(json.loads(sys.argv[1])).hex())", JSON.stringify(binding)], { cwd: new URL("../..", import.meta.url), encoding: "utf8" });
  assert.equal(py.status, 0, py.stderr); assert.equal(py.stdout.trim(), issuerReportData(binding).toString("hex"));
  assert.equal(issuerReportData(binding).length, 64);
  for (const changed of [{ peer_id: otherPeer }, { public_key_hex: "11".repeat(32) }, { challenge_hex: "bb".repeat(32) }, { policy_sha256: "cc".repeat(32) }])
    assert.notDeepEqual(issuerReportData(binding), issuerReportData({ ...binding, ...changed }));
});

test("strict synthetic identity verification reports only identity, never hardware/private issuance approval", async () => {
  for (const version of [1, 2]) {
    const { verifier, f } = setup();
    const vector = fixture(f.bundle.binding, { version }); f.bundle = vector.bundle; f.quote = vector.quote;
    const result = await verifier.verify(f.bundle, { remotePeer: peer });
    assert.equal(result.evidenceStatus, "synthetic-only-not-hardware"); assert.equal(result.scope, "issuer-identity-only");
    assert.equal(result.privateIssuanceQualified, false); assert.equal(result.rollbackQualified, false);
    assert.equal(result.peerId, peer); assert.equal(result.issuerPublicKeyHex, publicKeyHex);
    await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
  }
});

test("actual peer, accepted issuer key, policy, challenge and possession substitutions fail before DCAP", async () => {
  for (const change of [{ peer_id: otherPeer }, { public_key_hex: "11".repeat(32) }, { policy_sha256: "22".repeat(32) }, { challenge_hex: "33".repeat(32) }]) {
    const { verifier, f, calls } = setup(); f.bundle.binding = { ...f.bundle.binding, ...change };
    await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer })); assert.equal(calls(), 0);
  }
  const { verifier, f, calls } = setup();
  await assert.rejects(verifier.verify(f.bundle, { remotePeer: otherPeer })); assert.equal(calls(), 0);
  f.bundle.possession_signature_hex = "00".repeat(64);
  await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer })); assert.equal(calls(), 0);
});

test("quote version/type, TCB, debug/reserved bits, report data and boot measurements must all satisfy policy", async () => {
  for (const change of [{ quoteVersion: 5 }, { reportType: "sgx" }, { status: "OutOfDate" }, { tdAttributes: "0100001000000000" },
    { tdAttributes: "0000000000000000" }, { reportData: "00".repeat(64) }, { mrTd: "00".repeat(48) }, { rtMr0: "00".repeat(48) }, { rtMr1: "00".repeat(48) }, { rtMr2: "00".repeat(48) }]) {
    const { verifier, f } = setup(); Object.assign(f.quote, change); await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
  }
});

test("event display payload and name cannot be substituted while preserving genuine digest replay", async () => {
  for (const mutate of [(events) => { events[0].event_payload = "00".repeat(32); }, (events) => { events[1].event = "key-provider"; },
    (events) => { events[2].event_payload = "11".repeat(32); }, (events) => { events[0].version = 3; }]) {
    const { verifier, f } = setup(); const events = JSON.parse(f.bundle.event_log); mutate(events); f.bundle.event_log = JSON.stringify(events);
    await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
  }
  const { verifier, f } = setup(); f.bundle.app_compose += " "; await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
});

test("duplicate, absent or post-ready approval events and noncanonical v2 preimages fail even with matching synthetic RTMR3", async () => {
  for (const mutate of [(e) => e.splice(1, 1), (e) => e.unshift(e[0]), (e) => e.push(e.shift()), (e) => e.push(event("system-ready", ""))]) {
    const { verifier, f } = setup(); const events = JSON.parse(f.bundle.event_log); mutate(events);
    const v = fixture(f.bundle.binding, { events }); f.bundle = v.bundle; f.quote = v.quote;
    await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
  }
  const { verifier, f } = setup(); const v = fixture(f.bundle.binding, { version: 2 }); f.bundle = v.bundle; f.quote = v.quote;
  const e = JSON.parse(f.bundle.event_log); delete e[0].preimage; f.bundle.event_log = JSON.stringify(e);
  await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
});

test("same compose in another app or KMS scope is not admitted", async () => {
  for (const name of ["app-id", "key-provider", "os-image-hash"]) {
    const { verifier, f } = setup(); const events = JSON.parse(f.bundle.event_log);
    const index = events.findIndex((e) => e.event === name); events[index] = event(name, "ab".repeat(32));
    const v = fixture(f.bundle.binding, { events }); f.bundle = v.bundle; f.quote = v.quote;
    await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
  }
});

test("freshness, concurrent replay and closing during verification fail without later resurrection", async () => {
  let now = 1000;
  const expired = setup({ now: () => now }); now = 2000;
  await assert.rejects(expired.verifier.verify(expired.f.bundle, { remotePeer: peer })); assert.equal(expired.calls(), 0);
  now = 1000;
  let finish, signal;
  const delayed = setup({ now: () => now, adapter: (_quote, options) => { signal = options.signal; return new Promise((r) => { finish = r; }); } });
  const running = delayed.verifier.verify(delayed.f.bundle, { remotePeer: peer });
  await assert.rejects(delayed.verifier.verify(delayed.f.bundle, { remotePeer: peer }));
  delayed.verifier.close(); assert.equal(signal.aborted, true); finish(delayed.f.quote);
  await assert.rejects(running); assert.throws(() => delayed.verifier.challenge({ remotePeer: peer, issuerPublicKeyHex: publicKeyHex }));
  const slow = setup({ now: () => now, adapter: () => { now = 2000; return slow.f.quote; } });
  await assert.rejects(slow.verifier.verify(slow.f.bundle, { remotePeer: peer }));
  now = 1000; const rewind = setup({ now: () => now }); now = 999;
  await assert.rejects(rewind.verifier.verify(rewind.f.bundle, { remotePeer: peer }));
});

test("policy bytes cannot mutate after challenge; mismatched policy pin and unnamed synthetic override are refused", async () => {
  const mutable = copy(policy), { verifier, f } = setup({ p: mutable }); mutable.approved_measurements[0].runtime_events["app-id"] = "ff";
  assert.equal((await verifier.verify(f.bundle, { remotePeer: peer })).policySha256, issuerPolicyHash(policy));
  assert.throws(() => createDstackIssuerVerifier({ ...options(), expectedPolicySha256: "00".repeat(32) }));
  assert.throws(() => createDstackIssuerVerifier({ ...options(), syntheticQuoteVerifier: async () => f.quote }));
  const wildcard = copy(policy); wildcard.approved_measurements = []; assert.throws(() => issuerPolicyHash(wildcard));
});

test("bounded evidence and challenge inventory reject overflow before DCAP", async () => {
  for (const change of [{ quote_hex: "00".repeat(131073) }, { event_log: " ".repeat(1048577) }, { app_compose: "x".repeat(131073) }, { extra: true }]) {
    const { verifier, f, calls } = setup(); Object.assign(f.bundle, change); await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer })); assert.equal(calls(), 0);
  }
  const { verifier } = setup();
  for (let n = 1; n < 256; n++) verifier.challenge({ remotePeer: peer, issuerPublicKeyHex: publicKeyHex });
  assert.throws(() => verifier.challenge({ remotePeer: peer, issuerPublicKeyHex: publicKeyHex })); verifier.close();
});

test("normal genuine DCAP path rejects malformed evidence and startup timeout, reaps child, sanitizes errors", async () => {
  const start = Date.now();
  await assert.rejects(verifyDcapQuote("00"), { message: "dstack issuer identity verification refused" });
  await assert.rejects(verifyDcapQuote("00", { timeoutMs: 1 }), { message: "dstack issuer identity verification refused" });
  const aborted = new AbortController(); aborted.abort(); await assert.rejects(verifyDcapQuote("00", { signal: aborted.signal }));
  assert.ok(Date.now() - start < 5000);
  const verifier = createDstackIssuerVerifier(options()), b = verifier.challenge({ remotePeer: peer, issuerPublicKeyHex: publicKeyHex });
  await assert.rejects(verifier.verify(fixture(b).bundle, { remotePeer: peer })); verifier.close();
});

test("four active verifications bound work and refuse a fifth without spawning; completion frees capacity", async () => {
  const completions = [], calls = [];
  const verifier = createDstackIssuerVerifierForTesting({ ...options(), now: () => 1000,
    syntheticQuoteVerifier: (raw, { signal }) => { calls.push({ raw, signal }); return new Promise((resolve) => completions.push(resolve)); } });
  const vectors = Array.from({ length: 5 }, () => fixture(verifier.challenge({ remotePeer: peer, issuerPublicKeyHex: publicKeyHex })));
  const work = vectors.slice(0, 4).map(({ bundle }) => verifier.verify(bundle, { remotePeer: peer }));
  await assert.rejects(verifier.verify(vectors[4].bundle, { remotePeer: peer })); assert.equal(calls.length, 4);
  completions[0](vectors[0].quote); await work[0];
  const fifth = verifier.verify(vectors[4].bundle, { remotePeer: peer }); assert.equal(calls.length, 5);
  completions.slice(1).forEach((complete, index) => complete(vectors[index + 1].quote));
  await Promise.all([...work.slice(1), fifth]); verifier.close();
});

test("runnable CLI emits a fresh binding and normal path rejects synthetic evidence without hardware-success output", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "issuer-cli-test-")), policyFile = path.join(directory, "policy.json");
  fs.writeFileSync(policyFile, JSON.stringify(policy));
  const child = spawn(process.execPath, [fileURLToPath(new URL("./dstack_issuer_cli.mjs", import.meta.url)), "--policy", policyFile,
    "--expected-policy-sha256", issuerPolicyHash(policy), "--peer", peer, "--issuer-public-key", publicKeyHex]);
  let out = "", err = "", supplied = false;
  child.stdout.on("data", (chunk) => {
    out += chunk;
    if (!supplied && out.includes("\n")) {
      supplied = true;
      const { binding } = JSON.parse(out.split("\n")[0]);
      child.stdin.end(JSON.stringify(fixture(binding).bundle));
    }
  });
  child.stderr.on("data", (chunk) => { err += chunk; });
  try {
    const code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    assert.equal(code, 1); assert.equal(supplied, true); assert.equal(out.trim().split("\n").length, 1);
    assert.ok(err.includes("verification refused")); assert.ok(!out.includes("verified-intel"));
  } finally { child.kill("SIGKILL"); fs.rmSync(directory, { recursive: true, force: true }); }
});

test("runtime policy accepts the genuine guest event size and replay byte bound while preserving exact pins", async () => {
  // Guest 0.5.9 measured key-provider JSON has {name,id} and 204 UTF-8
  // bytes. Keep deployment identifiers private; this equivalent-shaped value
  // is synthetic, and the adapter cannot claim hardware verification.
  const realSizeShape = Buffer.from(JSON.stringify({ name: "kms", id: "x".repeat(182) })).toString("hex");
  assert.equal(realSizeShape.length, 204 * 2);
  for (const payload of [realSizeShape, "ab".repeat(4096)]) {
    const p = copy(policy); p.approved_measurements[0].runtime_events["key-provider"] = payload;
    const { verifier, f } = setup({ p });
    const m = p.approved_measurements[0];
    const events = [event("compose-hash", m.compose_sha256),
      ...Object.entries(m.runtime_events).map(([name, value]) => event(name, value)), event("system-ready", "")];
    const v = fixture(f.bundle.binding, { events }); f.bundle = v.bundle; f.quote = v.quote;
    const result = await verifier.verify(f.bundle, { remotePeer: peer });
    assert.equal(result.evidenceStatus, "synthetic-only-not-hardware");
    assert.equal(result.policySha256, issuerPolicyHash(p));
    verifier.close();

    const changed = setup({ p });
    const changedEvents = events.map(e => e.event === "key-provider" ? event("key-provider", "cd".repeat(payload.length / 2)) : e);
    const changedVector = fixture(changed.f.bundle.binding, { events: changedEvents });
    changed.f.bundle = changedVector.bundle; changed.f.quote = changedVector.quote;
    await assert.rejects(changed.verifier.verify(changed.f.bundle, { remotePeer: peer }));
    changed.verifier.close();
  }
  for (const payload of ["ab".repeat(4097), "ab".repeat(204) + "a", "gg".repeat(204), ""]) {
    const p = copy(policy); p.approved_measurements[0].runtime_events["key-provider"] = payload;
    assert.throws(() => issuerPolicyHash(p));
  }
});

test("SDK empty runtime digests are recomputed against authenticated RTMR3; substitutions still fail", async () => {
  for (const version of [1, 2]) {
    const { verifier, f } = setup();
    const v = fixture(f.bundle.binding, { version }); f.bundle = v.bundle; f.quote = v.quote;
    const events = JSON.parse(f.bundle.event_log);
    for (const e of events) e.digest = "";
    f.bundle.event_log = JSON.stringify(events);
    assert.equal((await verifier.verify(f.bundle, { remotePeer: peer })).evidenceStatus, "synthetic-only-not-hardware");
    verifier.close();
  }
  for (const change of [e => { e[1].event_payload = "ab".repeat(20); }, e => { e[1].event = "different-app"; },
    e => { e[1].event_type++; }, e => { e[1].digest = "00".repeat(48); }, e => { delete e[1].digest; },
    e => { e.push({ imr: 0, event_type: 1, digest: "", event: "", event_payload: "" }); }]) {
    const { verifier, f } = setup(); const events = JSON.parse(f.bundle.event_log);
    for (const e of events) e.digest = "";
    change(events); f.bundle.event_log = JSON.stringify(events);
    await assert.rejects(verifier.verify(f.bundle, { remotePeer: peer }));
    verifier.close();
  }
});
