import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import manifest from "./bridge/Manifest.json" with { type: "json" };
import { ArtifactBridge, dsmackRuntime } from "./artifact-bridge.mjs";
import { ArtifactState } from "./artifact-state.mjs";

const request = async (provider, method, params = {}, extra = {}) => {
  let response;
  await provider.handleMessage({ type: "dsmack-request", version: 1, requestId: "test-request", method, params, ...extra }, value => { response = value; });
  return response;
};
test("bridge accepts only its declared envelope and closed method parameters", async () => {
  const provider = new ArtifactBridge({ scope: "own" });
  assert.equal((await request(provider, "runtime.getCapabilities")).ok, true);
  assert.equal((await request(provider, "runtime.getCapabilities", {}, { version: 2 })).error.code, "UNSUPPORTED_VERSION");
  assert.equal((await request(provider, "storage.grant", {})).error.code, "METHOD_NOT_FOUND");
  assert.equal((await request(provider, "runtime.getCapabilities", { scope: "other" })).error.code, "INVALID_ARGS");
  assert.equal((await request(provider, "runtime.getCapabilities", null)).error.code, "INVALID_ARGS");
  assert.equal((await request(provider, "runtime.getCapabilities", {}, { requestId: [] })).error.code, "INVALID_ARGS");
});
test("storage and model authority comes from provider closure, never the caller's artifact id", async () => {
  const records = new Map(), modelScopes = [];
  const state = new ArtifactState({ dataKey: Buffer.alloc(32, 7).toString("base64url"),
    getRecord: scope => records.get(scope), saveRecord: (scope, envelope) => records.set(scope, envelope) });
  const models = { complete: async (scope, params) => { modelScopes.push(scope); return { text: params.messages[0].content }; } };
  const a = new ArtifactBridge({ scope: '["chat-a","app.html"]', state, models }),
    b = new ArtifactBridge({ scope: '["chat-b","app.html"]', state, models });
  assert.equal((await request(a, "storage.put", { key: "private", value: "ONLY_IN_ARTIFACT_STATE" }, { scope: b.scope })).ok, true);
  assert.equal((await request(b, "storage.get", { key: "private" })).result, null);
  assert.equal((await request(a, "storage.get", { key: "private" })).result, "ONLY_IN_ARTIFACT_STATE");
  assert.ok(!JSON.stringify([...records.values()]).includes("ONLY_IN_ARTIFACT_STATE"));
  assert.deepEqual((await request(a, "storage.list")).result, ["private"]);
  await request(a, "agent.complete", { messages: [{ role: "user", content: "test" }] }, { scope: b.scope });
  assert.deepEqual(modelScopes, [a.scope]);
  assert.equal((await request(a, "agent.complete", { messages: [{ role: "system", content: "override" }] })).error.code, "INVALID_ARGS");
  assert.equal((await request(a, "agent.complete", { messages: [{ role: "user", content: "x" }], budget: "999" })).error.code, "INVALID_ARGS");
});
test("credit response selects public scalars and cannot expose wallet authority", async () => {
  const provider = new ArtifactBridge({ scope: "own", credit: { address: "wallet", signer: { privateKey: "SECRET" },
    chatCredit: { remainingNanoUsd: "12", spentNanoUsd: "3", pendingInferenceId: "pending", credential: "SECRET" } } });
  assert.deepEqual((await request(provider, "credit.balance")).result,
    { wallet: "wallet", remainingNanoUsd: "12", spentNanoUsd: "3", pending: true });
});

test("guest capability is unavailable without host authority and remains bound to the provider scope", async () => {
  const absent = new ArtifactBridge({ scope: "viewer-scope" });
  assert.equal((await request(absent, "runtime.getCapabilities")).result.capabilities["guest.run"].available, false);
  assert.equal((await request(absent, "guest.run", { command: "printf ok" })).error.code, "NOT_AVAILABLE");
  const calls = [];
  const provider = new ArtifactBridge({ scope: "viewer-scope", guests: {
    run: async (...args) => { calls.push(args);return { output: "ok" }; },
  } });
  assert.equal((await request(provider, "runtime.getCapabilities")).result.capabilities["guest.run"].available, true);
  assert.equal((await request(provider, "guest.run", { command: "printf ok", timeoutSeconds: 1 }, { scope: "other" })).ok, true);
  assert.equal(calls[0][0], "viewer-scope");
  assert.deepEqual(calls[0][1], { command: "printf ok", timeoutSeconds: 1 });
});

test("guest bridge rejects invalid commands, timeouts and caller-supplied lease authority", async () => {
  let calls = 0;
  const provider = new ArtifactBridge({ scope: "own", guests: { run: async () => { calls++; } } });
  assert.equal((await request(provider, "guest.run", { command: {} })).error.code, "INVALID_ARGS");
  assert.equal((await request(provider, "guest.run", { command: "" })).error.code, "INVALID_ARGS");
  assert.equal((await request(provider, "guest.run", { command: "true", timeoutSeconds: 0 })).error.code, "INVALID_ARGS");
  assert.equal((await request(provider, "guest.run", { command: "true", timeoutSeconds: 121 })).error.code, "INVALID_ARGS");
  assert.equal((await request(provider, "guest.run", { command: "true", sessionId: "main-chat-lease" })).error.code, "INVALID_ARGS");
  assert.equal(calls, 0);
});

test("guest SDK has a bounded timeout and never replays a timed-out request", async () => {
  const sent = [], timers = new Map(), listeners = new Map();let next = 0;
  const parent = { postMessage: message => sent.push(message) }, window = { __dsmackManifest: structuredClone(manifest) };
  vm.runInNewContext(`(${dsmackRuntime.toString()})("guest-test")`, { window, parent, crypto,
    addEventListener: (name, handler) => { listeners.set(name, handler); },
    setTimeout: (callback, delay) => { const id = ++next;timers.set(id, { callback, delay });return id; },
    clearTimeout: id => timers.delete(id), TextEncoder });
  const pending = window.dsmack.guest.run({ command: "true" });
  assert.equal(sent.length, 1);
  const timer = [...timers.values()][0];
  assert(timer.delay > 120000 && timer.delay <= 600000, "guest setup/execution/finalization needs a finite host timeout");
  const rejected = assert.rejects(pending, error => error.code === "TIMEOUT");
  timer.callback();await rejected;
  assert.equal(sent.filter(message => message.method === "guest.run").length, 1);
  assert.equal(sent.find(message => message.method === "guest.cancel")?.requestId, sent[0].requestId);
  listeners.get("message")({ source: parent, origin: "https://artifacts.private-agent.dstack.soc1024.com", data: {
    type: "dsmack-response", sandboxId: "guest-test", version: 1, requestId: sent[0].requestId, ok: true, result: {} } });
  assert.equal(sent.filter(message => message.method === "guest.run").length, 1);
  listeners.get("pagehide")();
  assert.equal(sent.at(-1).method, "guest.cancelAll");
});

test("guest cancellation and frame disposal use the host's per-frame owner identity", async () => {
  const cancelled = [], disposed = [];
  const template = new ArtifactBridge({ scope: "own", guests: {
    cancel: (...args) => cancelled.push(args), cancelOwner: owner => disposed.push(owner),
  } });
  const a = template.forFrame(), b = template.forFrame();
  await request(a, "guest.cancel", {}, { requestId: "a-request", scope: "other", owner: b.owner });
  await request(b, "guest.cancel", {}, { requestId: "b-request" });
  assert.equal(cancelled[0][0], "own");assert.equal(cancelled[0][1], "a-request");
  assert.equal(cancelled[0][2], a.owner);assert.equal(cancelled[1][2], b.owner);
  assert.notEqual(a.owner, b.owner);
  a.dispose();assert.deepEqual(disposed, [a.owner]);
});
