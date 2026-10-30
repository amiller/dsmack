import test from "node:test";
import assert from "node:assert/strict";
import { ArtifactBridge } from "./artifact-bridge.mjs";
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
