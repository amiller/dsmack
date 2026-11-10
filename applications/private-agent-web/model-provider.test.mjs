import test from "node:test";
import assert from "node:assert/strict";
import { directModel, modelBadge, modelPrivacy, loadProvider, saveProvider, providerStream, defaultAnthropicModel, checkProvider } from "./model-provider.mjs";

const compatible = () => directModel("openai-compatible", "user-model", "https://model.example/v1");
const near = { provider: "near", id: "near-model" };
function memoryStorage() {
  const store = () => { const data = new Map(); return { data, get: async key => data.get(key), set: async (key, value) => data.set(key, value), delete: async key => data.delete(key) }; };
  const customProviders = store();
  customProviders.set = async value => customProviders.data.set(value.id, value);
  return { settings: store(), providerKeys: store(), customProviders };
}
const completion = () => new Response('data: {"id":"reply","choices":[{"delta":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });

test("NEAR is the zero-setup default and switching back keeps keys out of provider settings", async () => {
  const storage = memoryStorage();
  assert.equal(await loadProvider(storage), undefined);
  const model = compatible();
  await saveProvider(storage, model, "browser-only-secret");
  assert.deepEqual(await loadProvider(storage), model);
  assert.equal(await storage.providerKeys.get(model.provider), "browser-only-secret");
  assert(!JSON.stringify([...storage.customProviders.data, ...storage.settings.data]).includes("browser-only-secret"));
  await saveProvider(storage);
  assert.equal(await loadProvider(storage), undefined);
  assert.equal(await storage.providerKeys.get(model.provider), "browser-only-secret");
});

test("changing endpoint cannot reuse another endpoint's key", () => {
  assert.notEqual(compatible().provider, directModel("openai-compatible", "user-model", "https://other.example/v1").provider);
  assert.throws(() => directModel("openai-compatible", "x", "https://user:secret@model.example/v1"), /without credentials/);
});

test("badge and preamble identify who receives the conversation", () => {
  assert(modelBadge(near).includes("near model"));
  assert(modelBadge(near).includes("NEAR AI"));
  assert.doesNotMatch(modelPrivacy(near), /NEAR model TEE/);
  for (const model of [compatible(), directModel("anthropic", defaultAnthropicModel)]) {
    assert.match(modelBadge(model), /sees the conversation/);
    assert.match(modelPrivacy(model), /sees the conversation/);
    assert(!modelPrivacy(model).includes("NEAR model TEE"));
  }
});

test("NEAR selection retains the broker stream and its preflight", () => {
  const expected = {}, context = {}, options = {};
  const stream = providerStream({ near: (...args) => { assert.deepEqual(args, [near, context, options]); return expected; }, preflight: () => assert.fail("broker owns NEAR preflight") });
  assert.equal(stream(near, context, options), expected);
});

test("direct Pi inference checks the monitor, replaces the preamble and retains tools without broker billing", async () => {
  let checks = 0, requests = 0;
  const model = compatible();
  const context = { messages: [
    { role: "system", content: "Old NEAR TEE prompt", toolsAdded: [{ name: "bash", description: "Run", parameters: { type: "object", properties: {} } }], timestamp: 0 },
    { role: "user", content: "Inspect code", timestamp: 1 },
  ] };
  const stream = providerStream({ near: () => assert.fail("direct calls must bypass broker metering"),
    preflight: async (received, signal) => { assert.equal(received, context); assert(signal); checks++; },
    systemPrompt: ({ model }) => modelPrivacy(model), startedAt: "2026-11-02",
  });
  const options = { apiKey: "browser-only-secret", signal: new AbortController().signal,
    fetch: async (_url, init) => {
      requests++;
      assert.equal(checks, requests, "each direct inference runs preflight first");
      assert.equal(new Headers(init.headers).get("authorization"), "Bearer browser-only-secret");
      const body = JSON.parse(init.body);
      assert.match(body.messages[0].content, /model.example.*sees the conversation/);
      assert(!JSON.stringify(body).includes("Old NEAR TEE prompt"));
      assert.equal(body.tools[0].function.name, "bash");
      return completion();
    },
  };
  for (let i = 0; i < 2; i++) {
    const answer = await stream(model, context, options).result();
    assert.equal(answer.stopReason, "stop", answer.errorMessage);
    assert.equal(answer.content[0].text, "OK");
    assert.equal(answer.billing, undefined);
  }
  assert.equal(checks, 2);
});

test("Anthropic's normal Pi stream includes its direct browser access header", async () => {
  const model = directModel("anthropic", defaultAnthropicModel);
  const stream = providerStream({ preflight: async () => {}, systemPrompt: ({ model }) => modelPrivacy(model) });
  let request;
  const answer = await stream(model, { messages: [{ role: "user", content: "Hi", timestamp: 1 }] }, {
    apiKey: "sk-ant-browser-only", fetch: async (_url, init) => {
      request = init;
      return new Response('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"'+model.id+'","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}\n\nevent: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\nevent: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"OK"}}\n\nevent: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\nevent: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n', { headers: { "content-type": "text/event-stream" } });
    },
  }).result();
  assert.equal(answer.stopReason, "stop", answer.errorMessage);
  assert.equal(new Headers(request.headers).get("anthropic-dangerous-direct-browser-access"), "true");
  assert.equal(new Headers(request.headers).get("x-api-key"), "sk-ant-browser-only");
  assert.match(JSON.stringify(JSON.parse(request.body).system), /Anthropic.*sees the conversation/);
});

test("failed browser connection prevents selecting an endpoint", async () => {
  const prior = globalThis.fetch;
  globalThis.fetch = async () => { throw TypeError("Failed to fetch: CORS"); };
  try { await assert.rejects(checkProvider(compatible(), "test-key"), /Browser connection failed.*CORS/); }
  finally { globalThis.fetch = prior; }
});
