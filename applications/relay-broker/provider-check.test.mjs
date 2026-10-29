import assert from "node:assert/strict";
import { test } from "node:test";
import { providerCheck } from "./provider-check.mjs";
import { Payments } from "./payments.mjs";

const NONCE = "ab".repeat(32), MODEL = "fixture/tee-model";
const OPERATOR = "synthetic-operator-token",
  KEY = "sk-synthetic-provider-secret-marker";
const digest = async (text) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
    ),
    (n) => n.toString(16).padStart(2, "0"),
  ).join("");
function fixture() {
  let at = 2000000000, saved, paidCalls = 0, attests = 0, closed = 0;
  const calls = [];
  const payments = new Payments({
    cfg: {},
    key: {},
    quorum: {},
    save: async (state) => {
      saved = structuredClone(state);
    },
  });
  const provider = {
    apiKey: KEY,
    async attest({ model, nonce }) {
      attests++;
      return {
        evidence: { verification: "verified", model, nonce },
        transport: {
          close() {
            closed++;
          },
        },
      };
    },
    async chat(options) {
      paidCalls++;
      calls.push(options);
      assert.equal(
        saved.lastProviderCheckAt,
        at,
        "rate reservation must persist before inference",
      );
      return new Response(
        "data: " +
          JSON.stringify({
            model: MODEL,
            choices: [{ delta: { content: "OK" } }],
          }) + "\n\ndata: " +
          JSON.stringify({
            choices: [],
            usage: { prompt_tokens: 7, completion_tokens: 1, total_tokens: 8 },
          }) + "\n\ndata: [DONE]\n\n",
        {
          headers: {
            "content-type": "text/event-stream",
            "inference-id": "inference-fixture",
          },
        },
      );
    },
    async costs(options) {
      assert.deepEqual(options, {
        key: KEY,
        requestIds: ["inference-fixture"],
      });
      return {
        requests: [{ requestId: "inference-fixture", costNanoUsd: 300 }],
      };
    },
  };
  const request = (body = { nonce: NONCE }, token = OPERATOR) =>
    new Request("http://localhost/inference/provider-check", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + token,
      },
      body: JSON.stringify(body),
    });
  async function run(req = request()) {
    return await providerCheck({
      request: req,
      provider,
      payments,
      cfg: { model: MODEL },
      operatorTokenHash: await digest(OPERATOR),
      now: () => at,
    });
  }
  return {
    provider,
    payments,
    calls,
    request,
    run,
    advance: (n) => at += n,
    saved: () => saved,
    paidCalls: () => paidCalls,
    attests: () => attests,
    closed: () => closed,
  };
}
const code = (expected) => (error) => {
  assert.equal(error.code, expected);
  return true;
};

test("provider diagnostic refuses unauthorized and caller-controlled requests before inference", async () => {
  const f = fixture();
  await assert.rejects(
    f.run(f.request({ nonce: NONCE }, "wrong-token")),
    code("OPERATOR_AUTH"),
  );
  await assert.rejects(
    f.run(
      f.request({
        nonce: NONCE,
        messages: [{ role: "user", content: "caller prompt" }],
      }),
    ),
    code("BAD_REQUEST"),
  );
  await assert.rejects(
    f.run(f.request({ nonce: NONCE, model: "caller/model" })),
    code("BAD_REQUEST"),
  );
  await assert.rejects(f.run(f.request({ nonce: "old" })), code("BAD_REQUEST"));
  assert.equal(f.paidCalls(), 0);
  assert.equal(f.attests(), 0);
  assert.equal(f.saved(), undefined);
});

test("provider diagnostic uses fixed bounded prompt and reports attributed streamed usage", async () => {
  const f = fixture(), result = await f.run();
  assert.equal(result.result, "PASS");
  assert.equal(result.model, MODEL);
  assert.equal(result.inferenceId, "inference-fixture");
  assert.equal(result.attestation.nonce, NONCE);
  assert.equal(result.streamCompleted, true);
  assert.equal(result.reply, "OK");
  assert.deepEqual(result.usage, {
    prompt_tokens: 7,
    completion_tokens: 1,
    total_tokens: 8,
  });
  assert.equal(result.costNanoUsd, "300");
  assert.equal(f.calls[0].key, KEY);
  assert.equal(f.calls[0].model, MODEL);
  assert.equal(f.calls[0].max_tokens, 128);
  assert.deepEqual(f.calls[0].messages, [{
    role: "user",
    content: "Reply with exactly OK.",
  }]);
  assert.equal(f.closed(), 1);
  const persisted = JSON.stringify(f.saved());
  assert.deepEqual(Object.keys(f.saved()).sort(), [
    "grants",
    "lastProviderCheckAt",
    "receipts",
  ]);
  for (const value of [KEY, OPERATOR, "Reply with exactly OK.", '"OK"']) {
    assert(!persisted.includes(value));
  }
});

test("provider diagnostic serializes its durable one-minute rate limit", async () => {
  const f = fixture();
  const results = await Promise.allSettled([f.run(), f.run()]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(
    results.find((r) => r.status === "rejected").reason.code,
    "PROVIDER_RATE_LIMIT",
  );
  assert.equal(f.paidCalls(), 1);
  f.advance(59);
  await assert.rejects(f.run(), code("PROVIDER_RATE_LIMIT"));
  assert.equal(f.paidCalls(), 1);
  f.advance(1);
  assert.equal((await f.run()).result, "PASS");
  assert.equal(f.paidCalls(), 2);
});

test("provider diagnostic cannot call inference if durable reservation or attestation fails", async () => {
  const f = fixture();
  f.payments.save = async () => {
    throw Error("disk full");
  };
  await assert.rejects(f.run(), /disk full/);
  assert.equal(f.paidCalls(), 0);
  assert.equal(f.attests(), 0);
  const g = fixture();
  g.provider.attest = async ({ model }) => ({
    evidence: { verification: "verified", model, nonce: "00".repeat(32) },
  });
  await assert.rejects(g.run(), code("ATTESTATION_INVALID"));
  assert.equal(g.paidCalls(), 0);
});

test("provider diagnostic rejects incomplete stream and foreign cost attribution", async () => {
  const f = fixture();
  f.provider.chat = async () =>
    new Response('data: {"choices":[{"delta":{"content":"OK"}}]}\n\n', {
      headers: {
        "content-type": "text/event-stream",
        "inference-id": "inference-fixture",
      },
    });
  await assert.rejects(f.run(), code("PROVIDER_UNAVAILABLE"));
  const g = fixture();
  g.provider.costs = async () => ({
    requests: [{ requestId: "foreign-inference", costNanoUsd: 300 }],
  });
  await assert.rejects(g.run(), code("USAGE_MISMATCH"));
  assert.equal(g.closed(), 1);
});
