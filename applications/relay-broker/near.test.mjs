import { strict as assert } from "node:assert";
import { NearError, NearProvider } from "./near.mjs";
import { verifyNearAttestation } from "./near-attestation.mjs";
import { createPinnedTlsFetch } from "npm:@nearai/inference-sdk@0.2.0/node";

const refusal = (code) => (e) => e instanceof NearError && e.code === code;
Deno.test("billing uses the known request ID and integer provider costs", async () => {
  const p = new NearProvider({
    fetcher: (url, init) => {
      assert.equal(url, "https://cloud-api.near.ai/v1/billing/costs");
      assert.equal(init.headers.authorization, "Bearer schema-fixture");
      assert.deepEqual(JSON.parse(init.body), { requestIds: ["inference-1"] });
      return Response.json({
        requests: [{ requestId: "inference-1", costNanoUsd: 14100 }],
      });
    },
  });
  assert.deepEqual(
    await p.costs({ key: "schema-fixture", requestIds: ["inference-1"] }),
    { requests: [{ requestId: "inference-1", costNanoUsd: 14100 }] },
  );
  for (
    const result of [{ requests: [{ requestId: "foreign", costNanoUsd: 1 }] }, {
      requests: [{ requestId: "inference-1", costNanoUsd: 0.1 }],
    }]
  ) {
    p.fetcher = () => Response.json(result);
    await assert.rejects(
      () => p.costs({ key: "schema-fixture", requestIds: ["inference-1"] }),
      refusal("USAGE_MISMATCH"),
    );
  }
});
Deno.test("provider errors never reflect credentials or raw responses", async () => {
  const p = new NearProvider({
    fetcher: () => new Response("sk-secret-fixture", { status: 401 }),
  });
  await assert.rejects(
    () => p.costs({ key: "fixture", requestIds: ["inference-1"] }),
    refusal("PROVIDER_HTTP_401"),
  );
  p.fetcher = () => new Response('"sk-secret-fixture');
  await assert.rejects(
    () => p.costs({ key: "fixture", requestIds: ["inference-1"] }),
    refusal("USAGE_MISMATCH"),
  );
});
Deno.test("encrypted chat passes browser ciphertext unchanged over the pinned transport", async () => {
  const p = new NearProvider();
  const body = {
    model: "near/model",
    messages: [{ role: "user", content: "04" + "ab".repeat(100) }],
    stream: true,
    max_tokens: 8,
  };
  let calls = 0;
  const checked = {
    evidence: {
      model: body.model,
      verified: true,
      expires_at: Date.now() / 1000 + 60,
    },
    transport: {
      fetch: () => {
        throw Error("browser ciphertext must not be encrypted twice");
      },
      fetchEncrypted: (url, init) => {
        calls++;
        assert.equal(url, "https://cloud-api.near.ai/v1/chat/completions");
        assert.equal(init.headers.authorization, "Bearer fixture");
        assert.deepEqual(JSON.parse(init.body), body);
        assert.equal(init.headers["x-encrypt-all-fields"], "true");
        return new Response(
          'data: {"choices":[{"delta":{"content":"ciphertext"}}]}\n\ndata: [DONE]\n\n',
          {
            headers: {
              "content-type": "text/event-stream",
              "inference-id": "inference-1",
            },
          },
        );
      },
    },
  };
  const r = await p.chatEncrypted({
    key: "fixture",
    model: body.model,
    body,
    headers: { "x-encrypt-all-fields": "true" },
    attestation: checked,
  });
  assert((await r.text()).includes("ciphertext"));
  assert.equal(calls, 1);
  checked.evidence.expires_at = 1;
  await assert.rejects(
    () =>
      p.chatEncrypted({
        key: "fixture",
        model: body.model,
        body,
        headers: {},
        attestation: checked,
      }),
    refusal("ATTESTATION_INVALID"),
  );
  assert.equal(calls, 1);
});
Deno.test("attestation fetch uses the caller nonce without forwarding a provider credential", async () => {
  const nonce = "a".repeat(64), urls = [];
  const p = new NearProvider({
    apiKey: "must-stay-private",
    fetcher: (url, init) => {
      const u = new URL(url);
      urls.push(u);
      assert.equal(u.searchParams.get("nonce"), nonce);
      assert.equal(init.headers.authorization, undefined);
      return Response.json(
        u.searchParams.has("model")
          ? { model_attestations: [{}] }
          : { gateway_attestation: {} },
      );
    },
    verifyAttestation: ({ nonce: got, model }) => ({
      evidence: { nonce: got, model },
      modelPublicKey: "verified-key",
      transport: { fetch() {} },
    }),
  });
  const result = await p.attest({ model: "near/model", nonce });
  assert.equal(result.modelPublicKey, "verified-key");
  assert.equal(urls.length, 2);
  assert.equal(urls[0].searchParams.get("include_tls_fingerprint"), "true");
  assert.equal(urls[1].searchParams.get("provider"), "near");
});
Deno.test("unverified evidence and non-HTTPS channels cannot send a prompt", async () => {
  const p = new NearProvider();
  await assert.rejects(
    () =>
      p.chatEncrypted({
        key: "fixture",
        model: "near/model",
        body: {},
        headers: {},
      }),
    refusal("ATTESTATION_INVALID"),
  );
  await assert.rejects(() =>
    verifyNearAttestation({
      report: { gateway_attestation: {} },
      nonce: "1".repeat(64),
      model: "near/model",
      baseUrl: "https://cloud-api.near.ai",
    })
  );
  const pinned = createPinnedTlsFetch("1".repeat(64));
  await assert.rejects(
    () => pinned("http://127.0.0.1:1/chat", { method: "POST", body: "marker" }),
    /HTTPS/,
  );
});

Deno.test("upstream HTTP failures retain status and structured code without response content", async () => {
  const original = console.error, logs = [];
  console.error = line => logs.push(JSON.parse(line));
  try {
    for (const [status, body, suffix] of [
      [401, { error: { code: "invalid_api_key", message: "private response" } }, "_INVALID_API_KEY"],
      [402, { error: { code: "insufficient_credit" } }, "_INSUFFICIENT_CREDIT"],
      [429, { error: { code: "rate_limit" } }, "_RATE_LIMIT"],
      [503, { error: { message: "private response" } }, ""],
      [400, { error: { code: "secret with spaces" } }, ""],
    ]) {
      const code = `PROVIDER_HTTP_${status}${suffix}`;
      const attestation = { evidence: { model: "test", verified: true, expires_at: Date.now()/1000 + 60 },
        transport: { fetchEncrypted: () => Response.json(body, { status }) } };
      await assert.rejects(() => new NearProvider().chatEncrypted({ model: "test", body: {}, attestation }), refusal(code));
      assert.equal(logs.at(-1).code, code);
      assert.equal(logs.at(-1).http_status, status);
      const p = new NearProvider({ fetcher: () => Response.json(body, { status }) });
      await assert.rejects(() => p.costs({ key: "fixture", requestIds: ["known"] }), refusal(code));
    }
    assert(!JSON.stringify(logs).includes("private response"));
    assert(!JSON.stringify(logs).includes("secret with spaces"));
  } finally { console.error = original; }
});
Deno.test("transport errors distinguish timeout, abort and attested connection failure", async () => {
  for (const [name, code] of [["TimeoutError", "PROVIDER_TIMEOUT"], ["AbortError", "PROVIDER_ABORTED"], ["Error", "NEAR_ATTESTATION_TRANSPORT"]]) {
    const attestation = { evidence: { model: "test", verified: true, expires_at: Date.now()/1000 + 60 },
      transport: { fetchEncrypted: () => { throw Object.assign(Error("private transport details"), { name }); } } };
    await assert.rejects(() => new NearProvider().chatEncrypted({ model: "test", body: {}, attestation }), refusal(code));
  }
});

Deno.test("only definitive authentication refusals mark a dispatch rejected", async () => {
  for (const status of [401, 403, 429, 500]) {
    const p = new NearProvider({ fetcher: () => new Response("private provider body", { status }) });
    await assert.rejects(() => p.request("/v1/chat/completions", { token: "fixture", method: "POST" }), error => {
      assert.equal(error.dispatchRejected, status === 401 || status === 403);
      assert(!error.message.includes("private provider body"));
      return true;
    });
  }
});
