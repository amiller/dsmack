import { NearError, NearProvider } from "./near.mjs";
import { verifyNearAttestation } from "./near-attestation.mjs";
import { createPinnedTlsFetch } from "npm:@nearai/inference-sdk@0.2.0/node";
import { strict as assert } from "node:assert";

const config = {
  workspaceId: "workspace-1",
  organizationId: "org-1",
  managementToken: "schema-session-fixture",
  reportingToken: "schema-reporting-fixture",
};
const row = (key = "key-1", n = 1) => ({
  source: "inference",
  id: "row-" + n,
  created_at: "2026-10-29T12:00:00Z",
  workspace_id: "workspace-1",
  api_key_id: key,
  total_cost_nano_usd: 1280,
  inference: {
    model: "near/model",
    input_tokens: 12,
    output_tokens: 3,
    total_tokens: 15,
    inference_id: "inference-" + n,
  },
});
const query = {
  keyId: "key-1",
  from: "2026-10-29T00:00:00Z",
  to: "2026-10-30T00:00:00Z",
  model: "near/model",
};
const rejects = (fn, code) =>
  assert.rejects(
    fn,
    (e) =>
      e instanceof NearError && e.code === code &&
      !e.message.includes("fixture"),
  );

Deno.test("mint uses session API and checks actual cumulative cap before delivery", async () => {
  let calls = 0;
  const p = new NearProvider({
    ...config,
    fetcher: (url, init) => {
      calls++;
      assert.equal(
        url,
        "https://cloud-api.near.ai/v1/workspaces/workspace-1/api-keys",
      );
      assert.equal(init.method, "POST");
      assert.equal(init.headers.authorization, "Bearer schema-session-fixture");
      assert.deepEqual(JSON.parse(init.body), {
        name: "purchase-1",
        spendLimit: { amount: 50000, currency: "USD" },
        expires_at: "2026-10-30T00:00:00Z",
      });
      return Response.json({
        id: "key-1",
        key: "sk-schema-fixture",
        spend_limit: { amount: 50000, scale: 9, currency: "USD" },
      }, { status: 201 });
    },
  });
  const out = await p.mint({
    name: "purchase-1",
    capNanoUsd: "50000",
    expiresAt: "2026-10-30T00:00:00Z",
  });
  assert.equal(out.id, "key-1");
  assert.equal(calls, 1);
});
Deno.test("provider errors never expose raw error responses or secrets", async () => {
  const p = new NearProvider({
    ...config,
    fetcher: () => new Response("sk-secret-fixture", { status: 401 }),
  });
  await rejects(
    () =>
      p.mint({
        name: "purchase-1",
        capNanoUsd: "50000",
        expiresAt: "2026-10-30T00:00:00Z",
      }),
    "PROVIDER_AUTH",
  );
});
Deno.test("malformed provider JSON cannot leak response content in an error", async () => {
  const p = new NearProvider({
    ...config,
    fetcher: () => new Response('"sk-secret-fixture'),
  });
  await rejects(
    () =>
      p.mint({
        name: "purchase-1",
        capNanoUsd: "50000",
        expiresAt: "2026-10-30T00:00:00Z",
      }),
    "USAGE_MISMATCH",
  );
});
Deno.test("filtered usage keeps stable windows and paginates exact per-key totals", async () => {
  const urls = [];
  const p = new NearProvider({
    ...config,
    fetcher: (url) => {
      urls.push(new URL(url));
      return Response.json({
        data: [row("key-1", urls.length)],
        next_cursor: urls.length === 1 ? "second" : null,
      });
    },
  });
  const out = await p.usage(query);
  assert.equal(out.totalTokens, "30");
  assert.equal(out.costNanoUsd, "2560");
  const withUnknownText = new NearProvider({
    ...config,
    fetcher: () =>
      Response.json({
        data: [{ ...row(), prompt: "untrusted-prompt-marker" }],
        next_cursor: null,
      }),
  });
  assert(
    !JSON.stringify(await withUnknownText.usage(query)).includes(
      "untrusted-prompt-marker",
    ),
  );
  assert.equal(urls[0].searchParams.get("api_key_id"), "key-1");
  assert.equal(urls[1].searchParams.get("cursor"), "second");
  assert.equal(
    urls[0].searchParams.get("end_time"),
    urls[1].searchParams.get("end_time"),
  );
});
Deno.test("foreign-key rows cannot debit this user's credit", async () => {
  const p = new NearProvider({
    ...config,
    fetcher: () =>
      Response.json({ data: [row("foreign-key")], next_cursor: null }),
  });
  await rejects(() => p.usage(query), "USAGE_MISMATCH");
});
Deno.test("duplicate export pages cannot double bill usage", async () => {
  const p = new NearProvider({
    ...config,
    fetcher: () => Response.json({ data: [row()], next_cursor: "again" }),
  });
  await rejects(() => p.usage(query), "USAGE_MISMATCH");
});
Deno.test("attestation rejection stops chat before any prompt crosses transport", async () => {
  const p = new NearProvider({
    ...config,
    fetcher: () => {
      throw new Error("no network");
    },
  });
  await rejects(
    () =>
      p.chat({
        key: "fixture",
        model: "near/model",
        messages: [{ role: "user", content: "marker" }],
        max_tokens: 4,
      }),
    "ATTESTATION_INVALID",
  );
});
Deno.test("default verifier requires real evidence and an approved measured deployment", async () => {
  await assert.rejects(() =>
    verifyNearAttestation({
      report: {
        gateway_attestation: {
          tls_cert_fingerprint: "0".repeat(64),
          signing_algo: "ecdsa",
        },
      },
      nonce: "1".repeat(64),
      model: "near/model",
      baseUrl: "https://cloud-api.near.ai",
    })
  );
});
Deno.test("SDK pinned TLS refuses non-HTTPS prompt destinations before network", async () => {
  const pinned = createPinnedTlsFetch("1".repeat(64));
  await assert.rejects(
    () =>
      pinned("http://127.0.0.1:1/v1/chat/completions", {
        method: "POST",
        body: "marker",
      }),
    /HTTPS/,
  );
});
Deno.test("fresh caller nonce goes to both report requests without credentials", async () => {
  const urls = [], nonce = "a".repeat(64);
  const p = new NearProvider({
    ...config,
    fetcher: (url, init) => {
      const u = new URL(url);
      urls.push(u);
      assert.equal(u.searchParams.get("nonce"), nonce);
      assert.equal(u.searchParams.get("signing_algo"), "ecdsa");
      assert.equal(init.headers.authorization, undefined);
      return Response.json(
        u.searchParams.has("model")
          ? { model_attestations: [{ fixture: "model" }] }
          : { gateway_attestation: { fixture: "gateway" } },
      );
    },
    verifyAttestation: ({ report, nonce: n }) => {
      assert.equal(n, nonce);
      assert.equal(report.gateway_attestation.fixture, "gateway");
      return { evidence: { nonce }, transport: { fetch() {} } };
    },
  });
  const v = await p.attest({
    key: "sk-never-sent-fixture",
    model: "near/model",
    nonce,
  });
  assert.equal(v.evidence.nonce, nonce);
  assert.equal(urls[0].searchParams.get("include_tls_fingerprint"), "true");
  assert.equal(urls[1].searchParams.get("include_tls_fingerprint"), "false");
});
