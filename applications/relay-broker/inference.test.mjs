import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { Inference } from "./inference.mjs";
import { Payments } from "./payments.mjs";
import { NearError } from "./near.mjs";
import { grantBytes } from "./grants.mjs";
import {
  nodeBindingSigner,
  receiptSigner,
  Wallet,
} from "../payments/schema.mjs";

const NOW = Math.floor(Date.now() / 1000);
const NODE = "0x" + "11".repeat(32),
  COMPOSE = "0x" + "22".repeat(32),
  IMAGE = "0x" + "33".repeat(32);
const TX = "0x" + "44".repeat(32),
  ESCROW = "0x1000000000000000000000000000000000000001";
const SECRET = "sk-synthetic-delegated-key-marker",
  PROMPT = "private-prompt-marker-75381",
  ANSWER = "private-answer-marker-75381";
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function peer(pub) {
  const bytes = Buffer.concat([Buffer.from("002408011220", "hex"), pub]);
  let n = BigInt("0x" + bytes.toString("hex")), result = "";
  while (n) {
    result = alphabet[Number(n % 58n)] + result;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b) break;
    result = "1" + result;
  }
  return result;
}

function fixture({ amount = "100", unit = 2, state, key, pair } = {}) {
  key ??= Wallet.createRandom();
  pair ??= generateKeyPairSync("ed25519");
  const pub = pair.publicKey.export({ format: "der", type: "spki" }).subarray(
    -32,
  );
  const client_peer = peer(pub);
  let clock = NOW, saved, mintCalls = 0, calls = 0, revoked = 0;
  const p = {
    node: NODE,
    buyerKey: "0x" + pub.toString("hex"),
    payer: key.address,
    operator: key.address,
    unit,
    amount,
    price: "11",
    floorPrice: "7",
    boughtAt: NOW - 10,
    expires: NOW + 3600,
    sequence: 0,
    used: "0",
    closed: false,
  };
  const node = {
    operator: key.address,
    unit: 2,
    floorPrice: 7n,
    price: 11n,
    composeHash: COMPOSE,
    imageHash: IMAGE,
  };
  const snapshot = {
    block: { hash: "0x" + "55".repeat(32) },
    call(method) {
      if (method === "getNode") return node;
      if (method === "quote") return 11n;
      if (method === "brokerSigner") return key.address;
      if (method === "getPurchase") return p;
      throw Error("unexpected chain call: " + method);
    },
  };
  const quorum = { snapshot: async () => snapshot, purchase: async () => p };
  const payments = new Payments({
    cfg: { escrow: ESCROW, codeHash: "0x" + "66".repeat(32), classes: [NODE] },
    key,
    quorum,
    state,
    now: () => clock,
    save: async (value) => {
      saved = structuredClone(value);
    },
  });
  const rows = [];
  const provider = {
    async mint({ capNanoUsd, expiresAt }) {
      mintCalls++;
      return {
        id: "key-fixture",
        key: SECRET,
        expires_at: expiresAt,
        spend_limit: { amount: Number(capNanoUsd), scale: 9, currency: "USD" },
      };
    },
    async attest({ model, nonce }) {
      return {
        evidence: {
          model,
          nonce,
          verified: true,
          expires_at: clock + 60,
          signing_algorithm: "ecdsa",
          gateway: {
            signing_address: key.address,
            tls_fingerprint: "ab".repeat(32),
            tcb_status: "UpToDate",
          },
          models: [{
            model_name: model,
            signing_address: key.address,
            tcb_status: "UpToDate",
          }],
          report: { synthetic: true },
        },
        transport: { fetch },
      };
    },
    async chat({ key: delegated, model, messages }) {
      assert.equal(delegated, SECRET);
      assert.equal(messages[0].content, PROMPT);
      calls++;
      const inferenceId = "inference-" + calls;
      rows.push({
        id: "row-" + calls,
        source: "inference",
        api_key_id: "key-fixture",
        workspace_id: "workspace-fixture",
        created_at: new Date(clock * 1000).toISOString(),
        total_cost_nano_usd: 300,
        inference: {
          model,
          inference_id: inferenceId,
          input_tokens: 20,
          output_tokens: 10,
          total_tokens: 30,
        },
      });
      return new Response(
        "data: " +
          JSON.stringify({
            id: "chat-" + calls,
            choices: [{ delta: { content: ANSWER } }],
          }) + "\n\ndata: [DONE]\n\n",
        {
          headers: {
            "content-type": "text/event-stream",
            "inference-id": inferenceId,
          },
        },
      );
    },
    async usage() {
      return {
        rows: structuredClone(rows),
        inputTokens: rows.reduce(
          (n, r) => n + BigInt(r.inference.input_tokens),
          0n,
        ).toString(),
        outputTokens: rows.reduce(
          (n, r) => n + BigInt(r.inference.output_tokens),
          0n,
        ).toString(),
        totalTokens: rows.reduce(
          (n, r) => n + BigInt(r.inference.total_tokens),
          0n,
        ).toString(),
        costNanoUsd: rows.reduce(
          (n, r) => n + BigInt(r.total_cost_nano_usd),
          0n,
        ).toString(),
      };
    },
    async revoke() {
      revoked++;
    },
  };
  const cfg = {
    node: NODE,
    model: "fixture/tee-model",
    requestTokenCeiling: 40,
    maxNanoUsdPerToken: "10",
    gatewayComposeHashes: [COMPOSE],
    modelComposeHashes: [COMPOSE],
    origins: ["http://localhost:8765"],
    composeHash: COMPOSE,
    imageHash: IMAGE,
  };
  const make = (pmt = payments) =>
    new Inference({ payments: pmt, cfg, provider, now: () => clock });
  const inference = make();
  function request(action, extra = {}) {
    const fields = {
      action,
      purchaseId: "1",
      txHash: TX,
      client_peer,
      nonce: randomBytes(16).toString("hex"),
      issuedAt: clock,
      ...extra,
    };
    return {
      ...fields,
      sig: sign(null, grantBytes(fields), pair.privateKey).toString("hex"),
    };
  }
  async function confirm() {
    const fields = { purchaseId: "1", txHash: TX, client_peer };
    return await payments.confirm({
      ...fields,
      sig: sign(null, grantBytes(fields), pair.privateKey).toString("hex"),
    });
  }
  return {
    inference,
    payments,
    provider,
    rows,
    cfg,
    key,
    pair,
    p,
    node,
    quorum,
    request,
    confirm,
    make,
    now: () => clock,
    advance: (n) => clock += n,
    saved: () => saved,
    mintCalls: () => mintCalls,
    calls: () => calls,
    revoked: () => revoked,
  };
}
const refusal = (code) => (e) => {
  assert.equal(e.code, code);
  return true;
};
const chatRequest = (f) =>
  f.request("chat", {
    messages: [{ role: "user", content: PROMPT }],
    max_tokens: 10,
  });

// A funded but unfinalized purchase must not mint a provider credential.
test("inference only allocates confirmed token purchases and verifies buyer messages", async () => {
  const f = fixture();
  await assert.rejects(
    f.inference.mint(f.request("mint")),
    refusal("CREDIT_NOT_CONFIRMED"),
  );
  assert.equal(f.mintCalls(), 0);
  await f.confirm();
  const tampered = f.request("mint");
  tampered.purchaseId = "2";
  await assert.rejects(f.inference.mint(tampered), refusal("BUYER_SIGNATURE"));
  const expired = f.request("mint", { issuedAt: NOW - 121 });
  await assert.rejects(f.inference.mint(expired), refusal("REQUEST_EXPIRED"));
  const signed = f.request("mint");
  const allocation = await f.inference.mint(signed);
  assert.equal(allocation.amountTokens, "100");
  assert.equal(allocation.capNanoUsd, "1000");
  await assert.rejects(f.inference.mint(signed), refusal("REQUEST_REPLAY"));
  assert.equal(f.mintCalls(), 1);
  assert(
    !JSON.stringify(f.saved()).includes(SECRET),
    "delegated key must be encrypted in durable state",
  );
  const wrong = fixture({ unit: 1 });
  await wrong.confirm();
  await assert.rejects(
    wrong.inference.mint(wrong.request("mint")),
    refusal("WRONG_UNIT"),
  );
});

// A second simultaneous request must never use the same reservation.
test("chat reserves confirmed credit until provider accounting reconciles it", async () => {
  const f = fixture({ amount: "70" });
  await f.confirm();
  await f.inference.mint(f.request("mint"));
  f.advance(10);
  const results = await Promise.allSettled([
    f.inference.chat(chatRequest(f)),
    f.inference.chat(chatRequest(f)),
  ]);
  const accepted = results.filter((r) => r.status === "fulfilled"),
    denied = results.filter((r) => r.status === "rejected");
  assert.equal(accepted.length, 1);
  assert.equal(denied.length, 1);
  assert.equal(denied[0].reason.code, "REQUEST_IN_FLIGHT");
  const text = await accepted[0].value.text();
  assert(text.includes(ANSWER));
  assert(text.includes("event: attestation"));
  const usage = await f.inference.usage(f.request("usage"));
  assert.equal(usage.usage.totalTokens, "30");
  assert.equal(usage.usedTokens, "30");
  const second = await f.inference.chat(chatRequest(f));
  await second.text();
  await f.inference.usage(f.request("usage"));
  await assert.rejects(
    f.inference.chat(chatRequest(f)),
    refusal("CREDIT_EXHAUSTED"),
  );
  assert.equal(f.calls(), 2);
  for (const marker of [SECRET, PROMPT, ANSWER]) {
    assert(
      !JSON.stringify(f.saved()).includes(marker),
      "persisted state leaked " + marker,
    );
  }
});

// Receipts must reconcile wei without trusting browser-reported token counts.
test("provider usage signs cumulative settlement and final unused-credit refund", async () => {
  const f = fixture();
  await f.confirm();
  await f.inference.mint(f.request("mint"));
  f.advance(10);
  await (await f.inference.chat(chatRequest(f))).text();
  const charge = await f.inference.charges(f.request("charges"));
  assert.equal(charge.receipt.used, "30");
  assert.equal(charge.receipt.finalReceipt, false);
  assert.equal(
    receiptSigner(ESCROW, charge).toLowerCase(),
    f.key.address.toLowerCase(),
  );
  assert.equal(
    nodeBindingSigner(ESCROW, charge.nodeBinding).toLowerCase(),
    f.key.address.toLowerCase(),
  );
  assert.equal(charge.chargeWei, "330");
  assert.equal(charge.operatorWei, "210");
  assert.equal(charge.premiumWei, "120");
  assert.equal(charge.refundableWei, "770");
  const again = await f.inference.charges(f.request("charges"));
  assert.deepEqual(again, charge);
  const final = await f.inference.close(f.request("close"));
  assert.equal(final.receipt.finalReceipt, true);
  assert.equal(final.receipt.used, "30");
  assert(final.receipt.sequence > charge.receipt.sequence);
  assert.equal(f.revoked(), 1);
  assert.equal(BigInt(final.chargeWei) + BigInt(final.refundableWei), 1100n);
  await assert.rejects(
    f.inference.chat(chatRequest(f)),
    refusal("ALLOCATION_CLOSED"),
  );
});

// Provider accounting lag must retain reservation and prevent a free refund.
test("missing provider accounting blocks final settlement and overspend cannot debit credit", async () => {
  const f = fixture();
  await f.confirm();
  await f.inference.mint(f.request("mint"));
  f.advance(10);
  await (await f.inference.chat(chatRequest(f))).text();
  const row = f.rows.pop();
  await assert.rejects(
    f.inference.charges(f.request("charges")),
    refusal("USAGE_PENDING"),
  );
  assert(
    f.saved().inference["1"].pending,
    "unreconciled reservation must remain durable",
  );
  f.rows.push({
    ...row,
    total_cost_nano_usd: 1001,
    inference: { ...row.inference, total_tokens: 101 },
  });
  await assert.rejects(
    f.inference.charges(f.request("charges")),
    refusal("USAGE_MISMATCH"),
  );
});

// Restart must preserve both allocation custody and replay protection.
test("restart resumes encrypted allocation and rejects previously used requests", async () => {
  const f = fixture();
  await f.confirm();
  const old = f.request("mint");
  await f.inference.mint(old);
  const restarted = fixture({ state: f.saved(), key: f.key, pair: f.pair });
  restarted.advance(10);
  const summary = await restarted.inference.mint(restarted.request("mint"));
  assert.equal(summary.keyId, "key-fixture");
  assert.equal(restarted.mintCalls(), 0);
  await assert.rejects(
    restarted.inference.mint(old),
    refusal("REQUEST_REPLAY"),
  );
  await (await restarted.inference.chat(chatRequest(restarted))).text();
  assert.equal(restarted.calls(), 1);
});

// A crash before dispatch releases its reservation; unknown dispatch stays reserved.
test("restart only clears reservations whose prompt was never dispatched", async () => {
  const f = fixture();
  await f.confirm();
  await f.inference.mint(f.request("mint"));
  for (const stage of ["attesting", "sent"]) {
    const state = structuredClone(f.saved());
    state.inference["1"].pending = { stage, nonce: "ab".repeat(16) };
    const resumed = fixture({ state, key: f.key, pair: f.pair });
    await resumed.inference.recover();
    assert.equal(
      Boolean(resumed.payments.state.inference["1"].pending),
      stage === "sent",
    );
    if (stage === "sent") {
      await assert.rejects(
        resumed.inference.chat(chatRequest(resumed)),
        refusal("REQUEST_IN_FLIGHT"),
      );
    }
  }
});

// Lost mint responses must not silently create another independently usable key.
test("ambiguous provider mint is persisted and never blindly retried", async () => {
  const f = fixture();
  await f.confirm();
  let attempts = 0;
  f.provider.mint = async () => {
    attempts++;
    throw new NearError("PROVIDER_UNAVAILABLE");
  };
  await assert.rejects(f.inference.mint(f.request("mint")));
  await assert.rejects(
    f.inference.mint(f.request("mint")),
    refusal("MINT_AMBIGUOUS"),
  );
  assert.equal(attempts, 1);
});

// Closing while evidence is being checked cannot strand a reservation with no billing ID.
test("close during attestation preserves a recoverable allocation", async () => {
  const f = fixture();
  await f.confirm();
  await f.inference.mint(f.request("mint"));
  f.advance(10);
  let entered, release;
  const enteredPromise = new Promise((resolve) => entered = resolve),
    gate = new Promise((resolve) => release = resolve);
  const attest = f.provider.attest;
  f.provider.attest = async (r) => {
    entered();
    await gate;
    return await attest(r);
  };
  const pending = f.inference.chat(chatRequest(f));
  await enteredPromise;
  await assert.rejects(
    f.inference.close(f.request("close")),
    refusal("REQUEST_IN_FLIGHT"),
  );
  assert.equal(f.saved().inference["1"].status, "active");
  assert.equal(f.revoked(), 0);
  release();
  await (await pending).text();
  await f.inference.usage(f.request("usage"));
  const closed = await f.inference.close(f.request("close"));
  assert.equal(closed.receipt.finalReceipt, true);
});

// Run the exported broker handler over loopback HTTP, including browser CORS and SSE.
test("local HTTP broker confirms credit, streams, reconciles charges and refuses invalid requests", async () => {
  const { handleRequest } = await import("./server.ts");
  const f = fixture();
  const b = {
    cfg: { inference: f.cfg },
    inference: f.inference,
    payments: f.payments,
    live: () => [],
    key: { public_key: "ab".repeat(32) },
  };
  const shutdown = new AbortController();
  const server = Deno.serve({
    hostname: "127.0.0.1",
    port: 0,
    signal: shutdown.signal,
    onListen() {},
  }, (req) => handleRequest(req, b));
  const base = `http://127.0.0.1:${server.addr.port}`,
    origin = "http://localhost:8765";
  const post = (path, value) =>
    fetch(base + path, {
      method: "POST",
      headers: { origin, "content-type": "application/json" },
      body: JSON.stringify(value),
    });
  try {
    const page = await fetch(base + "/");
    assert.equal(page.status, 200);
    assert((await page.text()).includes("Attested egress relay"));
    const preflight = await fetch(base + "/inference/chat", {
      method: "OPTIONS",
      headers: {
        origin,
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), origin);
    assert.equal(preflight.headers.get("cache-control"), "no-store");
    await preflight.text();
    const quote = await fetch(base + "/inference/quote", {
      headers: { origin },
    });
    assert.equal(quote.status, 200);
    const quoted = await quote.json();
    assert.equal(quoted.unitId, 2);
    assert.equal(quoted.chainId, 84532);
    assert.equal(quoted.priceWei, "11");
    const unpaid = await post("/inference/mint", f.request("mint"));
    assert.equal(unpaid.status, 402);
    assert.equal((await unpaid.json()).error.code, "CREDIT_NOT_CONFIRMED");
    const fields = {
      client_peer: f.request("mint").client_peer,
      purchaseId: "1",
      txHash: TX,
    };
    const confirmed = await post("/payments/confirm", {
      ...fields,
      sig: sign(null, grantBytes(fields), f.pair.privateKey).toString("hex"),
    });
    assert.equal(confirmed.status, 200);
    assert.equal((await confirmed.json()).purchaseId, "1");
    const mintedRequest = f.request("mint"),
      minted = await post("/inference/mint", mintedRequest);
    assert.equal(minted.status, 200);
    const allocation = await minted.json();
    assert.equal(allocation.amountTokens, "100");
    assert(!JSON.stringify(allocation).includes(SECRET));
    const replay = await post("/inference/mint", mintedRequest);
    assert.equal(replay.status, 409);
    assert.equal((await replay.json()).error.code, "REQUEST_REPLAY");
    f.advance(10);
    const signedChat = chatRequest(f);
    const response = await post("/inference/chat", signedChat);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "text/event-stream");
    assert.equal(response.headers.get("cache-control"), "no-store");
    const stream = await response.text();
    assert(stream.includes("event: attestation"));
    const evidenceLine = stream.split("\n").find((line) =>
      line.startsWith("data: {")
    );
    const shownEvidence = JSON.parse(evidenceLine.slice(6));
    const expectedNonce = Buffer.from(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(
          "dsmack-near-attestation/1:" + signedChat.purchaseId + ":" +
            signedChat.txHash + ":" + signedChat.nonce,
        ),
      ),
    ).toString("hex");
    assert.equal(shownEvidence.nonce, expectedNonce);
    assert(stream.includes(ANSWER));
    assert(stream.includes("[DONE]"));
    const usageResponse = await post("/inference/usage", f.request("usage"));
    assert.equal(usageResponse.status, 200);
    assert.equal((await usageResponse.json()).usage.totalTokens, "30");
    const finalResponse = await post("/inference/close", f.request("close"));
    assert.equal(finalResponse.status, 200);
    const final = await finalResponse.json();
    assert.equal(final.receipt.finalReceipt, true);
    assert.equal(final.refundableWei, "770");
    const untrusted = await fetch(base + "/inference/quote", {
      headers: { origin: "https://foreign.invalid" },
    });
    assert.equal(untrusted.status, 403);
    assert.equal((await untrusted.json()).error.code, "ORIGIN_REFUSED");
    assert.equal(untrusted.headers.get("access-control-allow-origin"), null);
    const badJson = await fetch(base + "/inference/chat", {
      method: "POST",
      headers: { origin, "content-type": "application/json" },
      body: "[]",
    });
    assert.equal(badJson.status, 400);
    assert.equal((await badJson.json()).error.code, "BAD_REQUEST");
    const oversized = await fetch(base + "/inference/chat", {
      method: "POST",
      headers: { origin, "content-type": "application/json" },
      body: " ".repeat(150001),
    });
    assert.equal(oversized.status, 413);
    assert.equal((await oversized.json()).error.code, "BAD_REQUEST");
    const serialized = JSON.stringify(f.saved());
    for (const marker of [SECRET, PROMPT, ANSWER]) {
      assert(!serialized.includes(marker));
    }
    console.log(
      JSON.stringify({
        transport: "local HTTP",
        chainId: quoted.chainId,
        unit: quoted.unit,
        usedTokens: final.receipt.used,
        chargeWei: final.chargeWei,
        operatorWei: final.operatorWei,
        premiumWei: final.premiumWei,
        refundableWei: final.refundableWei,
        stateMarkersFound: 0,
      }),
    );
  } finally {
    shutdown.abort();
    await server.finished;
  }
});
