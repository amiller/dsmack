import assert from "node:assert/strict";
import { test } from "node:test";
import { computeAddress, SigningKey, Wallet } from "npm:ethers@6.17.0";
import { prepareE2eeChatRequest } from "npm:@nearai/inference-sdk@0.2.0/node";
import { Inference } from "./inference.mjs";
import { Payments } from "./payments.mjs";
import { canonical } from "./grants.mjs";

const MODEL = "fixture/tee-model",
  ROOT = "sk-synthetic-root-provider-key",
  PROMPT = "prompt-marker-only-in-browser",
  ANSWER = "answer-marker-only-in-browser";
const modelKey = new SigningKey("0x" + "11".repeat(32)).publicKey.slice(4);
const cipherAnswer = "04" + "ab".repeat(100);
const code = (value) => (error) => {
  assert.equal(error.code, value);
  return true;
};
function fixture({ state, cfg = {} } = {}) {
  let now = 2000000000,
    saved,
    calls = 0,
    attests = 0,
    cost = "300",
    costsCalls = 0,
    closed = 0;
  const wallet = Wallet.createRandom(), records = [];
  const payments = new Payments({
    cfg: {},
    key: {},
    state,
    quorum: {},
    now: () => now,
    save: async (next) => {
      saved = structuredClone(next);
      records.push(saved);
    },
  });
  const provider = {
    apiKey: ROOT,
    async attest({ model, nonce }) {
      attests++;
      return {
        modelPublicKey: modelKey,
        evidence: {
          verification: "verified",
          mode: "broker-proxy",
          model,
          nonce,
          verifiedAt: now,
          expires_at: now + 60,
          models: [{
            model,
            signingAddress: computeAddress("0x04" + modelKey),
          }],
        },
        transport: {
          fetchEncrypted: fetch,
          close() {
            closed++;
          },
        },
      };
    },
    async chatEncrypted(r) {
      calls++;
      assert.equal(r.key, ROOT);
      assert.equal(r.model, MODEL);
      assert(!JSON.stringify(r.body).includes(PROMPT));
      assert(
        Object.values(payments.state.inferenceRequests).some((r) =>
          r.status === "sent"
        ),
        "reservation must persist before inference",
      );
      return new Response(
        "data: " +
          JSON.stringify({
            id: "chat-fixture",
            model: MODEL,
            choices: [{ delta: { content: cipherAnswer } }],
          }) + "\n\ndata: " +
          JSON.stringify({
            choices: [],
            usage: { prompt_tokens: 7, completion_tokens: 1, total_tokens: 8 },
          }) + "\n\ndata: [DONE]\n\n",
        {
          headers: {
            "content-type": "text/event-stream",
            "inference-id": "inference-" + calls,
          },
        },
      );
    },
    async costs({ key, requestIds }) {
      costsCalls++;
      assert.equal(key, ROOT);
      return { requests: [{ requestId: requestIds[0], costNanoUsd: cost }] };
    },
  };
  const inference = new Inference({
    payments,
    cfg: { model: MODEL, ...cfg },
    provider,
    now: () => now,
  });
  async function signed(action, extra = {}, signer = wallet) {
    const fields = {
      action,
      wallet: signer.address,
      nonce: crypto.randomUUID().replaceAll("-", ""),
      issuedAt: now,
      ...extra,
    };
    return { ...fields, sig: await signer.signMessage(canonical(fields)) };
  }
  async function credit(signer = wallet) {
    return await inference.credit(await signed("credit", {}, signer));
  }
  async function prepare(signer = wallet) {
    return await inference.prepare(
      await signed("prepare", { attestationNonce: "cd".repeat(32) }, signer),
    );
  }
  async function encrypted(session) {
    const prepared = await prepareE2eeChatRequest({
      request: new Request("https://cloud-api.near.ai/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: MODEL,
          messages: [{ role: "user", content: PROMPT }],
          max_tokens: 128,
          stream: true,
          stream_options: { include_usage: true },
        }),
      }),
      modelKey: { signingAlgo: "ecdsa", publicKey: session.modelPublicKey },
    });
    return {
      sessionId: session.sessionId,
      body: await prepared.request.json(),
      headers: Object.fromEntries(prepared.request.headers),
    };
  }
  async function send() {
    return await inference.chat(
      await signed("chat", await encrypted(await prepare())),
    );
  }
  return {
    inference,
    payments,
    provider,
    wallet,
    signed,
    credit,
    prepare,
    encrypted,
    send,
    records,
    saved: () => saved,
    calls: () => calls,
    attests: () => attests,
    costsCalls: () => costsCalls,
    closed: () => closed,
    advance: (seconds) => now += seconds,
    cost: (value) => cost = value,
  };
}

test("wallet ownership, expiry and replay protect one starter grant per wallet", async () => {
  const f = fixture(), claim = await f.signed("credit");
  const tampered = { ...claim, wallet: Wallet.createRandom().address };
  await assert.rejects(f.inference.credit(tampered), code("BUYER_SIGNATURE"));
  const granted = await f.inference.credit(claim);
  assert.equal(granted.grantedNanoUsd, "250000000");
  assert.equal(granted.remainingNanoUsd, "250000000");
  await assert.rejects(f.inference.credit(claim), code("REQUEST_REPLAY"));
  assert.equal((await f.credit()).grantedNanoUsd, "250000000");
  const second = Wallet.createRandom();
  assert.equal((await f.credit(second)).grantedNanoUsd, "250000000");
  const old = await f.signed("usage");
  f.advance(121);
  await assert.rejects(f.inference.usage(old), code("REQUEST_EXPIRED"));
  const restarted = new Inference({
    payments: new Payments({
      cfg: {},
      key: {},
      state: f.saved(),
      quorum: {},
      save: async () => {},
    }),
    cfg: { model: MODEL },
    provider: f.provider,
    now: () => 2000000000,
  });
  await assert.rejects(restarted.credit(claim), code("REQUEST_REPLAY"));
  assert.equal(
    (await restarted.credit(await f.signed("credit", { issuedAt: 2000000000 })))
      .grantedNanoUsd,
    "250000000",
  );
  assert.equal(f.calls(), 0);
});

test("fresh verified model sessions accept SDK ciphertext and reject plaintext or swapped keys", async () => {
  const f = fixture();
  await f.credit();
  const session = await f.prepare();
  assert.equal(session.attestation.mode, "broker-e2ee");
  assert.equal(session.modelPublicKey, modelKey);
  const encrypted = await f.encrypted(session);
  const plain = structuredClone(encrypted);
  plain.body.messages[0].content = PROMPT;
  await assert.rejects(
    f.inference.chat(await f.signed("chat", plain)),
    code("BAD_REQUEST"),
  );
  const badHeader = structuredClone(encrypted);
  badHeader.headers["x-model-pub-key"] = "11".repeat(64);
  await assert.rejects(
    f.inference.chat(await f.signed("chat", badHeader)),
    code("BAD_REQUEST"),
  );
  const extra = structuredClone(encrypted);
  extra.body.prompt = PROMPT;
  await assert.rejects(
    f.inference.chat(await f.signed("chat", extra)),
    code("BAD_REQUEST"),
  );
  const response = await f.inference.chat(await f.signed("chat", encrypted)),
    raw = await response.text();
  assert(raw.includes(cipherAnswer));
  assert(!raw.includes(ANSWER));
  assert(!raw.includes("event: attestation"));
  assert.equal(response.headers.get("inference-id"), "inference-1");
  assert.equal(f.calls(), 1);
  for (
    const marker of [
      ROOT,
      PROMPT,
      ANSWER,
      encrypted.body.messages[0].content,
      cipherAnswer,
    ]
  ) {
    assert(
      !JSON.stringify(f.records).includes(marker),
      "durable state must contain accounting only",
    );
  }
});

test("budget reservation excludes concurrent requests and provider cost charges exactly once", async () => {
  const f = fixture();
  await f.credit();
  const session = await f.prepare(), encrypted = await f.encrypted(session);
  const responses = await Promise.allSettled([
    f.inference.chat(await f.signed("chat", encrypted)),
    f.inference.chat(await f.signed("chat", encrypted)),
  ]);
  assert.equal(responses.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(
    responses.find((r) => r.status === "rejected").reason.code,
    "REQUEST_IN_FLIGHT",
  );
  await responses.find((r) => r.status === "fulfilled").value.text();
  f.cost("0");
  await assert.rejects(
    f.inference.usage(await f.signed("usage")),
    code("USAGE_PENDING"),
  );
  await assert.rejects(f.prepare(), code("REQUEST_IN_FLIGHT"));
  const before = f.inference.summary(f.wallet.address.toLowerCase());
  assert(BigInt(before.reservedNanoUsd) > 0n);
  f.cost("300");
  const usages = await Promise.all([
    f.inference.usage(await f.signed("usage")),
    f.inference.usage(await f.signed("usage")),
  ]);
  for (const u of usages) {
    assert.equal(u.spentNanoUsd, "300");
    assert.equal(u.usedTokens, "8");
    assert.equal(u.remainingNanoUsd, "249999700");
  }
  assert.equal(
    (await f.inference.usage(await f.signed("usage"))).spentNanoUsd,
    "300",
  );
  assert.equal((await f.inference.recover()).pendingRequests, 0);
});

test("insufficient credit and untrusted provider costs cannot start or overdraw requests", async () => {
  const f = fixture({ cfg: { starterCreditNanoUsd: "100" } });
  await f.credit();
  const session = await f.prepare();
  await assert.rejects(
    f.inference.chat(await f.signed("chat", await f.encrypted(session))),
    code("CREDIT_EXHAUSTED"),
  );
  assert.equal(f.calls(), 0);
  const g = fixture();
  await g.credit();
  await (await g.send()).text();
  g.cost("999999999");
  await assert.rejects(
    g.inference.usage(await g.signed("usage")),
    code("USAGE_MISMATCH"),
  );
  assert.equal(
    g.inference.summary(g.wallet.address.toLowerCase()).spentNanoUsd,
    "0",
  );
  g.provider.costs = async () => ({
    requests: [{ requestId: "foreign", costNanoUsd: "300" }],
  });
  await assert.rejects(
    g.inference.usage(await g.signed("usage")),
    code("USAGE_MISMATCH"),
  );
});

test("unknown dispatched requests remain reserved across restart and are never resent", async () => {
  const f = fixture();
  await f.credit();
  f.provider.chatEncrypted = async () => {
    throw Error("connection lost");
  };
  await assert.rejects(f.send(), /connection lost/);
  const saved = f.saved(),
    payment = new Payments({
      cfg: {},
      key: {},
      state: saved,
      quorum: {},
      save: async () => {},
    });
  const restarted = new Inference({
    payments: payment,
    cfg: { model: MODEL },
    provider: f.provider,
    now: () => 2000000000,
  });
  assert.equal((await restarted.recover()).pendingRequests, 1);
  await assert.rejects(
    restarted.usage(await f.signed("usage")),
    code("USAGE_PENDING"),
  );
  await assert.rejects(
    restarted.prepare(
      await f.signed("prepare", { attestationNonce: "ef".repeat(32) }),
    ),
    code("REQUEST_IN_FLIGHT"),
  );
  assert(
    BigInt(restarted.summary(f.wallet.address.toLowerCase()).reservedNanoUsd) >
      0n,
  );
});

test("browser disconnect still drains the encrypted provider stream for billing evidence", async () => {
  const f = fixture();
  await f.credit();
  let finishSource, responded;
  const gate = new Promise((resolve) => finishSource = resolve),
    stored = new Promise((resolve) => responded = resolve);
  const save = f.payments.save;
  f.payments.save = async (next) => {
    await save(next);
    if (
      Object.values(next.inferenceRequests ?? {}).some((r) =>
        r.status === "responded"
      )
    ) responded();
  };
  f.provider.chatEncrypted = async () =>
    new Response(
      new ReadableStream({
        async start(controller) {
          controller.enqueue(
            new TextEncoder().encode('data: {"choices":[]}\n\n'),
          );
          await gate;
          controller.enqueue(
            new TextEncoder().encode(
              'data: {"usage":{"total_tokens":12}}\n\ndata: [DONE]\n\n',
            ),
          );
          controller.close();
        },
      }),
      {
        headers: {
          "content-type": "text/event-stream",
          "inference-id": "inference-disconnected",
        },
      },
    );
  const response = await f.send();
  await response.body.cancel();
  finishSource();
  await stored;
  const result = await f.inference.usage(await f.signed("usage"));
  assert.equal(result.spentNanoUsd, "300");
  assert.equal(result.usedTokens, "12");
});

test("provider billing IDs cannot charge a different wallet and missing token evidence stays pending", async () => {
  const f = fixture();
  await f.credit();
  await (await f.send()).text();
  await f.inference.usage(await f.signed("usage"));
  const other = Wallet.createRandom();
  await f.credit(other);
  const session = await f.prepare(other);
  f.provider.chatEncrypted = async () =>
    new Response("data: [DONE]\n\n", {
      headers: {
        "content-type": "text/event-stream",
        "inference-id": "inference-1",
      },
    });
  await assert.rejects(
    f.inference.chat(await f.signed("chat", await f.encrypted(session), other)),
    code("USAGE_MISMATCH"),
  );
  assert.equal(
    f.inference.summary(other.address.toLowerCase()).spentNanoUsd,
    "0",
  );
  const g = fixture();
  await g.credit();
  g.provider.chatEncrypted = async () =>
    new Response("data: [DONE]\n\n", {
      headers: {
        "content-type": "text/event-stream",
        "inference-id": "inference-no-tokens",
      },
    });
  await (await g.send()).text();
  await assert.rejects(
    g.inference.usage(await g.signed("usage")),
    code("USAGE_PENDING"),
  );
  assert.equal(g.costsCalls(), 0);
  assert.equal(
    g.inference.summary(g.wallet.address.toLowerCase()).spentNanoUsd,
    "0",
  );
});

test("prepared sessions are wallet-bound and expire before any paid call", async () => {
  const f = fixture();
  await f.credit();
  const session = await f.prepare(), other = Wallet.createRandom();
  await f.credit(other);
  await assert.rejects(
    f.inference.chat(await f.signed("chat", await f.encrypted(session), other)),
    code("ATTESTATION_INVALID"),
  );
  f.advance(60);
  await assert.rejects(
    f.inference.chat(await f.signed("chat", await f.encrypted(session))),
    code("ATTESTATION_INVALID"),
  );
  assert.equal(f.calls(), 0);
});

test("startup tops up every old account once while preserving spend and pending requests", async () => {
  const wallet = Wallet.createRandom(), inactive = Wallet.createRandom();
  const activeKey = wallet.address.toLowerCase(),
    inactiveKey = inactive.address.toLowerCase();
  const account = {
    grantedNanoUsd: "10000000",
    spentNanoUsd: "9000000",
    usedTokens: "1234",
    pending: "pending-request",
    nonces: { ["ab".repeat(16)]: 2000000000 },
  };
  const pending = {
    wallet: activeKey,
    status: "sent",
    reservedNanoUsd: "500000",
    inferenceId: null,
    createdAt: 1999999999,
  };
  const history = { status: "charged", costNanoUsd: "9000000" };
  const f = fixture({
    state: {
      grants: { existing: { retained: true } },
      receipts: {},
      inferenceCredit: {
        [activeKey]: account,
        [inactiveKey]: { ...account, pending: null },
        alreadyAbove: { ...account, grantedNanoUsd: "300000000" },
      },
      inferenceRequests: { "pending-request": pending, old: history },
    },
  });
  let finishSave, saving;
  const gate = new Promise((resolve) => finishSave = resolve),
    started = new Promise((resolve) => saving = resolve);
  const save = f.payments.save;
  f.payments.save = async (next) => {
    saving();
    await gate;
    await save(next);
  };
  const recovery = f.inference.recover();
  await started;
  assert.equal(
    f.payments.state.inferenceCredit[activeKey].grantedNanoUsd,
    "10000000",
  );
  const claim = f.inference.credit(await f.signed("credit", {}, wallet));
  finishSave();
  assert.equal((await recovery).pendingRequests, 1);
  assert.equal((await claim).remainingNanoUsd, "240500000");
  for (const key of [activeKey, inactiveKey]) {
    const migrated = f.saved().inferenceCredit[key];
    assert.equal(migrated.grantedNanoUsd, "250000000");
    assert.equal(migrated.spentNanoUsd, account.spentNanoUsd);
    assert.equal(migrated.usedTokens, account.usedTokens);
    assert.equal(migrated.pending, key === activeKey ? account.pending : null);
    assert.equal(migrated.nonces["ab".repeat(16)], 2000000000);
    assert.deepEqual(migrated.starterTopUps, [{
      amountNanoUsd: "240000000",
      grantedNanoUsd: "250000000",
      grantedAt: 2000000000,
    }]);
  }
  assert.deepEqual(f.saved().inferenceRequests, {
    "pending-request": pending,
    old: history,
  });
  assert.deepEqual(f.saved().grants, { existing: { retained: true } });
  assert.equal(
    f.saved().inferenceCredit.alreadyAbove.grantedNanoUsd,
    "300000000",
  );
  assert.equal(f.saved().inferenceCredit.alreadyAbove.starterTopUps, undefined);
  const restarted = fixture({ state: f.saved() });
  await restarted.inference.recover();
  assert.equal(restarted.records.length, 0);
  const repeated = await restarted.inference.credit(
    await restarted.signed("credit", {}, wallet),
  );
  assert.equal(repeated.grantedNanoUsd, "250000000");
  assert.equal(
    restarted.saved().inferenceCredit[activeKey].starterTopUps.length,
    1,
  );
  await restarted.inference.recover();
  assert.equal(restarted.records.length, 1);
});

test("failed startup top-up persistence leaves the original grant available for retry", async () => {
  const original = {
    grantedNanoUsd: "10000000",
    spentNanoUsd: "100",
    usedTokens: "3",
    pending: null,
    nonces: {},
  };
  const f = fixture({
    state: { inferenceCredit: { wallet: original } },
    cfg: { starterCreditNanoUsd: "500000000" },
  });
  const save = f.payments.save;
  f.payments.save = async () => {
    throw new Error("disk write failed");
  };
  await assert.rejects(f.inference.recover(), /disk write failed/);
  assert.deepEqual(f.payments.state.inferenceCredit.wallet, original);
  f.payments.save = save;
  await f.inference.recover();
  assert.equal(f.saved().inferenceCredit.wallet.grantedNanoUsd, "500000000");
  assert.equal(f.saved().inferenceCredit.wallet.starterTopUps.length, 1);
  assert.equal(
    f.saved().inferenceCredit.wallet.starterTopUps[0].amountNanoUsd,
    "490000000",
  );
});
