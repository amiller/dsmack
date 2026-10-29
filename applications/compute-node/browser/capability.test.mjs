import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonical,
  createClient,
  hex,
  INFERENCE_PRIVACY,
  requestCapability,
  verifyTurnOutputs,
} from "./sandbox.mjs";

// Cryptographic broker responses here are fixtures; no provider call is mocked as real TEE verification.
test("capability mint authenticates the buyer and refuses an unverified grant before HTTP", async () => {
  const broker = await crypto.subtle.generateKey("Ed25519", false, [
    "sign",
    "verify",
  ]);
  const key = hex(
      new Uint8Array(await crypto.subtle.exportKey("raw", broker.publicKey)),
    ),
    client = await createClient();
  const peer = "12D3KooWPdcePFHp8pmoxdwpNC2ADNivvsCFYH8KPSfqutt7GWzA",
    jobId = "01".repeat(16);
  const body = {
    client_peer: client.peer,
    expires_at: Math.floor(Date.now() / 1000) + 60,
    grant_id: "02".repeat(16),
    relay_peer: peer,
    seconds: 60,
    unit: "seconds",
    v: 1,
  };
  const grant = {
    ...body,
    sig: hex(
      new Uint8Array(
        await crypto.subtle.sign("Ed25519", broker.privateKey, canonical(body)),
      ),
    ),
  };
  const node = {
    policy: { brokerKey: key },
    registration: { relay_peer: peer },
  };
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (url, options) => {
    calls++;
    assert.equal(url, "https://broker.test/sandbox/capability");
    const { sig, ...request } = JSON.parse(options.body);
    assert.equal(request.client_peer, client.peer);
    assert.equal(request.job_id, jobId);
    assert.deepEqual(request.grant, grant);
    const buyer = await crypto.subtle.importKey(
      "raw",
      (await import("./sandbox.mjs")).peerBytes(client.peer).slice(6),
      "Ed25519",
      false,
      ["verify"],
    );
    assert(
      await crypto.subtle.verify(
        "Ed25519",
        buyer,
        Uint8Array.from(sig.match(/../g), (v) => parseInt(v, 16)),
        canonical(request),
      ),
    );
    return new Response(
      JSON.stringify({
        schema: "dsmack-broker-inference/1",
        job_id: jobId,
        token: "fixture-capability",
      }),
    );
  };
  try {
    const credential = await requestCapability("https://broker.test", {
      node,
      client,
      grant,
      jobId,
    });
    assert.equal(credential.job_id, jobId);
    assert.equal(calls, 1);
    await assert.rejects(
      requestCapability("https://broker.test", {
        node,
        client,
        grant: { ...grant, sig: "00".repeat(64) },
        jobId,
      }),
      /signature/,
    );
    assert.equal(calls, 1, "forged grant reached capability endpoint");
  } finally {
    globalThis.fetch = original;
  }
});

test("signed model response evidence refuses a substituted assistant message or foreign job", async () => {
  const broker = await crypto.subtle.generateKey("Ed25519", false, [
    "sign",
    "verify",
  ]);
  const key = hex(
      new Uint8Array(await crypto.subtle.exportKey("raw", broker.publicKey)),
    ),
    model = "fixture/near-model",
    job = { jobId: "03".repeat(16), sealedAt: Date.now() };
  const nonce = "04".repeat(32),
    requestHash = "05".repeat(32),
    message = { role: "assistant", content: "Done." },
    usage = { total_tokens: 10 };
  const evidence = {
    mode: "broker-proxy",
    provider: "near",
    model,
    nonce,
    verifiedAt: Math.floor(Date.now() / 1000),
    verification: "verified",
    verifier: "fixture",
    privacy: INFERENCE_PRIVACY,
    gateway: {
      signingAddress: "fixture-address",
      tlsFingerprint: "fixture-fingerprint",
    },
    models: [{ model, signingAddress: "fixture-address" }],
    tls: { checkedBy: "broker", browserObservable: false, binding: "spki" },
  };
  const payload = {
    schema: "dsmack-broker-inference-response/1",
    job_id: job.jobId,
    nonce,
    request_sha256: requestHash,
    model,
    attestation: evidence,
    result: { model, choices: [{ message }], usage },
  };
  const proof = {
    type: "provider_attestation",
    payload,
    signature: hex(
      new Uint8Array(
        await crypto.subtle.sign(
          "Ed25519",
          broker.privateKey,
          canonical(payload),
        ),
      ),
    ),
  };
  const assistant = {
    type: "assistant",
    model,
    message,
    usage,
    nonce,
    request_sha256: requestHash,
  };
  const verdict = {
    answer: null,
    summary: "Done.",
    num_turns: 1,
    observed_models: [model],
    provider: "broker-near",
    privacy: INFERENCE_PRIVACY,
  };
  const outputs = { transcript: canonical(proof), verdict: canonical(verdict) };
  outputs.transcript = new TextEncoder().encode(
    JSON.stringify(proof) + "\n" + JSON.stringify(assistant) + "\n",
  );
  const node = {
    policy: {
      brokerKey: key,
      provider: { schema: "dsmack-broker-model/1", model },
    },
  };
  assert.deepEqual(await verifyTurnOutputs(node, outputs, job), verdict);
  await assert.rejects(
    verifyTurnOutputs(node, {
      ...outputs,
      transcript: new TextEncoder().encode(
        JSON.stringify(proof) + "\n" +
          JSON.stringify({
            ...assistant,
            message: { role: "assistant", content: "Substituted" },
          }) + "\n",
      ),
    }, job),
    /differs from signed/,
  );
  await assert.rejects(
    verifyTurnOutputs(node, outputs, { ...job, jobId: "06".repeat(16) }),
    /job\/model\/nonce/,
  );
});
