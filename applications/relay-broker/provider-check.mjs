import { InferenceError } from "./inference.mjs";

const encoder = new TextEncoder();
const fail = (code, message, status) => {
  throw new InferenceError(code, message, status);
};
const require = (ok, code, message, status = 502) => {
  if (!ok) fail(code, message, status);
};
const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const safeInteger = (n) => Number.isSafeInteger(n) && n >= 0;

async function nonceBody(request) {
  require(
    request.method === "POST" && request.body,
    "BAD_REQUEST",
    "POST a nonce object",
    400,
  );
  let size = 0, text = "";
  const decoder = new TextDecoder("utf-8", { fatal: true });
  try {
    for await (const chunk of request.body) {
      size += chunk.length;
      require(
        size <= 1024,
        "BAD_REQUEST",
        "nonce object exceeds request limit",
        400,
      );
      text += decoder.decode(chunk, { stream: true });
    }
    const body = JSON.parse(text + decoder.decode());
    require(
      body && Object.keys(body).join() === "nonce" &&
        /^[0-9a-f]{64}$/.test(body.nonce),
      "BAD_REQUEST",
      "only a fresh 32-byte hex nonce is accepted",
      400,
    );
    return body.nonce;
  } catch (error) {
    if (error instanceof InferenceError) throw error;
    fail("BAD_REQUEST", "nonce object is invalid", 400);
  }
}

async function completion(response, model) {
  require(
    response?.ok && response.body &&
      response.headers.get("content-type")?.startsWith("text/event-stream"),
    "PROVIDER_UNAVAILABLE",
    "provider did not return a completion stream",
  );
  const inferenceId = response.headers.get("inference-id");
  require(
    typeof inferenceId === "string" && /^[a-zA-Z0-9_-]+$/.test(inferenceId),
    "USAGE_MISMATCH",
    "provider omitted its billing correlation ID",
  );
  let pending = "", bytes = 0, done = false, reply = "", usage;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const frame = (raw) => {
    const data = raw.split("\n").filter((line) => line.startsWith("data:")).map(
      (line) => line.slice(5).trimStart(),
    ).join("\n");
    if (!data) return;
    require(
      !done,
      "PROVIDER_UNAVAILABLE",
      "provider sent data after completion",
    );
    if (data === "[DONE]") {
      done = true;
      return;
    }
    let value;
    try {
      value = JSON.parse(data);
    } catch {
      fail("PROVIDER_UNAVAILABLE", "provider stream is invalid", 502);
    }
    require(
      !value.error && (!value.model || value.model === model),
      "PROVIDER_UNAVAILABLE",
      "provider stream model or content is invalid",
    );
    const content = value.choices?.[0]?.delta?.content;
    require(
      content === undefined || content === null || typeof content === "string",
      "PROVIDER_UNAVAILABLE",
      "provider completion text is invalid",
    );
    if (content) reply += content;
    if (value.usage) {
      const u = value.usage;
      require(
        safeInteger(u.prompt_tokens) && safeInteger(u.completion_tokens) &&
          safeInteger(u.total_tokens) &&
          u.total_tokens >= u.prompt_tokens + u.completion_tokens,
        "USAGE_MISMATCH",
        "provider token usage is invalid",
      );
      usage = {
        prompt_tokens: u.prompt_tokens,
        completion_tokens: u.completion_tokens,
        total_tokens: u.total_tokens,
      };
    }
  };
  try {
    for await (const chunk of response.body) {
      bytes += chunk.length;
      require(
        bytes <= 1024 * 1024,
        "PROVIDER_UNAVAILABLE",
        "provider diagnostic response exceeded its limit",
      );
      pending = (pending + decoder.decode(chunk, { stream: true })).replace(
        /\r\n/g,
        "\n",
      );
      let at;
      while ((at = pending.indexOf("\n\n")) >= 0) {
        frame(pending.slice(0, at));
        pending = pending.slice(at + 2);
      }
    }
    pending += decoder.decode();
    require(
      !pending.trim() && done && reply.trim() && usage,
      "PROVIDER_UNAVAILABLE",
      "provider diagnostic stream did not complete with text and usage",
    );
    return { inferenceId, reply, usage };
  } catch (error) {
    if (error instanceof InferenceError) throw error;
    fail("PROVIDER_UNAVAILABLE", "provider diagnostic stream failed", 502);
  }
}

// This operator-only diagnostic has one fixed, small request; it never mints a
// key, accepts user prompts, changes credit, or stores provider content.
export async function providerCheck(
  {
    request,
    provider,
    payments,
    cfg,
    operatorTokenHash,
    now = () => Math.floor(Date.now() / 1000),
  },
) {
  const auth = request.headers.get("authorization");
  require(
    typeof operatorTokenHash === "string" &&
      /^[0-9a-f]{64}$/.test(operatorTokenHash) &&
      typeof auth === "string" && /^Bearer [^\s]+$/.test(auth),
    "OPERATOR_AUTH",
    "operator authentication required",
    403,
  );
  const actual = hex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(auth.slice(7))),
    ),
  );
  let different = 0;
  for (let i = 0; i < 64; i++) {
    different |= actual.charCodeAt(i) ^ operatorTokenHash.charCodeAt(i);
  }
  require(
    different === 0,
    "OPERATOR_AUTH",
    "operator authentication required",
    403,
  );
  const nonce = await nonceBody(request);
  require(
    provider?.apiKey && payments && typeof cfg?.model === "string" &&
      cfg.model.includes("/"),
    "PROVIDER_NOT_CONFIGURED",
    "a configured TEE model and provider key are required",
    503,
  );
  await payments.serial(async () => {
    const at = now();
    require(
      !Number.isFinite(payments.state.lastProviderCheckAt) ||
        at - payments.state.lastProviderCheckAt >= 60,
      "PROVIDER_RATE_LIMIT",
      "operator provider check is limited to once per minute",
      429,
    );
    const next = { ...payments.state, lastProviderCheckAt: at };
    await payments.save(next);
    payments.state = next;
  });
  let attestation;
  try {
    attestation = await provider.attest({ model: cfg.model, nonce });
    require(
      attestation?.evidence?.verification === "verified" &&
        attestation.evidence.model === cfg.model &&
        attestation.evidence.nonce === nonce,
      "ATTESTATION_INVALID",
      "provider evidence does not match this diagnostic",
    );
    const response = await provider.chat({
      key: provider.apiKey,
      model: cfg.model,
      messages: [{ role: "user", content: "Reply with exactly OK." }],
      max_tokens: 128,
      attestation,
    });
    const result = await completion(response, cfg.model);
    let costNanoUsd;
    for (let attempt = 0; attempt < 5; attempt++) {
      if (attempt) await new Promise((resolve) => setTimeout(resolve, 2000));
      const costs = await provider.costs({
        key: provider.apiKey,
        requestIds: [result.inferenceId],
      });
      const rows = costs?.requests;
      require(
        Array.isArray(rows) && rows.length === 1 &&
          rows[0].requestId === result.inferenceId &&
          ((typeof rows[0].costNanoUsd === "string" &&
            /^(0|[1-9][0-9]*)$/.test(rows[0].costNanoUsd)) ||
            safeInteger(rows[0].costNanoUsd)),
        "USAGE_MISMATCH",
        "provider cost attribution does not match this diagnostic",
      );
      if (BigInt(rows[0].costNanoUsd) > 0n) {
        costNanoUsd = String(rows[0].costNanoUsd);
        break;
      }
    }
    require(
      costNanoUsd !== undefined,
      "USAGE_PENDING",
      "provider cost accounting is pending",
      409,
    );
    return {
      result: "PASS",
      model: cfg.model,
      ...result,
      attestation: attestation.evidence,
      costNanoUsd,
      streamCompleted: true,
    };
  } catch (error) {
    if (error instanceof InferenceError) throw error;
    if (error?.code === "PROVIDER_AUTH") {
      fail("PROVIDER_AUTH", "provider authentication failed", 502);
    }
    fail("PROVIDER_UNAVAILABLE", "operator provider diagnostic failed", 502);
  } finally {
    attestation?.transport?.close?.();
  }
}
