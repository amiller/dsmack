import { verifyMessage } from "../payments/schema.mjs";
import { canonical } from "./grants.mjs";

export class InferenceError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}
const check = (ok, code, message, status = 400) => {
  if (!ok) throw new InferenceError(code, message, status);
};
const enc = new TextEncoder();
const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const randomId = () => hex(crypto.getRandomValues(new Uint8Array(16)));
const uint = (v) =>
  (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v)) ||
  (Number.isSafeInteger(v) && v >= 0);
const fields = (value, allowed) =>
  value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).every((k) => allowed.includes(k));
export const PRIVACY =
  "Browser-encrypted prompts and replies; broker forwards ciphertext to NEAR TEE model";

export class Inference {
  constructor(
    { payments, cfg, provider, now = () => Math.floor(Date.now() / 1000) },
  ) {
    Object.assign(this, {
      payments,
      cfg: {
        starterCreditNanoUsd: "250000000",
        maxNanoUsdPerToken: "1500",
        maxOutputTokens: 512,
        ...cfg,
      },
      provider,
      now,
    });
    check(
      payments && typeof cfg?.model === "string" && cfg.model.length > 0 &&
        uint(this.cfg.starterCreditNanoUsd) &&
        BigInt(this.cfg.starterCreditNanoUsd) > 0n &&
        uint(this.cfg.maxNanoUsdPerToken) &&
        BigInt(this.cfg.maxNanoUsdPerToken) > 0n &&
        Number.isSafeInteger(this.cfg.maxOutputTokens) &&
        this.cfg.maxOutputTokens > 0,
      "BAD_REQUEST",
      "model and integer inference limits are required",
    );
    this.sessions = new Map();
  }
  configured() {
    check(
      this.provider?.apiKey,
      "PROVIDER_NOT_CONFIGURED",
      "private inference is not configured",
      503,
    );
  }
  quote() {
    return {
      mode: "broker-e2ee",
      provider: "near",
      model: this.cfg.model,
      configured: Boolean(this.provider?.apiKey),
      starterCreditNanoUsd: String(this.cfg.starterCreditNanoUsd),
      maxNanoUsdPerToken: String(this.cfg.maxNanoUsdPerToken),
      maxOutputTokens: this.cfg.maxOutputTokens,
      maxRequestBytes: 262144,
      privacy: PRIVACY,
    };
  }
  status() {
    return this.quote();
  }
  async recover() {
    await this.payments.serial(async () => {
      const state = this.payments.state;
      const starter = BigInt(this.cfg.starterCreditNanoUsd);
      const accounts = { ...state.inferenceCredit };
      let changed = false;
      for (const [wallet, account] of Object.entries(accounts)) {
        const granted = BigInt(account.grantedNanoUsd);
        if (granted >= starter) continue;
        accounts[wallet] = {
          ...account,
          grantedNanoUsd: String(starter),
          starterTopUps: [...(account.starterTopUps ?? []), {
            amountNanoUsd: String(starter - granted),
            grantedNanoUsd: String(starter),
            grantedAt: this.now(),
          }],
        };
        changed = true;
      }
      if (changed) await this.save({ ...state, inferenceCredit: accounts });
    });
    // A persisted dispatch without a billing ID is ambiguous. Keep its credit
    // reserved: restarting must never send another request on its behalf.
    return {
      pendingRequests:
        Object.values(this.payments.state.inferenceRequests ?? {}).filter((r) =>
          r.status !== "charged"
        ).length,
    };
  }
  async save(next) {
    await this.payments.save(next);
    this.payments.state = next;
  }
  account(wallet) {
    const account = this.payments.state.inferenceCredit?.[wallet];
    check(
      account,
      "CREDIT_NOT_CONFIRMED",
      "claim starter credit with this wallet first",
      402,
    );
    return account;
  }
  summary(wallet) {
    const a = this.account(wallet),
      pending = this.payments.state.inferenceRequests?.[a.pending];
    const reserved = pending && pending.status !== "charged"
      ? BigInt(pending.reservedNanoUsd)
      : 0n;
    const guestReserved = Object.values(this.payments.state.agentSessions ?? {})
      .filter((s) => s.wallet === wallet && !s.final)
      .reduce((total, s) => total + BigInt(s.reservedNanoUsd), 0n);
    return {
      wallet,
      model: this.cfg.model,
      mode: "broker-e2ee",
      grantedNanoUsd: a.grantedNanoUsd,
      spentNanoUsd: a.spentNanoUsd,
      reservedNanoUsd: String(reserved + guestReserved),
      remainingNanoUsd: String(
        BigInt(a.grantedNanoUsd) - BigInt(a.spentNanoUsd) - reserved - guestReserved,
      ),
      modelSpentNanoUsd: String(Object.values(this.payments.state.inferenceRequests ?? {})
        .filter(r => r.wallet === wallet && r.status === "charged")
        .reduce((sum, r) => sum + BigInt(r.costNanoUsd), 0n)),
      artifactBudgets: Object.fromEntries(Object.entries(a.artifactBudgets ?? {}).map(([id, budget]) =>
        [id, { ...budget, reservedNanoUsd: pending?.artifactId === id && pending.status !== "charged" ? pending.reservedNanoUsd : "0" }])),
      usedTokens: a.usedTokens,
      pendingInferenceId: pending?.inferenceId ?? null,
    };
  }
  async authorized(r, action) {
    const extra = action === "prepare"
      ? ["attestationNonce", "artifactId"]
      : action === "artifact-budget"
      ? ["artifactId", "limitNanoUsd"]
      : action === "chat"
      ? ["sessionId", "body", "headers"]
      : action === "agent-open"
      ? ["conversationId", "client_peer", "node_peer"]
      : ["agent-status", "agent-end"].includes(action)
      ? ["sessionId"]
      : [];
    check(
      fields(r, ["action", "wallet", "nonce", "issuedAt", "sig", ...extra]) &&
        r.action === action &&
        /^0x[0-9a-fA-F]{40}$/.test(r.wallet) && /^[0-9a-f]{32}$/.test(r.nonce),
      "BAD_REQUEST",
      "signed wallet request fields required",
    );
    check(
      Number.isSafeInteger(r.issuedAt) &&
        Math.abs(this.now() - r.issuedAt) <= 120,
      "REQUEST_EXPIRED",
      "wallet request must be signed within 120 seconds",
      403,
    );
    const { sig, ...unsigned } = r;
    let signer;
    try {
      signer = verifyMessage(canonical(unsigned), sig).toLowerCase();
    } catch { /* rejected below */ }
    const wallet = r.wallet.toLowerCase();
    check(
      signer === wallet,
      "BUYER_SIGNATURE",
      "wallet signature does not verify",
      403,
    );
    await this.payments.serial(async () => {
      const state = this.payments.state;
      let a = state.inferenceCredit?.[wallet];
      if (!a) {
        check(
          action === "credit",
          "CREDIT_NOT_CONFIRMED",
          "claim starter credit with this wallet first",
          402,
        );
        a = {
          grantedNanoUsd: String(this.cfg.starterCreditNanoUsd),
          spentNanoUsd: "0",
          usedTokens: "0",
          pending: null,
          nonces: {},
        };
      }
      check(
        !Object.hasOwn(a.nonces, r.nonce),
        "REQUEST_REPLAY",
        "wallet request nonce already used",
        409,
      );
      const nonces = Object.fromEntries(
        Object.entries(a.nonces).filter(([, at]) => at >= this.now() - 240),
      );
      await this.save({
        ...state,
        inferenceCredit: {
          ...state.inferenceCredit,
          [wallet]: { ...a, nonces: { ...nonces, [r.nonce]: r.issuedAt } },
        },
      });
    });
    return wallet;
  }
  async credit(r) {
    const wallet = await this.authorized(r, "credit");
    return this.summary(wallet);
  }
  async artifactBudget(r) {
    const wallet = await this.authorized(r, "artifact-budget");
    check(typeof r.artifactId === "string" && /^[0-9a-f]{64}$/.test(r.artifactId) && typeof r.limitNanoUsd === "string" && r.limitNanoUsd.length <= 24 && uint(r.limitNanoUsd),
      "BAD_REQUEST", "artifact hash and integer budget limit required");
    await this.payments.serial(async () => {
      const a = this.account(wallet), old = this.summary(wallet).artifactBudgets[r.artifactId];
      check(!old || old.limitNanoUsd === r.limitNanoUsd,
        "BUDGET_ALREADY_SET", "artifact budget limit is already set", 409);
      if (old) return;
      await this.save({ ...this.payments.state, inferenceCredit: { ...this.payments.state.inferenceCredit,
        [wallet]: { ...a, artifactBudgets: { ...a.artifactBudgets,
          [r.artifactId]: { limitNanoUsd: r.limitNanoUsd, spentNanoUsd: "0" } } } } });
    });
    return this.summary(wallet);
  }
  artifactRemaining(wallet, artifactId) {
    check(typeof artifactId === "string" && /^[0-9a-f]{64}$/.test(artifactId), "BAD_REQUEST", "artifact identity must be a SHA256 hash");
    const budget = this.summary(wallet).artifactBudgets[artifactId];
    check(budget, "BUDGET_EXHAUSTED", "set an artifact budget before making model calls", 402);
    return BigInt(budget.limitNanoUsd) - BigInt(budget.spentNanoUsd) - BigInt(budget.reservedNanoUsd);
  }
  async prepare(r) {
    const wallet = await this.authorized(r, "prepare");
    this.configured();
    check(
      /^[0-9a-f]{64}$/.test(r.attestationNonce),
      "BAD_REQUEST",
      "fresh 32-byte attestation nonce required",
    );
    check(
      !this.account(wallet).pending,
      "REQUEST_IN_FLIGHT",
      "reconcile the previous inference request first",
      409,
    );
    check(
      BigInt(this.summary(wallet).remainingNanoUsd) > 0n,
      "CREDIT_EXHAUSTED",
      "wallet has no available inference credit",
      402,
    );
    if (r.artifactId !== undefined) check(this.artifactRemaining(wallet, r.artifactId) > 0n,
      "BUDGET_EXHAUSTED", "artifact model budget is exhausted", 402);
    const checked = await this.provider.attest({
      model: this.cfg.model,
      nonce: r.attestationNonce,
    });
    const e = checked?.evidence;
    check(
      e?.verification === "verified" && e.model === this.cfg.model &&
        e.nonce === r.attestationNonce &&
        /^[0-9a-fA-F]{128}$/.test(checked.modelPublicKey) &&
        checked.transport?.fetchEncrypted,
      "ATTESTATION_INVALID",
      "verified model key, nonce and encrypted transport required",
      502,
    );
    for (const [id, s] of this.sessions) {
      if (s.expiresAt <= this.now() || s.wallet === wallet) {
        s.attestation.transport?.close?.();
        this.sessions.delete(id);
      }
    }
    const sessionId = randomId(),
      expiresAt = Math.min(this.now() + 60, e.expires_at ?? this.now() + 60);
    check(
      expiresAt > this.now(),
      "ATTESTATION_INVALID",
      "provider evidence has expired",
      502,
    );
    this.sessions.set(sessionId, {
      wallet,
      expiresAt,
      attestation: checked,
      consumed: false,
      artifactId: r.artifactId,
    });
    return {
      ...this.summary(wallet),
      sessionId,
      expiresAt,
      attestation: { ...e, mode: "broker-e2ee", privacy: PRIVACY },
      modelPublicKey: checked.modelPublicKey,
    };
  }
  encryptedRequest(r, session) {
    const b = r.body, h = r.headers;
    const ciphertext = (v) => typeof v === "string" && /^04[0-9a-fA-F]{184,}$/.test(v) && v.length % 2 === 0;
    const callId = (v) => typeof v === "string" && /^[a-zA-Z0-9_-]{1,256}$/.test(v);
    const functionCall = (v) => fields(v, ["name", "arguments"]) && ciphertext(v.name) && ciphertext(v.arguments);
    const message = (m) => fields(m, ["role", "content", "tool_calls", "tool_call_id"]) &&
      ["user", "assistant", "system", "tool"].includes(m.role) &&
      (ciphertext(m.content) || (m.role === "assistant" && m.content === null && Array.isArray(m.tool_calls) && m.tool_calls.length > 0)) &&
      (m.tool_calls === undefined || (m.role === "assistant" && Array.isArray(m.tool_calls) && m.tool_calls.length <= 16 &&
        m.tool_calls.every((c) => fields(c, ["id", "type", "function"]) && callId(c.id) && c.type === "function" && functionCall(c.function)))) &&
      (m.role === "tool" ? callId(m.tool_call_id) : m.tool_call_id === undefined);
    const tool = (t) => fields(t, ["type", "function"]) && t.type === "function" &&
      fields(t.function, ["name", "description", "parameters"]) &&
      ciphertext(t.function.name) && ciphertext(t.function.description) && ciphertext(t.function.parameters);
    check(
      fields(b, ["model", "messages", "stream", "max_tokens", "stream_options", "tools", "tool_choice"]) &&
        b.model === this.cfg.model && b.stream === true && Number.isSafeInteger(b.max_tokens) &&
        b.max_tokens > 0 && b.max_tokens <= this.cfg.maxOutputTokens &&
        fields(b.stream_options, ["include_usage"]) && b.stream_options.include_usage === true &&
        Array.isArray(b.messages) && b.messages.length > 0 && b.messages.length <= 128 && b.messages.every(message) &&
        (b.tools === undefined || (Array.isArray(b.tools) && b.tools.every(tool))) &&
        (b.tool_choice === undefined || (b.tool_choice === "auto" && b.tools?.length > 0)),
      "BAD_REQUEST", "only bounded SDK-encrypted messages and tool fields are accepted",
    );
    check(
      fields(h, [
        "content-type",
        "x-signing-algo",
        "x-client-pub-key",
        "x-model-pub-key",
        "x-no-aliasing",
        "x-encrypt-all-fields",
      ]) &&
        h["content-type"] === "application/json" &&
        h["x-signing-algo"] === "ecdsa" &&
        h["x-encrypt-all-fields"] === "true" &&
        h["x-no-aliasing"] === "true" &&
        /^[0-9a-fA-F]{128}$/.test(h["x-client-pub-key"]) &&
        h["x-model-pub-key"] === session.attestation.modelPublicKey,
      "BAD_REQUEST",
      "SDK encryption headers must match the attested model key",
    );
    const size = enc.encode(JSON.stringify(b)).length;
    check(
      size <= 262144,
      "BAD_REQUEST",
      "encrypted inference request exceeds 262144 bytes",
    );
    return BigInt(size + 256 + 64 * b.messages.length + b.max_tokens) *
      BigInt(this.cfg.maxNanoUsdPerToken);
  }
  async chat(r) {
    const wallet = await this.authorized(r, "chat");
    this.configured();
    let session, localId;
    await this.payments.serial(async () => {
      const a = this.account(wallet);
      check(
        !a.pending,
        "REQUEST_IN_FLIGHT",
        "reconcile the previous inference request first",
        409,
      );
      session = this.sessions.get(r.sessionId);
      check(
        session && session.wallet === wallet &&
          session.expiresAt > this.now() && !session.consumed,
        "ATTESTATION_INVALID",
        "prepare a fresh attested inference session",
        403,
      );
      const reserve = this.encryptedRequest(r, session);
      check(
        BigInt(this.summary(wallet).remainingNanoUsd) >= reserve,
        "CREDIT_EXHAUSTED",
        "wallet credit cannot cover this request's maximum cost",
        402,
      );
      if (session.artifactId !== undefined) check(this.artifactRemaining(wallet, session.artifactId) >= reserve,
        "BUDGET_EXHAUSTED", "artifact budget cannot cover this request's maximum cost", 402);
      localId = randomId();
      const state = this.payments.state;
      await this.save({
        ...state,
        inferenceCredit: {
          ...state.inferenceCredit,
          [wallet]: { ...a, pending: localId },
        },
        inferenceRequests: {
          ...state.inferenceRequests,
          [localId]: {
            wallet,
            sessionId: r.sessionId,
            status: "sent",
            ...(session.artifactId !== undefined ? { artifactId: session.artifactId } : {}),
            reservedNanoUsd: String(reserve),
            inferenceId: null,
            usedTokens: null,
            streamCompleted: false,
            createdAt: this.now(),
          },
        },
      });
      session.consumed = true;
      this.sessions.delete(r.sessionId);
    });
    let response;
    try {
      response = await this.provider.chatEncrypted({
        key: this.provider.apiKey,
        model: this.cfg.model,
        body: r.body,
        headers: r.headers,
        attestation: session.attestation,
      });
      check(
        response?.ok && response.body &&
          response.headers.get("content-type")?.startsWith("text/event-stream"),
        "PROVIDER_UNAVAILABLE",
        "provider did not return an encrypted completion stream",
        502,
      );
      const inferenceId = response.headers.get("inference-id");
      check(
        inferenceId && /^[a-zA-Z0-9_-]+$/.test(inferenceId),
        "USAGE_PENDING",
        "provider billing ID is unavailable; credit remains reserved",
        409,
      );
      await this.payments.serial(async () => {
        const state = this.payments.state,
          ledger = state.inferenceRequests[localId];
        check(
          !Object.entries(state.inferenceRequests).some(([id, record]) =>
            id !== localId && record.inferenceId === inferenceId
          ),
          "USAGE_MISMATCH",
          "provider reused another request's billing ID",
          502,
        );
        await this.save({
          ...state,
          inferenceRequests: {
            ...state.inferenceRequests,
            [localId]: { ...ledger, inferenceId, status: "streaming" },
          },
        });
      });
    } catch (error) {
      await response?.body?.cancel();
      session.attestation.transport?.close?.();
      throw error;
    }
    const inference = this, decoder = new TextDecoder();
    let disconnected = false;
    const stream = new ReadableStream({
      async start(controller) {
        let buffer = "", tokens = null, done = false, failure = false;
        try {
          for await (const chunk of response.body) {
            buffer = (buffer + decoder.decode(chunk, { stream: true })).replace(
              /\r\n/g,
              "\n",
            );
            check(
              buffer.length <= 1024 * 1024,
              "PROVIDER_UNAVAILABLE",
              "provider stream frame exceeds its limit",
              502,
            );
            let at;
            while ((at = buffer.indexOf("\n\n")) >= 0) {
              const frame = buffer.slice(0, at);
              buffer = buffer.slice(at + 2);
              const data = frame.split("\n").filter((line) =>
                line.startsWith("data:")
              ).map((line) => line.slice(5).trimStart()).join("\n");
              if (data === "[DONE]") done = true;
              else if (data) {
                const value = JSON.parse(data);
                if (uint(value.usage?.total_tokens)) {
                  tokens = String(value.usage.total_tokens);
                }
              }
            }
            if (!disconnected) {
              try {
                controller.enqueue(chunk);
              } catch {
                disconnected = true;
              }
            }
          }
          buffer += decoder.decode();
          check(
            done && !buffer.trim(),
            "PROVIDER_UNAVAILABLE",
            "encrypted provider stream ended before completion",
            502,
          );
        } catch {
          failure = true;
        } finally {
          session.attestation.transport?.close?.();
          inference.sessions.delete(r.sessionId);
          try {
            await inference.payments.serial(async () => {
              const state = inference.payments.state,
                ledger = state.inferenceRequests[localId];
              await inference.save({
                ...state,
                inferenceRequests: {
                  ...state.inferenceRequests,
                  [localId]: {
                    ...ledger,
                    status: "responded",
                    usedTokens: tokens,
                    streamCompleted: done && !failure,
                  },
                },
              });
            });
          } catch {
            failure = true;
          }
          if (!disconnected) {
            if (failure) {
              controller.error(
                new InferenceError(
                  "PROVIDER_UNAVAILABLE",
                  "encrypted stream interrupted; reconcile usage before retry",
                  502,
                ),
              );
            } else controller.close();
          }
        }
      },
      cancel() {
        disconnected = true;
      },
    });
    return new Response(stream, {
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
        "inference-id": response.headers.get("inference-id"),
      },
    });
  }
  async usage(r) {
    const wallet = await this.authorized(r, "usage");
    this.configured();
    const a = this.account(wallet);
    if (!a.pending) return this.summary(wallet);
    const localId = a.pending,
      ledger = this.payments.state.inferenceRequests[localId];
    check(
      ledger.inferenceId && ledger.status === "responded" &&
        uint(ledger.usedTokens),
      "USAGE_PENDING",
      "provider request or billing evidence is still pending",
      409,
    );
    const costs = await this.provider.costs({
      key: this.provider.apiKey,
      requestIds: [ledger.inferenceId],
    });
    check(
      Array.isArray(costs?.requests) && costs.requests.length === 1 &&
        costs.requests[0].requestId === ledger.inferenceId &&
        uint(costs.requests[0].costNanoUsd),
      "USAGE_MISMATCH",
      "provider cost record does not match the dispatched request",
      502,
    );
    const cost = BigInt(costs.requests[0].costNanoUsd);
    check(
      cost > 0n,
      "USAGE_PENDING",
      "provider cost accounting is pending",
      409,
    );
    check(
      cost <= BigInt(ledger.reservedNanoUsd),
      "USAGE_MISMATCH",
      "provider cost exceeded the reserved maximum",
      502,
    );
    await this.payments.serial(async () => {
      const state = this.payments.state,
        current = state.inferenceRequests[localId];
      if (current.status === "charged") return;
      const account = this.account(wallet);
      check(
        account.pending === localId,
        "USAGE_MISMATCH",
        "wallet request ledger changed",
        502,
      );
      await this.save({
        ...state,
        inferenceCredit: {
          ...state.inferenceCredit,
          [wallet]: {
            ...account,
            pending: null,
            ...(current.artifactId !== undefined ? { artifactBudgets: { ...account.artifactBudgets,
              [current.artifactId]: { ...account.artifactBudgets[current.artifactId],
                spentNanoUsd: String(BigInt(account.artifactBudgets[current.artifactId].spentNanoUsd) + cost),
                lastSessionId: current.sessionId, lastCostNanoUsd: String(cost) } } } : {}),
            spentNanoUsd: String(BigInt(account.spentNanoUsd) + cost),
            usedTokens: String(
              BigInt(account.usedTokens) + BigInt(current.usedTokens),
            ),
          },
        },
        inferenceRequests: {
          ...state.inferenceRequests,
          [localId]: {
            ...current,
            status: "charged",
            costNanoUsd: String(cost),
            chargedAt: this.now(),
          },
        },
      });
    });
    return this.summary(wallet);
  }
}
