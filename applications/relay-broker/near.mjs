import { verifyNearAttestation } from "./near-attestation.mjs";

export class NearError extends Error {
  constructor(code, status = code === "PROVIDER_NOT_CONFIGURED" ? 503 : 502) {
    super(code);
    this.code = code;
    this.status = status;
  }
}
const need = (ok, code = "USAGE_MISMATCH") => {
  if (!ok) throw new NearError(code);
};
const integer = (v) =>
  (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v)) ||
  (Number.isSafeInteger(v) && v >= 0);
const readJson = async (response) => {
  try {
    return await response.json();
  } catch {
    throw new NearError("USAGE_MISMATCH");
  }
};
const id = (v) => typeof v === "string" && /^[a-zA-Z0-9_-]+$/.test(v);

export class NearProvider {
  constructor(
    {
      workspaceId,
      organizationId,
      managementToken,
      reportingToken,
      fetcher = fetch,
      verifyAttestation = verifyNearAttestation,
      attestationPolicy,
      baseUrl = "https://cloud-api.near.ai",
    } = {},
  ) {
    Object.assign(this, {
      workspaceId,
      organizationId,
      managementToken,
      reportingToken,
      fetcher,
      verifyAttestation,
      attestationPolicy,
      baseUrl: baseUrl.replace(/\/$/, ""),
    });
  }
  async request(
    path,
    { token, method = "GET", body, signal, anonymous = false } = {},
  ) {
    need(anonymous || token, "PROVIDER_NOT_CONFIGURED");
    let r;
    try {
      r = await this.fetcher(this.baseUrl + path, {
        method,
        headers: {
          ...(anonymous ? {} : { authorization: `Bearer ${token}` }),
          "content-type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: signal
          ? AbortSignal.any([signal, AbortSignal.timeout(30000)])
          : AbortSignal.timeout(30000),
        redirect: "error",
      });
    } catch {
      throw new NearError("PROVIDER_UNAVAILABLE");
    }
    if (!r.ok) {
      await r.body?.cancel();
      throw new NearError(
        r.status === 401 || r.status === 403
          ? "PROVIDER_AUTH"
          : r.status === 429
          ? "PROVIDER_RATE_LIMIT"
          : "PROVIDER_UNAVAILABLE",
        r.status === 429 ? 429 : 502,
      );
    }
    return r;
  }
  async mint({ name, capNanoUsd, expiresAt }) {
    need(
      id(this.workspaceId) && typeof name === "string" && name.length > 0 &&
        name.length <= 100 &&
        integer(capNanoUsd) && BigInt(capNanoUsd) > 0n &&
        BigInt(capNanoUsd) <= BigInt(Number.MAX_SAFE_INTEGER) &&
        Number.isFinite(Date.parse(expiresAt)),
    );
    const r = await this.request(
      `/v1/workspaces/${this.workspaceId}/api-keys`,
      {
        token: this.managementToken,
        method: "POST",
        body: {
          name,
          spendLimit: { amount: Number(capNanoUsd), currency: "USD" },
          expires_at: expiresAt,
        },
      },
    );
    const out = await readJson(r);
    need(
      id(out.id) && typeof out.key === "string" && out.key.length > 0 &&
        integer(out.spend_limit?.amount) &&
        String(out.spend_limit.amount) === String(capNanoUsd) &&
        out.spend_limit.currency === "USD",
    );
    return out;
  }
  async revoke(keyId) {
    need(id(this.workspaceId) && id(keyId));
    const r = await this.request(
      `/v1/workspaces/${this.workspaceId}/api-keys/${keyId}`,
      {
        token: this.managementToken,
        method: "DELETE",
      },
    );
    await r.body?.cancel();
  }
  async usage({ keyId, from, to, model }) {
    need(
      id(this.organizationId) && id(this.workspaceId) && id(keyId) &&
        Number.isFinite(Date.parse(from)) && Date.parse(to) >= Date.parse(from),
    );
    const filters = {
      start_time: from,
      end_time: to,
      source: "inference",
      workspace_id: this.workspaceId,
      api_key_id: keyId,
      limit: "1000",
    };
    const rows = [], ids = new Set(), cursors = new Set();
    let cursor;
    do {
      const q = new URLSearchParams(filters);
      if (cursor) q.set("cursor", cursor);
      const response = await this.request(
        `/v1/organizations/${this.organizationId}/usage/export?${q}`,
        { token: this.reportingToken },
      );
      const page = await readJson(response);
      need(Array.isArray(page.data));
      for (const row of page.data) {
        const i = row.inference;
        need(
          row.source === "inference" && row.api_key_id === keyId &&
            row.workspace_id === this.workspaceId &&
            id(row.id) && !ids.has(row.id) && i &&
            (!model || i.model === model) &&
            integer(i.input_tokens) && integer(i.output_tokens) &&
            integer(i.total_tokens) &&
            BigInt(i.total_tokens) >=
              BigInt(i.input_tokens) + BigInt(i.output_tokens) &&
            integer(row.total_cost_nano_usd) && id(i.inference_id) &&
            Date.parse(row.created_at) >= Date.parse(from) &&
            Date.parse(row.created_at) <= Date.parse(to),
          "USAGE_MISMATCH",
        );
        ids.add(row.id);
        // Persist only documented billing fields: unknown provider fields must
        // not smuggle prompt/answer text or credentials into durable state.
        rows.push({
          source: row.source,
          id: row.id,
          created_at: row.created_at,
          workspace_id: row.workspace_id,
          api_key_id: row.api_key_id,
          total_cost_nano_usd: String(row.total_cost_nano_usd),
          inference: {
            model: i.model,
            inference_id: i.inference_id,
            response_id: i.response_id,
            inference_type: i.inference_type,
            input_tokens: String(i.input_tokens),
            output_tokens: String(i.output_tokens),
            total_tokens: String(i.total_tokens),
            ...(integer(i.cache_read_tokens)
              ? { cache_read_tokens: String(i.cache_read_tokens) }
              : {}),
          },
        });
      }
      cursor = page.next_cursor;
      need(
        cursor === null || cursor === undefined ||
          (typeof cursor === "string" && cursor.length > 0 &&
            !cursors.has(cursor)),
      );
      if (cursor) cursors.add(cursor);
    } while (cursor);
    const sum = (fn) =>
      rows.reduce((n, row) => n + BigInt(fn(row)), 0n).toString();
    return {
      rows,
      inputTokens: sum((r) => r.inference.input_tokens),
      outputTokens: sum((r) => r.inference.output_tokens),
      totalTokens: sum((r) => r.inference.total_tokens),
      costNanoUsd: sum((r) => r.total_cost_nano_usd),
    };
  }
  async attest({ key, model, nonce }) {
    need(
      typeof model === "string" && model.length > 0 &&
        /^[0-9a-f]{64}$/.test(nonce),
    );
    const gatewayQuery = new URLSearchParams({
      nonce,
      signing_algo: "ecdsa",
      include_tls_fingerprint: "true",
    });
    const modelQuery = new URLSearchParams({
      model,
      provider: "near",
      nonce,
      signing_algo: "ecdsa",
      include_tls_fingerprint: "false",
    });
    const gateway = await readJson(
      await this.request(`/v1/attestation/report?${gatewayQuery}`, {
        anonymous: true,
      }),
    );
    const models = await readJson(
      await this.request(`/v1/attestation/report?${modelQuery}`, {
        anonymous: true,
      }),
    );
    const report = {
      gateway_attestation: gateway.gateway_attestation,
      model_attestations: models.model_attestations,
    };
    try {
      const checked = await this.verifyAttestation({
        report,
        nonce,
        model,
        baseUrl: this.baseUrl,
        policy: this.attestationPolicy,
        fetcher: this.fetcher,
      });
      need(
        checked?.evidence && checked.transport?.fetch,
        "ATTESTATION_INVALID",
      );
      return checked;
    } catch (e) {
      if (e instanceof NearError) throw e;
      throw new NearError("ATTESTATION_INVALID", 502);
    }
  }
  async chat({ key, model, messages, max_tokens, attestation, signal }) {
    need(
      attestation?.transport?.fetch && attestation.evidence?.model === model &&
        attestation.evidence?.verified === true &&
        attestation.evidence.expires_at > Date.now() / 1000,
      "ATTESTATION_INVALID",
    );
    need(
      Array.isArray(messages) && Number.isSafeInteger(max_tokens) &&
        max_tokens > 0,
    );
    let response;
    try {
      response = await attestation.transport.fetch(
        this.baseUrl + "/v1/chat/completions",
        {
          method: "POST",
          signal,
          headers: {
            authorization: `Bearer ${key}`,
            "content-type": "application/json",
            "x-no-aliasing": "true",
            "accept-encoding": "identity",
          },
          body: JSON.stringify({
            model,
            messages,
            max_tokens,
            stream: true,
            stream_options: { include_usage: true },
          }),
        },
      );
    } catch {
      throw new NearError("ATTESTATION_INVALID", 502);
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new NearError(
        response.status === 429
          ? "PROVIDER_RATE_LIMIT"
          : "PROVIDER_UNAVAILABLE",
        response.status === 429 ? 429 : 502,
      );
    }
    need(response.headers.get("content-type")?.startsWith("text/event-stream"));
    return response;
  }
}
