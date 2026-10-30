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
      apiKey,
      fetcher = fetch,
      verifyAttestation = verifyNearAttestation,
      attestationPolicy,
      baseUrl = "https://cloud-api.near.ai",
    } = {},
  ) {
    Object.assign(this, {
      apiKey,
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
  async costs({ key, requestIds }) {
    need(
      Array.isArray(requestIds) && requestIds.length > 0 &&
        requestIds.length <= 10000 && requestIds.every(id),
    );
    const body = await readJson(
      await this.request("/v1/billing/costs", {
        token: key,
        method: "POST",
        body: { requestIds },
      }),
    );
    need(
      Array.isArray(body.requests) &&
        body.requests.every((r) =>
          requestIds.includes(r.requestId) && integer(r.costNanoUsd)
        ),
    );
    return {
      requests: body.requests.map((r) => ({
        requestId: r.requestId,
        costNanoUsd: r.costNanoUsd,
      })),
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
  async chatEncrypted({ key, model, body, headers, attestation, signal }) {
    need(
      attestation?.transport?.fetchEncrypted &&
        attestation.evidence?.model === model &&
        attestation.evidence?.verified === true &&
        attestation.evidence.expires_at > Date.now() / 1000,
      "ATTESTATION_INVALID",
    );
    let response;
    try {
      response = await attestation.transport.fetchEncrypted(
        this.baseUrl + "/v1/chat/completions",
        {
          method: "POST",
          signal,
          headers: {
            ...headers,
            authorization: `Bearer ${key}`,
            "content-type": "application/json",
            "accept-encoding": "identity",
          },
          body: JSON.stringify(body),
        },
      );
    } catch {
      throw new NearError("ATTESTATION_INVALID");
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
