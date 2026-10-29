import { peerBytes, verifyRelay } from "./attestation.mjs";
import { signGrant } from "./grants.mjs";
import { Refused } from "./broker.mjs";
import {
  hex,
  sha256,
  unhex,
} from "../../dstack-compat/secret-release/policy.mjs";
const enc = new TextEncoder();
const need = (ok, message, status = 403) => {
  if (!ok) throw new Refused(message, status);
};
export function canonical(value) {
  const sort = (v) =>
    Array.isArray(v)
      ? v.map(sort)
      : v && typeof v === "object"
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sort(v[k])]))
      : v;
  return JSON.stringify(sort(value));
}
const bytes = (v) => enc.encode(canonical(v)),
  hash = async (v) => hex(await sha256(v));
async function verify(key, sig, value) {
  need(
    typeof sig === "string" && /^[0-9a-f]{128}$/.test(sig),
    "sandbox_signature",
  );
  const pub = await crypto.subtle.importKey("raw", key, "Ed25519", false, [
    "verify",
  ]);
  need(
    await crypto.subtle.verify("Ed25519", pub, unhex(sig), bytes(value)),
    "sandbox_signature",
  );
}
async function sign(key, value) {
  return hex(
    new Uint8Array(await crypto.subtle.sign("Ed25519", key.priv, bytes(value))),
  );
}
async function operator(req, expected) {
  const auth = req.headers.get("authorization");
  need(expected && auth?.startsWith("Bearer "), "operator_auth");
  const actual = await hash(enc.encode(auth.slice(7)));
  let different = actual.length ^ expected.length;
  for (let i = 0; i < actual.length; i++) {
    different |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  need(different === 0, "operator_auth");
}
export async function registerDiagnostic(b, r) {
  need(!r.payments && r.kind === "compute", "diagnostic_registration");
  const workloads = b.cfg.sandboxDiagnosticWorkloads ?? [];
  const checked = await verifyRelay(
    r,
    { ...b.cfg, workloads },
    b.chain,
    b.now(),
  );
  const out = {
    ...Object.fromEntries(
      [
        "relay_peer",
        "relay_maddr",
        "manifest_sha256",
        "os_image_hash",
        "cdhash",
        "receipt_key",
        "secret_key",
        "admit_until",
      ].filter((k) => r[k] !== undefined).map((k) => [k, r[k]]),
    ),
    kind: "compute",
    proof: r.attestation,
    attestation: { status: "verified", ...checked },
    expires_at: b.now() + 60,
    operator_diagnostic: true,
  };
  need(
    Number.isSafeInteger(out.admit_until) && out.admit_until > b.now(),
    "diagnostic_expired",
  );
  b.relays.set(r.relay_peer, out);
  return out;
}
export async function readCompletion(response, model) {
  need(response.ok && response.body, "provider_response", 502);
  const inferenceId = response.headers.get("inference-id");
  need(
    inferenceId && /^[a-zA-Z0-9_-]+$/.test(inferenceId),
    "provider_billing_id",
    502,
  );
  let pending = "",
    size = 0,
    done = false,
    content = "",
    usage,
    finishReason,
    identifier;
  const calls = new Map(), decoder = new TextDecoder("utf-8", { fatal: true });
  function frame(raw) {
    const data = raw.split("\n").filter((l) => l.startsWith("data:")).map((l) =>
      l.slice(5).trimStart()
    ).join("\n");
    if (!data) return;
    need(!done, "provider_after_done", 502);
    if (data === "[DONE]") {
      done = true;
      return;
    }
    const v = JSON.parse(data);
    need(!v.error && (!v.model || v.model === model), "provider_model", 502);
    identifier = v.id ?? identifier;
    const choice = v.choices?.[0], d = choice?.delta ?? {};
    if (d.content) content += d.content;
    for (const c of d.tool_calls ?? []) {
      need(
        Number.isSafeInteger(c.index) && c.index >= 0 && c.index < 32,
        "provider_tool_index",
        502,
      );
      const old = calls.get(c.index) ??
        { id: "", type: "function", function: { name: "", arguments: "" } };
      if (c.id) old.id += c.id;
      if (c.function?.name) old.function.name += c.function.name;
      if (c.function?.arguments) old.function.arguments += c.function.arguments;
      calls.set(c.index, old);
    }
    if (choice?.finish_reason) finishReason = choice.finish_reason;
    if (v.usage) usage = v.usage;
  }
  for await (const chunk of response.body) {
    size += chunk.length;
    need(size <= 4 << 20, "provider_result_bound", 502);
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
  need(
    !pending.trim() && done && usage &&
      ["prompt_tokens", "completion_tokens", "total_tokens"].every((k) =>
        Number.isSafeInteger(usage[k]) && usage[k] >= 0
      ),
    "provider_completion_incomplete",
    502,
  );
  const normalizedUsage = Object.fromEntries(
    ["prompt_tokens", "completion_tokens", "total_tokens"].map(
      (k) => [k, usage[k]],
    ),
  );
  need(
    normalizedUsage.total_tokens >=
      normalizedUsage.prompt_tokens + normalizedUsage.completion_tokens,
    "provider_usage",
    502,
  );
  const toolCalls = [...calls.entries()].sort((a, b) => a[0] - b[0]).map((
    [, v],
  ) => v);
  need(
    toolCalls.every((c) =>
      c.id &&
      ["list_files", "read_file", "write_file"].includes(c.function.name)
    ),
    "provider_tool",
    502,
  );
  return {
    inferenceId,
    result: {
      id: identifier ?? inferenceId,
      model,
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content,
          ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
        },
        finish_reason: finishReason ?? "stop",
      }],
      usage: normalizedUsage,
    },
  };
}
export class SandboxInference {
  constructor(b) {
    this.b = b;
  }
  async operatorGrant(req, r, tokenHash) {
    const b = this.b;
    await operator(req, tokenHash);
    need(
      /^[0-9a-f]{32}$/.test(r.job_id) && Number.isSafeInteger(r.amount) &&
        r.amount >= 1 && r.amount <= 180,
      "operator_job",
      400,
    );
    const node = b.live().find((n) =>
      n.relay_peer === r.node_peer && n.operator_diagnostic
    );
    need(node, "diagnostic_node_not_live", 404);
    need(peerBytes(r.client_peer).length === 38, "operator_client");
    return b.payments.serial(async () => {
      const existing = b.payments.state.sandboxDiagnosticGrants ?? {};
      need(
        !Object.values(existing).some((g) => g.job_id === r.job_id),
        "operator_job_replay",
        409,
      );
      const grant = await signGrant(b.key, {
        client_peer: r.client_peer,
        relay_peer: r.node_peer,
        unit: "seconds",
        seconds: r.amount,
        expires_at: b.now() + 300,
      });
      await this.save({
        sandboxDiagnosticGrants: {
          ...existing,
          [grant.grant_id]: {
            job_id: r.job_id,
            client_peer: r.client_peer,
            node_peer: r.node_peer,
            expires_at: grant.expires_at,
          },
        },
      });
      return grant;
    });
  }
  async save(fields) {
    const p = this.b.payments, next = { ...p.state, ...fields };
    await p.save(next);
    p.state = next;
  }
  async mint(r) {
    const b = this.b;
    need(b.inference?.provider?.apiKey, "sandbox_provider_not_configured", 503);
    const { sig, ...body } = r;
    need(
      Object.keys(body).sort().join() ===
          "client_peer,grant,job_id,node_peer,nonce" &&
        /^[0-9a-f]{32}$/.test(r.job_id) && /^[0-9a-f]{32}$/.test(r.nonce),
      "capability_request",
      400,
    );
    const peer = peerBytes(r.client_peer);
    need(peer.length === 38, "capability_client");
    await verify(peer.slice(6), sig, body);
    const node = b.live().find((n) => n.relay_peer === r.node_peer);
    need(node, "node_not_live", 404);
    let expires;
    if (r.grant?.grant) {
      const g = r.grant.grant, saved = b.payments.state.grants[g.purchaseId];
      need(
        saved && canonical(saved.envelope) === canonical(r.grant),
        "unknown_paid_grant",
      );
      need(
        g.buyerKey === "0x" + hex(peer.slice(6)) &&
          g.runId === node.payments?.runId && g.unit === 1,
        "paid_capability_scope",
      );
      need(
        b.cfg.sandboxPaidInferenceEnabled === true,
        "paid_model_allocation_not_configured",
        503,
      );
      expires = g.serviceUntil;
    } else {
      const { sig: grantSig, ...grant } = r.grant;
      await verify(unhex(b.key.public_key), grantSig, grant);
      const record = b.payments.state.sandboxDiagnosticGrants?.[grant.grant_id];
      need(
        record && record.job_id === r.job_id &&
          record.client_peer === r.client_peer &&
          record.node_peer === r.node_peer &&
          grant.client_peer === r.client_peer &&
          grant.relay_peer === r.node_peer && grant.unit === "seconds",
        "diagnostic_grant_scope",
      );
      expires = grant.expires_at;
    }
    need(expires > b.now(), "capability_grant_expired");
    return b.payments.serial(async () => {
      const jobs = b.payments.state.sandboxJobs ?? {};
      need(!jobs[r.job_id], "capability_replay", 409);
      const token = hex(crypto.getRandomValues(new Uint8Array(32))),
        job = {
          client_peer: r.client_peer,
          node_peer: r.node_peer,
          tokenHash: await hash(enc.encode(token)),
          expires,
          calls: 0,
          nonces: [],
          active: false,
          failed: false,
          usage: [],
          mode: node.operator_diagnostic ? "operator-diagnostic" : "paid",
        };
      await this.save({ sandboxJobs: { ...jobs, [r.job_id]: job } });
      return { schema: "dsmack-broker-inference/1", token, job_id: r.job_id };
    });
  }
  async complete(req, r) {
    const b = this.b,
      p = b.payments,
      provider = b.inference?.provider,
      model = b.cfg.inference?.model;
    need(
      provider?.apiKey && model && !model.startsWith("anthropic/"),
      "sandbox_provider_not_configured",
      503,
    );
    need(
      r &&
        Object.keys(r).sort().join() ===
          "job_id,max_tokens,messages,model,nonce,stream,tools" &&
        /^[0-9a-f]{32}$/.test(r.job_id) && /^[0-9a-f]{64}$/.test(r.nonce) &&
        r.model === model && r.stream === false &&
        Number.isSafeInteger(r.max_tokens) && r.max_tokens > 0 &&
        r.max_tokens <= 4096 && Array.isArray(r.messages) &&
        r.messages.length <= 64 && Array.isArray(r.tools) &&
        r.tools.length <= 3 && r.tools.every((t) =>
          t.type === "function" &&
          ["list_files", "read_file", "write_file"].includes(t.function?.name)
        ),
      "sandbox_model_request",
      400,
    );
    const auth = req.headers.get("authorization");
    need(auth?.startsWith("Bearer "), "capability_auth");
    const tokenHash = await hash(enc.encode(auth.slice(7)));
    await p.serial(async () => {
      const job = p.state.sandboxJobs?.[r.job_id];
      need(
        job && job.tokenHash === tokenHash && job.expires > b.now(),
        "capability_auth",
      );
      need(
        !job.active && !job.failed && job.calls < 8,
        "capability_exhausted",
        409,
      );
      need(
        !(job.nonces ?? []).includes(r.nonce),
        "capability_request_replay",
        409,
      );
      await this.save({
        sandboxJobs: {
          ...p.state.sandboxJobs,
          [r.job_id]: {
            ...job,
            calls: job.calls + 1,
            nonces: [...(job.nonces ?? []), r.nonce],
            active: true,
          },
        },
      });
    });
    let attestation;
    try {
      attestation = await provider.attest({ model, nonce: r.nonce });
      need(
        attestation.evidence?.verified &&
          attestation.evidence.model === model &&
          attestation.evidence.nonce === r.nonce,
        "sandbox_model_attestation",
        502,
      );
      const response = await provider.chat({
        key: provider.apiKey,
        model,
        messages: r.messages,
        tools: r.tools,
        max_tokens: r.max_tokens,
        attestation,
        signal: AbortSignal.any([req.signal, AbortSignal.timeout(150000)]),
      });
      const completion = await readCompletion(response, model);
      let costNanoUsd = null;
      for (let n = 0; n < 5; n++) {
        const costs = await provider.costs({
          key: provider.apiKey,
          requestIds: [completion.inferenceId],
        });
        const item = costs.requests?.find((v) =>
          v.requestId === completion.inferenceId
        );
        if (item && BigInt(item.costNanoUsd) > 0n) {
          costNanoUsd = String(item.costNanoUsd);
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      need(costNanoUsd !== null, "sandbox_cost_pending", 502);
      await p.serial(async () => {
        const job = p.state.sandboxJobs[r.job_id];
        await this.save({
          sandboxJobs: {
            ...p.state.sandboxJobs,
            [r.job_id]: {
              ...job,
              active: false,
              usage: [...job.usage, {
                inferenceId: completion.inferenceId,
                usage: completion.result.usage,
                costNanoUsd,
              }],
            },
          },
        });
      });
      const payload = {
        schema: "dsmack-broker-inference-response/1",
        job_id: r.job_id,
        nonce: r.nonce,
        request_sha256: await hash(bytes(r)),
        model,
        attestation: attestation.evidence,
        result: completion.result,
      };
      return { payload, signature: await sign(b.key, payload) };
    } catch (e) {
      await p.serial(async () => {
        const job = p.state.sandboxJobs?.[r.job_id];
        if (job) {
          await this.save({
            sandboxJobs: {
              ...p.state.sandboxJobs,
              [r.job_id]: { ...job, active: false, failed: true },
            },
          });
        }
      });
      if (e instanceof Refused) throw e;
      throw new Refused(e?.code ?? "sandbox_provider_failed", 502);
    } finally {
      attestation?.transport?.close();
    }
  }
}
