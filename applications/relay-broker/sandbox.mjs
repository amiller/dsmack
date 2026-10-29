import { Refused } from "./broker.mjs";
import { canonical } from "./grants.mjs";
import { hex, sha256 } from "../../dstack-compat/secret-release/policy.mjs";
const enc = new TextEncoder();
export const jobLimit = 48 * 1024 * 1024 + 16384;
const require = (ok, message, status = 400) => { if (!ok) throw new Refused(message, status); };

// Inputs and outputs remain encrypted to the compute node/browser. No job state
// is persisted, and a broken response is never automatically resubmitted.
export async function sandbox(req, broker, readBody, token, fetcher = fetch) {
  const url = new URL(req.url), path = url.pathname;
  let node, payload, endpoint;
  const match = /^\/sandbox\/nodes\/([^/]+)\/attestation$/.exec(path);
  if (req.method === "GET" && match) {
    node = broker.live().find((r) => r.kind === "compute" && r.relay_peer === match[1]);
    require(node, "node_not_live", 404);
    const challenge = url.searchParams.get("challenge") ?? "";
    require(!challenge || /^[0-9a-f]{64}$/.test(challenge), "challenge");
    require(!node.payments || challenge, "fresh_challenge_required");
    payload = { target: node.relay_maddr, challenge }; endpoint = "attestation";
  } else if (req.method === "POST" && path === "/sandbox/jobs") {
    const r = await readBody(req, jobLimit);
    node = broker.live().find((n) => n.kind === "compute" && n.relay_peer === r.node_peer);
    require(node, "node_not_live", 404);
    require(typeof r.job_id === "string" && /^[0-9a-f]{32}$/.test(r.job_id), "job_id");
    require(r.grant && typeof r.grant === "object" && !Array.isArray(r.grant), "grant");
    require(typeof r.client_peer === "string" && typeof r.signature === "string" && /^[0-9a-f]{128}$/.test(r.signature), "signed_admission");
    const b = r.sealed;
    require(b && Object.keys(b).sort().join() === "ct,epk,iv" && /^[0-9a-f]{128}$/.test(b.epk) && /^[0-9a-f]{24}$/.test(b.iv) && typeof b.ct === "string" && b.ct.length >= 32 && /^[0-9a-f]+$/.test(b.ct) && b.ct.length % 2 === 0, "sealed_bundle");
    payload = { target: node.relay_maddr, sealed: b, admission: {
      job_id: r.job_id, grant: r.grant, client_peer: r.client_peer, signature: r.signature,
      bundle_sha256: hex(await sha256(enc.encode(canonical(b)))),
    } }; endpoint = "jobs";
    require(enc.encode(canonical(payload.admission)).length <= 4096, "admission_too_large", 413);
  } else return new Response("not found", { status: 404 });
  require(broker.cfg.sandbox_forwarder, "sandbox_forwarder_not_configured", 503);
  let response;
  try {
    response = await fetcher(broker.cfg.sandbox_forwarder.replace(/\/$/, "") + "/" + endpoint, {
      method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) },
      body: canonical(payload), signal: AbortSignal.any([req.signal, AbortSignal.timeout(endpoint === "jobs" ? 905000 : 30000)]),
    });
  } catch { throw new Refused(endpoint === "jobs" ? "node_result_lost" : "node_unreachable", 502); }
  const raw = await response.text();
  require(enc.encode(raw).length <= jobLimit, "node_response_too_large", 502);
  let result;
  try { result = JSON.parse(raw); } catch { throw new Refused("node_response_invalid", 502); }
  if (!response.ok) return Response.json(result, { status: response.status });
  if (endpoint === "jobs" && result.status === "refused") return Response.json(result, { status: result.error === "busy" || result.error === "replay" ? 409 : 403 });
  return Response.json(result);
}

export function cors(req, response, origins = []) {
  const origin = req.headers.get("origin");
  if (origin && origins.includes(origin)) {
    response.headers.set("access-control-allow-origin", origin);
    response.headers.set("vary", "Origin");
    response.headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
    response.headers.set("access-control-allow-headers", "content-type");
  }
  return response;
}
