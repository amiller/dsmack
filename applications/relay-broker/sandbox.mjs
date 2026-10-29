import { Refused } from "./broker.mjs";
import { canonical } from "./grants.mjs";
import { hex, sha256 } from "../../dstack-compat/secret-release/policy.mjs";
const enc = new TextEncoder();
export const jobLimit = 48 * 1024 * 1024 + 16384;
const require = (ok, message, status = 400) => { if (!ok) throw new Refused(message, status); };
let inProcess;
async function nativeTransport(cfg) {
  return await (inProcess ??= import("./deno-forwarder.mjs").then(({ createDenoForwarder }) => createDenoForwarder({ backhaulPeers: cfg.sandbox_backhaul_peers ?? [] })));
}
function nodeResponse(result) {
  if (result.status === "refused") return Response.json(result, { status: result.error === "busy" || result.error === "replay" ? 409 : 403 });
  return Response.json(result);
}

// Inputs and outputs remain encrypted to the compute node/browser. No job state
// is persisted, and a broken response is never automatically resubmitted.
export async function sandbox(req, broker, readBody, transport = nativeTransport) {
  const url = new URL(req.url), path = url.pathname;
  let node, payload, endpoint;
  if (path.startsWith("/sandbox/p2p/")) {
    require(broker.cfg.sandbox_backhaul_peers?.length, "backhaul_not_configured", 503);
    return (await transport(broker.cfg)).acceptBackhaul(req);
  }
  const match = /^\/sandbox\/nodes\/([^/]+)\/attestation$/.exec(path);
  if (req.method === "GET" && match) {
    node = broker.live().find((r) => r.kind === "compute" && r.relay_peer === match[1]);
    require(node, "node_not_live", 404);
    const challenge = url.searchParams.get("challenge") ?? "";
    require(!challenge || /^[0-9a-f]{64}$/.test(challenge), "challenge");
    require(!node.payments || challenge, "fresh_challenge_required");
    payload = { target: node.relay_maddr, challenge: node.payments ? challenge : "" }; endpoint = "attestation";
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
  let forwarder;
  try { forwarder = await transport(broker.cfg); }
  catch { throw new Refused("sandbox_transport_unavailable", 503); }
  try { return nodeResponse(await forwarder.forward(endpoint, payload, { signal: req.signal })); }
  catch (error) { throw new Refused(error.code || "node_unreachable", error.status || 502); }
}
