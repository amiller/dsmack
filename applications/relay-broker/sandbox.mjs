import { Refused } from "./broker.mjs";
const require = (ok, message, status = 400) => { if (!ok) throw new Refused(message, status); };
let inProcess;
async function nativeTransport(cfg, key) {
  return await (inProcess ??= import("./deno-forwarder.mjs").then(({ createDenoForwarder }) => createDenoForwarder({ signingKey: key, backhaulPeers: cfg.sandbox_backhaul_peers ?? [] })));
}
export async function sandbox(req, broker, transport = nativeTransport) {
  const url = new URL(req.url), path = url.pathname;
  let node, payload;
  if (req.method === "GET" && path === "/sandbox/transport") {
    return Response.json({ peer_id: (await transport(broker.cfg, broker.key)).peerId });
  }
  if (path.startsWith("/sandbox/p2p/")) {
    require(broker.cfg.sandbox_backhaul_peers?.length, "backhaul_not_configured", 503);
    return (await transport(broker.cfg, broker.key)).acceptBackhaul(req);
  }
  const match = /^\/sandbox\/nodes\/([^/]+)\/attestation$/.exec(path);
  if (req.method === "GET" && match) {
    node = broker.live().find((r) => r.kind === "compute" && r.relay_peer === match[1]);
    require(node, "node_not_live", 404);
    const challenge = url.searchParams.get("challenge") ?? "";
    require(!challenge || /^[0-9a-f]{64}$/.test(challenge), "challenge");
    require(!node.payments || challenge, "fresh_challenge_required");
    payload = { target: node.relay_maddr, challenge: node.payments ? challenge : "" };
  } else return new Response("not found", { status: 404 });
  let forwarder;
  try { forwarder = await transport(broker.cfg, broker.key); }
  catch { throw new Refused("sandbox_transport_unavailable", 503); }
  try { return Response.json(await forwarder.forward("attestation", payload, { signal: req.signal })); }
  catch (error) {
    const code = error.code || "node_unreachable", status = error.status || 502;
    if (error.detail) return Response.json({ error: code, stage: error.stage || code, detail: error.detail }, { status });
    throw new Refused(code, status);
  }
}
