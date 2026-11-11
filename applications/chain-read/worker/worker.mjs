// Holds the RPC key: forwards the JSON-RPC reads Helios needs to env.RPC_URL, and GET .../latest to env.RELAY_URL.
const METHODS = new Set(["eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getCode",
  "eth_getProof", "eth_createAccessList", "eth_call"]);
const CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "content-type" };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...CORS, "content-type": "application/json" } });
const error = (id, code, message) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (!(await env.LIMITER.limit({ key: req.headers.get("cf-connecting-ip") ?? "" })).success) return json(error(null, -32005, "rate limited"), 429);
    if (req.method === "GET" && env.RELAY_URL && new URL(req.url).pathname.endsWith("/latest")) {
      const r = await fetch(env.RELAY_URL.replace(/\/$/, "") + "/latest").catch(() => null);
      return r ? new Response(r.body, { status: r.status, headers: { ...CORS, "content-type": "application/json" } }) : json({ error: "relay unreachable" }, 502);
    }
    if (req.method !== "POST") return json(error(null, -32600, "POST a JSON-RPC request"), 405);
    const body = await req.json().catch(() => undefined);
    if (body === undefined) return json(error(null, -32700, "parse error"), 400);
    const list = Array.isArray(body) ? body : [body];
    const allowed = list.filter((r) => METHODS.has(r?.method));
    const denied = list.filter((r) => !METHODS.has(r?.method)).map((r) => error(r?.id, -32601, `method not allowed: ${r?.method}`));
    let answers = [];
    if (allowed.length) {
      const r = await fetch(env.RPC_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(Array.isArray(body) ? allowed : allowed[0]) }).catch(() => null);
      if (!r) return json(error(null, -32603, "upstream unreachable"), 502);
      // Upstream errors pass through unchanged: Helios backs off on the provider's own 429, not on a rewritten one.
      if (!r.ok) return new Response(r.body, { status: r.status, headers: { ...CORS, "content-type": r.headers.get("content-type") ?? "text/plain" } });
      answers = [await r.json()].flat();
    }
    return json(Array.isArray(body) ? [...answers, ...denied] : answers[0] ?? denied[0]);
  },
};
