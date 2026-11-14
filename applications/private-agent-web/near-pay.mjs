// Pass-through for the three PingPay calls that refuse browser origins. Fixed upstreams, nothing stored: the page
// sends its own NEAR AI session, which NEAR AI's dashboard route reads from cookies.
const routes = {
  "/near-pay/checkout": "https://cloud.near.ai/api/pingpay/create-checkout-session",
  "/near-pay/session": "https://pay.pingpay.io/api/rpc/checkout/getSession",
  "/near-pay/prepare": "https://pay.pingpay.io/api/rpc/payments/prepare",
};
const cors = { "access-control-allow-origin": "*", "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type" };
export async function nearPay(req, fetcher = fetch) {
  const upstream = routes[new URL(req.url).pathname];
  if (!upstream) return new Response("Not found", { status: 404, headers: cors });
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405, headers: cors });
  const text = await req.text();
  if (text.length > 16384) return new Response("Too large", { status: 413, headers: cors });
  let body = JSON.parse(text), headers = { "content-type": "application/json" };
  if (upstream.startsWith("https://cloud.near.ai/")) {
    const { accessToken, refreshToken, ...rest } = body;
    const token = (v, n) => typeof v === "string" && v.length <= n && /^[\w.~-]+$/.test(v);
    if (!token(accessToken, 8192) || !token(refreshToken, 16384))
      return new Response("NEAR AI session required", { status: 400, headers: cors });
    headers.cookie = `access_token=${accessToken}; refresh_token=${refreshToken}`;
    body = rest;
  }
  const r = await fetcher(upstream, { method: "POST", headers, body: JSON.stringify(body), redirect: "error" });
  return new Response(r.body, { status: r.status, headers: { ...cors, "content-type": r.headers.get("content-type") || "application/json" } });
}
