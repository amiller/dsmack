// Pass-through for the PingPay calls that refuse browser origins. Fixed upstreams, nothing stored. The checkout route
// is NEAR AI's dashboard, which has its own session cookie: the page sends a fresh NEP-413 sign-in, this signs in to
// the dashboard with it and uses the cookie it sets for that one checkout call.
const DASHBOARD = "https://cloud.near.ai";
const routes = {
  "/near-pay/checkout": DASHBOARD + "/api/pingpay/create-checkout-session",
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
  let body = JSON.parse(text);
  const headers = { "content-type": "application/json", "user-agent": req.headers.get("user-agent") ?? "" };
  if (upstream.startsWith(DASHBOARD)) {
    const { signIn, ...rest } = body;
    headers.origin = DASHBOARD; // the dashboard refuses cross-site POSTs (403)
    if (!signIn?.signed_message || !signIn?.payload) return new Response("NEP-413 sign-in required", { status: 400, headers: cors });
    const login = await fetcher(DASHBOARD + "/api/auth/near", { method: "POST", headers, redirect: "error",
      body: JSON.stringify({ signedMessage: signIn.signed_message, payload: signIn.payload }) });
    if (!login.ok) return new Response(await login.text(), { status: login.status, headers: cors });
    headers.cookie = login.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
    body = rest;
  }
  const r = await fetcher(upstream, { method: "POST", headers, body: JSON.stringify(body), redirect: "error" });
  return new Response(r.body, { status: r.status, headers: { ...cors, "content-type": r.headers.get("content-type") || "application/json" } });
}
