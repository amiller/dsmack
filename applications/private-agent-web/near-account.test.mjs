import test from "node:test";
import assert from "node:assert/strict";
import { signInBody, checkPayment, NEAR_USDC, TREASURY } from "./near-account.mjs";
import { BASE_USDC } from "./intents-funding.mjs";
import { nearPay } from "./near-pay.mjs";

test("NEP-413 sign-in matches the ZCON stick's account.py for the same seed and nonce", async () => {
  // python: nacl SigningKey(bytes(range(32))) signing sha256(NEP-413 bytes) as in near_fund/account.py bootstrap().
  const body = await signInBody(Uint8Array.from({ length: 32 }, (_, i) => i), Uint8Array.from({ length: 32 }, (_, i) => 100 + i));
  assert.equal(body.signed_message.accountId, "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
  assert.equal(body.signed_message.signature, "MVVWOavwHXUoCaYVMv79Ep05lAW8LIi9tN2yhGBquVtkYG4GXRzleLbf1gRd0d+pGORM/+TTI5aT9FnX6HVhBA==");
  assert.deepEqual(body.payload, { message: "Sign in to NEAR AI Cloud", nonce: Array.from({ length: 32 }, (_, i) => 100 + i), recipient: "cloud.near.ai" });
});

const payer = "0x00000000000000000000000000000000000000aa", to = "0x00000000000000000000000000000000000000bb";
const prepared = () => ({ depositAddress: to,
  payment: { status: "PENDING", paymentMethod: "DEPOSIT", depositAddress: to, request: { payer: { address: payer }, recipient: { address: TREASURY }, idempotencyKey: "session:s1" } },
  quote: { amountIn: "2030331", amountOut: "2000000", depositAddress: to,
    quoteRequest: { originAsset: BASE_USDC, destinationAsset: NEAR_USDC } } });
const terms = { sessionId: "s1", units: 2000000n, payer };

test("PingPay payment is accepted only when it pays this invoice to NEAR AI from this wallet", () => {
  assert.deepEqual(checkPayment(prepared(), terms), { depositAddress: to, amountIn: 2030331n });
  const refused = (change, message) => { const p = prepared(); change(p); assert.throws(() => checkPayment(p, terms), message); };
  refused((p) => { p.payment.request.recipient.address = "attacker.near"; }, /someone other than NEAR AI/);
  refused((p) => { p.quote.amountOut = "1000000"; }, /output differs/);
  refused((p) => { p.payment.request.payer.address = to; }, /another payer/);
  refused((p) => { p.payment.request.idempotencyKey = "session:other"; }, /another invoice/);
  refused((p) => { p.quote.amountIn = "2300000"; }, /more than 10%/);
  refused((p) => { p.payment.depositAddress = payer; }, /deposit addresses differ/);
});

test("PingPay pass-through signs in to NEAR AI's dashboard with the page's NEP-413 message, then checks out with its cookie", async () => {
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/api/auth/near")) return new Response("{}", { headers: [["set-cookie", "sid=abc; Path=/; HttpOnly"], ["set-cookie", "rt=def; Path=/"]] });
    return new Response('{"sessionId":"s1"}', { headers: { "content-type": "application/json" } });
  };
  const post = (path, body) => nearPay(new Request("http://x" + path, { method: "POST", body: JSON.stringify(body), headers: { "user-agent": "UA/1" } }), fetcher);
  assert.equal((await post("/near-pay/other", {})).status, 404);
  assert.equal((await post("/near-pay/checkout", { organizationId: "o" })).status, 400);
  const signIn = { signed_message: { accountId: "a" }, payload: { message: "m" } };
  const r = await post("/near-pay/checkout", { signIn, organizationId: "o", amount: 200 });
  assert.equal(r.headers.get("access-control-allow-origin"), "*");
  assert.deepEqual(await r.json(), { sessionId: "s1" });
  assert.equal(calls[0].url, "https://cloud.near.ai/api/auth/near");
  assert.deepEqual(JSON.parse(calls[0].init.body), { signedMessage: signIn.signed_message, payload: signIn.payload });
  assert.equal(calls[1].url, "https://cloud.near.ai/api/pingpay/create-checkout-session");
  assert.equal(calls[1].init.headers.cookie, "sid=abc; rt=def");
  assert.equal(calls[1].init.headers["user-agent"], "UA/1");
  assert.equal(calls[1].init.headers.origin, "https://cloud.near.ai");
  assert.deepEqual(JSON.parse(calls[1].init.body), { organizationId: "o", amount: 200 });
  await post("/near-pay/prepare", { json: { input: {} } });
  assert.equal(calls[2].url, "https://pay.pingpay.io/api/rpc/payments/prepare");
  assert.equal(calls[2].init.headers.cookie, undefined);
});

test("the run after the one payment activates, signs in, swaps only the USDC shortfall, pays once, and resumes without paying twice", async () => {
  const { NearAccount } = await import("./near-account.mjs");
  const log = [], a = Object.create(NearAccount.prototype);
  let active = false, usdc = 500000n, credited = false;
  Object.assign(a, { activation: null, session: null, payment: null, usdcSwap: null, fetch: async () => new Response('{"status":"SUCCESS"}'),
    activated: async () => active,
    activationQuote: async () => ({ to: "0xa", wei: 1n }),
    activate: async () => { log.push("activate"); a.activation = { depositAddress: "0xa" }; active = true; },
    signIn: async () => { log.push("signIn"); a.session = {}; },
    invoice: async () => { log.push("invoice"); return { sessionId: "s", units: 2000000n, amountIn: 2030000n, depositAddress: "0xd" }; },
    balances: async () => ({ usdcUnits: usdc }),
    swapToUsdc: async (n) => { log.push("swap " + n); a.usdcSwap = { depositAddress: "0xs" }; usdc += n; },
    payInvoice: async () => { log.push("pay"); a.payment = { txHash: "0xp" }; credited = true; },
    paymentCredited: async () => credited,
    credit: async () => ({ remaining: credited ? 2000000000 : 0 }),
    apiKey: async () => "sk-test" });
  assert.equal(await a.run(2, () => {}, async () => {}), "sk-test");
  assert.deepEqual(log, ["activate", "signIn", "invoice", "swap 1780000", "pay"]);
  log.length = 0;
  assert.equal(await a.run(2, () => {}, async () => {}), "sk-test");
  assert.deepEqual(log, []);
  a.payment = null; // the payment landed but its record was lost: the credit is there, so nothing is bought again
  assert.equal(await a.run(2, () => {}, async () => {}), "sk-test");
  assert.deepEqual(log, []);
});

test("the one payment covers the credit, the activation and gas", async () => {
  const { fundingWei } = await import("./near-account.mjs");
  const wei = fundingWei(2, 3000);
  assert.equal(wei, 823333333333334n + 3n * 10n ** 13n + 4n * 10n ** 13n);
});
