// Fund this page's own wallet with any token through NEAR Intents 1Click, entirely from the browser: no broker, no
// treasury. The page asks 1Click for an exact-output quote paying USDC on Base mainnet to the wallet's own address,
// checks 1Click's signature and that the quote is the one asked for, then shows the deposit address and polls status.
// Quote checks adapted from abalone portable/funding quote-signature.mjs and quote-semantics.mjs (1Click SDK 0.1.26
// projection, ISC, NEAR Foundation), using WebCrypto instead of node:crypto.
export const API = "https://1click.chaindefuser.com/v0";
export const BASE_USDC = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
export const BASE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MANAGER_KEY = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const REQUEST = ["dry", "swapType", "slippageTolerance", "originAsset", "depositType", "destinationAsset", "amount", "refundTo",
  "refundType", "recipient", "recipientType", "deadline"];
const OPTIONAL = ["quoteWaitingTimeMs", "referral", "virtualChainRecipient", "virtualChainRefundRecipient", "customRecipientMsg"];
const AMOUNTS = ["amountIn", "amountInFormatted", "amountInUsd", "minAmountIn", "amountOut", "amountOutFormatted", "amountOutUsd", "minAmountOut"];
const EXECUTION = ["depositAddress", "depositMemo", "deadline", "timeWhenInactive", "timeEstimate", "refundFee", "withdrawFee"];
const MAX_FEE_BPS = 50;
const check = (ok, message) => { if (!ok) throw new Error("NEAR Intents quote refused: " + message); };

function decode58(text, length) {
  let n = 0n;
  const s = text.replace(/^ed25519:/, "");
  for (const c of s) { const d = B58.indexOf(c); check(d >= 0, "bad base58"); n = n * 58n + BigInt(d); }
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = Uint8Array.from([...Array(s.match(/^1*/)[0].length).fill(0), ...(n ? hex.match(/../g).map((x) => parseInt(x, 16)) : [])]);
  check(bytes.length === length, "bad key or signature length");
  return bytes;
}
function encode58(bytes) {
  let n = BigInt("0x" + Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("")), out = "";
  while (n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b) break; out = "1" + out; }
  return out;
}

// The message 1Click signs: base58(sha256(sorted JSON of the SDK 0.1.26 projected fields)), as UTF-8.
export async function signedMessage(response) {
  const r = response.quoteRequest, q = response.quote, f = {};
  for (const k of REQUEST) f[k] = r[k];
  for (const k of OPTIONAL) f[k] = r[k] || undefined;
  for (const k of AMOUNTS) f[k] = q[k];
  if (!r.dry) for (const k of EXECUTION) f[k] = q[k] || undefined;
  f.timestamp = response.timestamp;
  for (const v of Object.values(f)) check(v === null || v === undefined || ["string", "number", "boolean"].includes(typeof v), "nested field");
  const canonical = "{" + Object.keys(f).sort().filter((k) => f[k] !== undefined).map((k) => JSON.stringify(k) + ":" + JSON.stringify(f[k])).join(",") + "}";
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
  return new TextEncoder().encode(encode58(digest));
}
export async function verifySignature(response) {
  const key = await crypto.subtle.importKey("raw", decode58(MANAGER_KEY, 32), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, decode58(response.signature, 64), await signedMessage(response));
}

const units = (s) => { check(typeof s === "string" && /^(0|[1-9]\d{0,30})$/.test(s), "bad amount " + s); return BigInt(s); };
const formatted = (s, n, decimals) => {
  check(typeof s === "string" && /^\d+(\.\d+)?$/.test(s), "bad formatted amount");
  const [whole, frac = ""] = s.split(".");
  check(frac.length <= decimals && BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, "0") || "0") === n, "formatted amount differs");
};

// The exact request this page sends: EXACT_OUTPUT `usdc` (6-decimal units) to `recipient` on Base, refunds to `refundTo`.
export function quoteRequest({ originAsset, usdc, recipient, refundTo, now = Date.now() }) {
  check(/^0x[0-9a-fA-F]{40}$/.test(recipient), "recipient must be this page's wallet");
  check(typeof refundTo === "string" && refundTo.trim().length > 0, "a refund address on the paying chain is required");
  return { dry: false, swapType: "EXACT_OUTPUT", slippageTolerance: 100, originAsset, depositType: "ORIGIN_CHAIN",
    destinationAsset: BASE_USDC, amount: String(units(usdc)), refundTo: refundTo.trim(), refundType: "ORIGIN_CHAIN",
    recipient, recipientType: "DESTINATION_CHAIN", deadline: new Date(Math.floor(now / 1000) * 1000 + 3600000).toISOString() };
}

// Refuses a quote unless 1Click signed it and it pays exactly what was asked to the page's wallet in time to use it.
export async function checkQuote(raw, request, { decimals, sentAt, now = Date.now() }) {
  const response = JSON.parse(raw), r = response.quoteRequest, q = response.quote;
  check(r && q && typeof response.signature === "string", response.message || "no quote in the reply");
  for (const k of REQUEST) check(r[k] === request[k], `${k} differs from the request`);
  const fee = (r.appFees ?? []).reduce((s, f) => s + f.fee, 0);
  check(fee <= MAX_FEE_BPS, `fees of ${fee} bps exceed ${MAX_FEE_BPS}`);
  const out = units(q.amountOut), wanted = units(request.amount);
  check(out === wanted && units(q.minAmountOut) === wanted, "output differs from the requested USDC");
  const amountIn = units(q.amountIn);
  check(units(q.minAmountIn) <= amountIn, "minimum input above input");
  formatted(q.amountInFormatted, amountIn, decimals);
  check(typeof q.depositAddress === "string" && q.depositAddress.length > 0, "no deposit address");
  const stamp = Date.parse(response.timestamp), deadline = Date.parse(q.deadline);
  check(stamp >= sentAt - 30000 && stamp <= now + 30000 && now - stamp <= 120000, "quote timestamp is not fresh");
  check(deadline >= Date.parse(request.deadline), "deadline earlier than requested");
  check(deadline - now >= Math.ceil(q.timeEstimate * 1000) + 600000, "too little time left to pay");
  check(await verifySignature(response), "1Click's signature does not verify");
  return { depositAddress: q.depositAddress, depositMemo: q.depositMemo ?? null, amountIn: q.amountIn,
    amountInFormatted: q.amountInFormatted, amountInUsd: q.amountInUsd, amountOut: q.amountOut, deadline: q.deadline,
    timeEstimate: q.timeEstimate, refundFee: q.refundFee, feeBps: fee, correlationId: response.correlationId };
}

// Tokens 1Click accepts, without the destination itself.
export async function tokens(fetcher = fetch) {
  const r = await fetcher(API + "/tokens");
  check(r.ok, `token list HTTP ${r.status}`);
  return (await r.json()).filter((t) => t.assetId !== BASE_USDC && t.price > 0)
    .sort((a, b) => a.symbol.localeCompare(b.symbol) || a.blockchain.localeCompare(b.blockchain));
}

export async function quote(args, { decimals, fetcher = fetch, now = Date.now } = {}) {
  const request = quoteRequest({ ...args, now: now() }), sentAt = now();
  const r = await fetcher(API + "/quote", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request) });
  const raw = await r.text();
  check(r.ok, `HTTP ${r.status} ${raw.slice(0, 200)}`);
  return { ...(await checkQuote(raw, request, { decimals, sentAt, now: now() })), request };
}

// 1Click's own view of the swap: PENDING_DEPOSIT, KNOWN_DEPOSIT_TX, PROCESSING, SUCCESS, INCOMPLETE_DEPOSIT, REFUNDED, FAILED.
export async function swapStatus(depositAddress, fetcher = fetch) {
  const r = await fetcher(API + "/status?" + new URLSearchParams({ depositAddress }));
  check(r.ok, `status HTTP ${r.status}`);
  return r.json();
}

// USDC balance on Base mainnet, read through a chainRead({ network: "base" }) snapshot so Helios verifies it.
export async function baseUsdcBalance(reader, address) {
  const s = await reader.snapshot();
  const b = await s.call(BASE_USDC_CONTRACT, "0x70a08231" + address.slice(2).toLowerCase().padStart(64, "0"));
  return { units: BigInt("0x" + (Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("") || "0")), block: s.block };
}
