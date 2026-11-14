import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { checkQuote, quoteRequest, BASE_USDC } from "./intents-funding.mjs";

// An issued ZEC -> 5 USDC (Base) quote recorded from 1Click on 2026-11-11; nothing was paid into it.
const f = JSON.parse(await readFile(new URL("./test-fixtures/intents/zec-to-base-usdc.json", import.meta.url)));
const at = { decimals: 8, sentAt: f.sentAt, now: f.sentAt + 1000 };
const edit = (fn) => { const r = JSON.parse(f.raw); fn(r); return JSON.stringify(r); };

test("an issued quote that 1Click signed and that pays the asked USDC to the wallet is accepted", async () => {
  const q = await checkQuote(f.raw, f.request, at);
  assert.equal(q.amountOut, "5000000");
  assert.ok(q.depositAddress.startsWith("t1"));
  assert.equal(f.request.destinationAsset, BASE_USDC);
});

test("a quote is refused if any signed field changed, the recipient or amount differs, or it is stale", async () => {
  await assert.rejects(checkQuote(edit((r) => { r.quote.depositAddress = "t1KfwsnwJeNRVjQGBDZhwKskpQbih2qx5Ua"; }), f.request, at), /signature/);
  await assert.rejects(checkQuote(f.raw, { ...f.request, recipient: "0x2222222222222222222222222222222222222222" }, at), /recipient differs/);
  await assert.rejects(checkQuote(edit((r) => { r.quote.amountOut = "4000000"; }), f.request, at), /output differs/);
  await assert.rejects(checkQuote(f.raw, f.request, { ...at, now: f.sentAt + 3600000 }), /fresh|time left/);
});

test("the request pays this wallet exactly, with a refund address and a deadline on a whole second", () => {
  const r = quoteRequest({ originAsset: "nep141:zec.omft.near", usdc: "1000000", recipient: "0x1111111111111111111111111111111111111111", refundTo: " t1abc ", now: 1794426000123 });
  assert.equal(r.swapType, "EXACT_OUTPUT");
  assert.equal(r.refundTo, "t1abc");
  assert.equal(r.deadline, "2026-11-11T20:40:00.000Z");
  assert.throws(() => quoteRequest({ originAsset: "x", usdc: "1", recipient: "alice.near", refundTo: "t1" }), /this page's wallet/);
});
