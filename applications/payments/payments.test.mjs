import { test } from "node:test";
import assert from "node:assert/strict";
import {
  abi,
  receiptDomain,
  json,
  keccak256,
  receiptSigner,
  TypedDataEncoder,
  Wallet,
} from "./schema.mjs";
import { ChainReader } from "./chain-reader.mjs";

const now = 2000000000,
  zero = "0x" + "00".repeat(32),
  escrow = "0x1000000000000000000000000000000000000001";
const code = "0x6000",
  cfg = {
    escrow,
    codeHash: keccak256(code),
    rpcs: ["https://a.invalid", "https://b.invalid", "https://c.invalid"],
    destinationPolicyHash: zero,
  };
function rpc(overrides = {}, rpcs = cfg.rpcs) {
  const block = {
    number: "0x20",
    hash: "0x" + "aa".repeat(32),
    timestamp: "0x" + (now - 10).toString(16),
  };
  const calls = [];
  const fetcher = (url, opts) => {
    const { method, params } = JSON.parse(opts.body);
    calls.push({ url, method, params });
    let result = method === "eth_chainId"
      ? "0x14a34"
      : method === "eth_getBlockByNumber"
      ? block
      : method === "eth_getCode"
      ? code
      : method === "eth_call"
      ? abi.encodeFunctionResult("deposits", [123])
      : null;
    if (overrides[method]) result = overrides[method](url, params, result);
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  };
  return { q: new ChainReader({ ...cfg, rpcs, now: () => now, fetcher }), calls, block };
}
test("one healthy provider supplies a hash-pinned finalized snapshot", async () => {
  const { q, calls, block } = rpc({ eth_chainId: url => {
    if (!url.includes("c.invalid")) throw Error("offline");
    return "0x14a34";
  } });
  const s = await q.snapshot();
  assert.equal(await s.call("deposits", [escrow]), 123n);
  for (const c of calls.filter(c => ["eth_getCode", "eth_call"].includes(c.method))) {
    assert.deepEqual(c.params[1], { blockHash: block.hash, requireCanonical: true });
  }
});

test("stale or wrong-chain providers cannot supply state, and changed code stops credit", async () => {
  await assert.rejects(rpc({ eth_getBlockByNumber: (_, __, v) => ({ ...v, timestamp: "0x1" }) }).q.snapshot(), /stale/);
  await assert.rejects(rpc({ eth_chainId: () => "0x2105" }).q.snapshot(), /Base Sepolia/);
  await assert.rejects(rpc({ eth_getCode: () => "0x6001" }).q.snapshot(), /code mismatch/);
  const { q } = rpc({ eth_getBlockByNumber: (url, _, v) => url.includes("a.invalid") ? { ...v, timestamp: "0x1" } : v });
  assert.equal((await q.snapshot()).block.number, "0x20");
});

test("state failover rejects a different hash or height at the pinned block", async () => {
  for (const changed of [{ hash: "0x" + "bb".repeat(32) }, { number: "0x21" }]) {
    const { q } = rpc({
      eth_call: () => { throw Error("offline"); },
      eth_getBlockByNumber: (url, _, v) => url.includes("a.invalid") ? v : { ...v, ...changed },
    });
    const s = await q.snapshot();
    await assert.rejects(s.call("deposits", [escrow]), /snapshot block changed/);
  }
});

test("a lagging provider can serve the pinned block during state failover", async () => {
  const { q } = rpc({
    eth_getBlockByNumber: (url, params, v) => url.includes("b.invalid") && params[0] === "finalized" ? { ...v, number: "0x10" } : v,
    eth_call: (url, _, v) => { if (url.includes("a.invalid")) throw Error("offline"); return v; },
  });
  const s = await q.snapshot();
  assert.equal(await s.call("deposits", [escrow]), 123n);
});

test("quota failure during a snapshot moves state reads to one matching provider", async () => {
  const { q } = rpc(), fetcher = q.rpc.fetcher;
  let limited = 0;
  q.rpc.fetcher = (url, opts) => {
    const { method } = JSON.parse(opts.body);
    if (url.includes("a.invalid") && method === "eth_call") {
      limited++;
      return new Response("quota", { status: 429 });
    }
    if (url.includes("c.invalid")) throw Error("offline");
    return fetcher(url, opts);
  };
  const s = await q.snapshot();
  assert.equal(await s.call("deposits", [escrow]), 123n);
  assert.equal(await s.call("deposits", [escrow]), 123n);
  assert.equal(limited, 1);
});
const evidence = Deno.env.get("PAYMENTS_EVIDENCE");
if (evidence) {
  test("Go receipt agrees with ethers EIP-712", async () => {
    const f = JSON.parse(
      await Deno.readTextFile(evidence + "/guest-interop.json"),
    );
    assert.equal(
      receiptSigner(f.escrow, f.receipt).toLowerCase(),
      f.registration.receiptSigner.toLowerCase(),
    );
    assert.equal(
      TypedDataEncoder.hash(receiptDomain(f.escrow), {
        Receipt: (await import("./schema.mjs")).Receipt,
      }, f.receipt.receipt),
      f.receiptDigest,
    );
    assert.equal((await import("../compute-node/browser/payments.mjs")).paidReceiptKey(f.registration).length, 33);
    console.log(
      json({
        guestSigner: f.registration.receiptSigner,
        receiptDigest: f.receiptDigest,
        used: f.receipt.receipt.used,
      }),
    );
  });
}
