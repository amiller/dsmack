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
import { Quorum } from "./quorum.mjs";
import { linkedOperator } from "./mac-operator.mjs";
import { ownershipDomain, ownershipTypes } from "../relay-broker/ownership.mjs";

test("escrow registration refuses a broker that changes the linked operator", async () => {
  const publisher = Wallet.createRandom(), operator = Wallet.createRandom();
  const escrow = "0x" + "12".repeat(20), kid = "0x" + "34".repeat(32);
  const domain = ownershipDomain(escrow);
  const link = { kid, publisher: publisher.address, operator: operator.address, nonce: "0" };
  const record = { link,
    publisherSignature: await publisher.signTypedData(domain, { MacLink: ownershipTypes.MacLink }, link),
    operatorSignature: await operator.signTypedData(domain, { MacLink: ownershipTypes.MacLink }, link) };
  const response = { domain, links: [record] };
  assert.equal(linkedOperator(response, escrow, publisher.address, kid), operator.address.toLowerCase());
  assert.throws(() => linkedOperator({ ...response, links: [{ ...record,
    link: { ...link, operator: Wallet.createRandom().address } }] }, escrow, publisher.address, kid), /signature/);
});

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
function rpc(overrides = {}, rpcs = cfg.rpcs, extra = {}) {
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
  return { q: new Quorum({ ...cfg, ...extra, rpcs, now: () => now, fetcher }), calls, block };
}
test("quorum requires a strict majority of configured hosts, including failed hosts", async () => {
  for (const count of [4, 5]) {
    const rpcs = Array.from({ length: count }, (_, i) => `https://p${i}.example`);
    const votes = agree => rpc({ eth_getCode: url => rpcs.indexOf(url) < agree ? code : "0x6001" }, rpcs).q.snapshot();
    await votes(3);
    await assert.rejects(votes(2), /quorum disagreement|code mismatch/);
    await assert.rejects(rpc({ eth_getCode: url => {
      if (rpcs.indexOf(url) >= 2) throw Error("offline");
      return code;
    } }, rpcs).q.snapshot(), /quorum disagreement/);
  }
});
test("quorum freezes calls to a common finalized hash and tolerates one wrong provider", async () => {
  const { q, calls, block } = rpc({
    eth_getBlockByNumber: (url, _, value) => ({
      ...value,
      providerMetadata: url,
    }),
    eth_call: (url, _, value) =>
      url.includes("c.invalid")
        ? abi.encodeFunctionResult("deposits", [900])
        : value,
  });
  const s = await q.snapshot();
  assert.equal(await s.call("deposits", [escrow]), 123n);
  for (
    const c of calls.filter((c) =>
      ["eth_getCode", "eth_call"].includes(c.method)
    )
  ) {
    assert.deepEqual(c.params[1], {
      blockHash: block.hash,
      requireCanonical: true,
    });
  }
});
test("stale, wrong chain, changed code and split state cannot mint credit", async () => {
  await assert.rejects(
    rpc({ eth_getBlockByNumber: (_, __, v) => ({ ...v, timestamp: "0x1" }) }).q
      .snapshot(),
    /stale/,
  );
  await assert.rejects(
    rpc({ eth_chainId: () => "0x1" }).q.snapshot(),
    /quorum unavailable/,
  );
  await assert.rejects(
    rpc({ eth_getCode: () => "0x6001" }).q.snapshot(),
    /code mismatch/,
  );
  const s = await rpc({
    eth_call: (url) =>
      abi.encodeFunctionResult("deposits", [
        url.includes("a.invalid") ? 1 : url.includes("b.invalid") ? 2 : 3,
      ]),
  }).q.snapshot();
  await assert.rejects(s.call("deposits", [escrow]), /quorum disagreement/);
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

test("a provider with a lagging finalized tag can corroborate state at the quorum-pinned hash", async () => {
  const { q } = rpc({
    eth_getBlockByNumber: (url, params, value) =>
      url.includes("c.invalid") && params[0] === "finalized"
        ? { ...value, number: "0x10" }
        : value,
    eth_getCode: (url, _, value) => {
      if (url.includes("b.invalid")) throw Error("data backend unavailable");
      return value;
    },
  });
  assert.equal((await q.snapshot()).block.number, "0x20");
});

test("a staging quorum reads the safe head and refuses any other shallow tag", async () => {
  const { q, calls } = rpc({}, cfg.rpcs, { blockTag: "safe" });
  await q.snapshot();
  assert.deepEqual([...new Set(calls.filter((c) => c.method === "eth_getBlockByNumber").map((c) => c.params[0]))], ["safe", "0x20"]);
  assert.throws(() => rpc({}, cfg.rpcs, { blockTag: "latest" }), /blockTag must be finalized or safe/);
});

test("two matching state replies complete without waiting for a stalled third provider", async () => {
  let cancelled = false;
  const base = rpc();
  const fetcher = async (url, opts) => {
    const query = JSON.parse(opts.body);
    if (url.includes("c.invalid") && query.method === "eth_getCode") {
      return await new Promise((_, reject) =>
        opts.signal.addEventListener("abort", () => {
          cancelled = true;
          reject(Error("aborted"));
        }, { once: true })
      );
    }
    let result = query.method === "eth_chainId"
      ? "0x14a34"
      : query.method === "eth_getBlockByNumber"
      ? base.block
      : code;
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  };
  const q = new Quorum({ ...cfg, now: () => now, fetcher });
  await q.snapshot();
  assert.equal(cancelled, true);
});
