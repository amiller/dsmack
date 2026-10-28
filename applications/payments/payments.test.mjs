import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  abi,
  binding,
  domain,
  json,
  keccak256,
  Receipt,
  receiptSigner,
  TypedDataEncoder,
  Wallet,
} from "./schema.mjs";
import { Quorum } from "./quorum.mjs";
import { Payments } from "../relay-broker/payments.mjs";
import { grantBytes } from "../relay-broker/grants.mjs";

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
function rpc(overrides = {}) {
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
      ? abi.encodeFunctionResult("quote", [123])
      : null;
    if (overrides[method]) result = overrides[method](url, params, result);
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  };
  return { q: new Quorum({ ...cfg, now: () => now, fetcher }), calls, block };
}
test("quorum freezes calls to a common finalized hash and tolerates one wrong provider", async () => {
  const { q, calls, block } = rpc({
    eth_getBlockByNumber: (url, _, value) => ({
      ...value,
      providerMetadata: url,
    }),
    eth_call: (url, _, value) =>
      url.includes("c.invalid")
        ? abi.encodeFunctionResult("quote", [900])
        : value,
  });
  const s = await q.snapshot();
  assert.equal(await s.call("quote", [zero]), 123n);
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
      abi.encodeFunctionResult("quote", [
        url.includes("a.invalid") ? 1 : url.includes("b.invalid") ? 2 : 3,
      ]),
  }).q.snapshot();
  await assert.rejects(s.call("quote", [zero]), /quorum disagreement/);
});
test("Purchase event must be canonical and match finalized state", async () => {
  const payer = Wallet.createRandom().address;
  const event = abi.encodeEventLog(abi.getEvent("Purchase"), [
    1,
    zero,
    payer,
    "0x" + "01".repeat(32),
    1,
    4,
    1000,
    now + 3600,
  ]);
  const p = {
    node: zero,
    payer,
    buyerKey: "0x" + "01".repeat(32),
    unit: 1n,
    amount: 4n,
    price: 1000n,
    expires: BigInt(now + 3600),
    closed: false,
  };
  let receipt = {
    status: "0x1",
    blockNumber: "0x20",
    blockHash: "0x" + "aa".repeat(32),
    logs: [{ address: escrow, ...event }],
  };
  const s = {
    block: { number: "0x20" },
    read: (method) =>
      method === "eth_getTransactionReceipt"
        ? receipt
        : { hash: receipt.blockHash },
    call: () => p,
  };
  const q = new Quorum(cfg), tx = "0x" + "99".repeat(32);
  assert.equal((await q.purchase(s, "1", tx)).amount, 4n);
  p.amount = 5n;
  await assert.rejects(q.purchase(s, "1", tx), /event\/state mismatch/);
  p.amount = 4n;
  receipt = { ...receipt, blockNumber: "0x21" };
  await assert.rejects(q.purchase(s, "1", tx), /not finalized/);
});
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let n = BigInt("0x" + Buffer.from(bytes).toString("hex")), s = "";
  while (n) {
    s = alphabet[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}
test("paid grants require buyer control and persist fixed deadlines before returning", async () => {
  const pair = generateKeyPairSync("ed25519"),
    pub = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const client_peer = base58(
    Buffer.concat([Buffer.from("002408011220", "hex"), pub]),
  );
  const key = Wallet.createRandom(),
    p = {
      node: zero,
      buyerKey: "0x" + pub.toString("hex"),
      unit: 1,
      amount: 4n,
      boughtAt: now - 10,
      expires: now + 3600,
      closed: false,
    };
  const payment = {
    escrow,
    node: zero,
    operator: key.address,
    receiptSigner: Wallet.createRandom().address,
    buildId: zero,
    runExpires: now + 3600,
  };
  const node = {
    relay_peer: client_peer,
    manifest_sha256: zero.slice(2),
    os_image_hash: zero.slice(2),
    payments: payment,
  };
  const n = {
    runExpires: now + 3600,
    attestationHash: binding(
      payment,
      client_peer,
      node.manifest_sha256,
      node.os_image_hash,
    ),
  };
  const snapshot = { block: { hash: zero }, call: () => n };
  const chain = { snapshot: () => snapshot, purchase: () => p };
  let saved;
  const broker = new Payments({
    cfg,
    key,
    quorum: chain,
    now: () => now,
    save: (state) => {
      saved = structuredClone(state);
    },
  });
  broker.checkNode = async () => {}; // Apple assertion boundary is covered separately by broker.test.mjs.
  const fields = {
    client_peer,
    purchaseId: "1",
    txHash: "0x" + "bb".repeat(32),
  };
  const request = {
    ...fields,
    sig: sign(null, grantBytes(fields), pair.privateKey).toString("hex"),
  };
  const result = await broker.grant(request, [node]);
  assert.equal(saved.grants["1"].envelope.grant.serviceUntil, now + 600);
  assert.equal(result.grant.buyerKey, p.buyerKey);
  const restarted = new Payments({
    cfg,
    key,
    state: saved,
    quorum: chain,
    now: () => now + 30,
    save: () => {
      throw Error("unexpected write");
    },
  });
  restarted.checkNode = async () => {};
  assert.deepEqual(await restarted.grant(request, [node]), result);
  broker.save = () => {
    throw Error("disk full");
  };
  delete broker.state.grants["1"];
  await assert.rejects(broker.grant(request, [node]), /disk full/);
  request.sig = "00".repeat(64);
  await assert.rejects(
    broker.grant(request, [node]),
    /buyer grant request signature/,
  );
});
const evidence = Deno.env.get("PAYMENTS_EVIDENCE");
if (evidence) {
  test("Go receipt and binding agree with ethers EIP-712", async () => {
    const f = JSON.parse(
      await Deno.readTextFile(evidence + "/guest-interop.json"),
    );
    assert.equal(
      receiptSigner(f.escrow, f.receipt).toLowerCase(),
      f.registration.receiptSigner.toLowerCase(),
    );
    assert.equal(
      TypedDataEncoder.hash(domain(f.escrow), {
        Receipt: (await import("./schema.mjs")).Receipt,
      }, f.receipt.receipt),
      f.receiptDigest,
    );
    assert.equal(binding(f.registration, f.peer, zero, zero), f.binding);
    console.log(
      json({
        guestSigner: f.registration.receiptSigner,
        receiptDigest: f.receiptDigest,
        used: f.receipt.receipt.used,
      }),
    );
  });
}

test("receipt storage rejects forged, regressing and over-budget usage before acknowledgement", async () => {
  const signer = Wallet.createRandom(), coordinator = Wallet.createRandom();
  const purchase = {
    receiptSigner: signer.address,
    amount: "4",
    boughtAt: String(now - 20),
    expires: String(now + 100),
  };
  let saved;
  const b = new Payments({
    cfg,
    key: coordinator,
    state: { grants: { "1": { purchase } }, receipts: {} },
    now: () => now,
    quorum: {
      snapshot: () => {
        throw Error("immutable cached purchase should avoid RPC");
      },
    },
    save: (s) => {
      saved = structuredClone(s);
    },
  });
  const signed = async (sequence, used, finalReceipt = false, key = signer) => {
    const receipt = {
      purchaseId: "1",
      sequence,
      used,
      endedAt: now,
      finalReceipt,
    };
    return {
      receipt,
      signature: await key.signTypedData(domain(escrow), { Receipt }, receipt),
    };
  };
  await assert.rejects(
    b.collect(await signed(1, "1", false, coordinator)),
    /registered guest receipt signer/,
  );
  await b.collect(await signed(1, "1"));
  assert.equal(saved.receipts["1"].receipt.used, "1");
  await assert.rejects(b.collect(await signed(2, "5")), /receipt bounds/);
  await assert.rejects(b.collect(await signed(2, "0")), /regressed/);
  const final = await signed(2, "2", true);
  await b.collect(final);
  const reordered = {
    signature: final.signature,
    receipt: Object.fromEntries(Object.entries(final.receipt).reverse()),
  };
  assert.deepEqual(await b.collect(reordered), { stored: true });
  await assert.rejects(b.collect(await signed(3, "3")), /already final/);
});

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
