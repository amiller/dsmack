import assert from "node:assert/strict";
import { test } from "node:test";
import { RpcClient } from "./rpc.mjs";

const rpcs = ["https://one.invalid", "https://two.invalid", "https://three.invalid"];
test("HTTP 429 cools one provider, honors Retry-After and allows one healthy provider", async () => {
  let now = 100000, throttles = 0;
  const calls = [];
  const rpc = new RpcClient({ rpcs, now: () => now, fetcher: async (url, opts) => {
    const { method } = JSON.parse(opts.body); calls.push([url, method]);
    if (url === rpcs[0]) { throttles++; return new Response("limited", { status: 429, headers: { "retry-after": "10" } }); }
    if (url === rpcs[1]) throw Error("offline");
    return Response.json({ result: method === "eth_chainId" ? "0x14a34" : "0x12" });
  } });
  assert.equal(await rpc.request("eth_blockNumber", []), "0x12");
  assert.equal(await rpc.request("eth_blockNumber", []), "0x12");
  assert.equal(throttles, 1);
  now += 10000;
  await rpc.request("eth_blockNumber", []);
  assert.equal(throttles, 2);
  assert.ok(calls.some(([url, method]) => url === rpcs[2] && method === "eth_blockNumber"));
});

test("JSON RPC quotas back off exponentially, reset after success and fail when all are cooling", async () => {
  let now = 0, limited = true, attempts = 0;
  const rpc = new RpcClient({ rpcs: [rpcs[0]], now: () => now, fetcher: async (_url, opts) => {
    const { method } = JSON.parse(opts.body);
    if (method === "eth_chainId") return Response.json({ result: "0x14a34" });
    attempts++;
    return Response.json(limited ? { error: { code: -32005, message: "quota" } } : { result: "0x1" });
  } });
  await assert.rejects(rpc.request("eth_blockNumber", []), /RPC unavailable/);
  now = 999;
  await assert.rejects(rpc.request("eth_blockNumber", []), /cooling down/);
  assert.equal(attempts, 1);
  now = 1000;
  await assert.rejects(rpc.request("eth_blockNumber", []));
  now = 2999;
  await assert.rejects(rpc.request("eth_blockNumber", []), /cooling down/);
  assert.equal(attempts, 2);
  now = 3000; limited = false;
  assert.equal(await rpc.request("eth_blockNumber", []), "0x1");
  limited = true;
  await assert.rejects(rpc.request("eth_blockNumber", []));
  now = 4000; limited = false;
  assert.equal(await rpc.request("eth_blockNumber", []), "0x1");
});

test("wrong-chain responses cannot reach a read, and a contract revert is never retried", async () => {
  const calls = [];
  const rpc = new RpcClient({ rpcs, fetcher: async (url, opts) => {
    const { method } = JSON.parse(opts.body); calls.push([url, method]);
    return Response.json(method === "eth_chainId"
      ? { result: url === rpcs[0] ? "0x2105" : "0x14a34" }
      : { error: { code: 3, message: "execution reverted" } });
  } });
  await assert.rejects(rpc.request("eth_call", []), /execution reverted/);
  assert.deepEqual(calls, [[rpcs[0], "eth_chainId"], [rpcs[1], "eth_chainId"], [rpcs[1], "eth_call"]]);
});
