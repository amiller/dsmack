import assert from "node:assert/strict";
import { test } from "node:test";
import { RpcClient } from "../payments/rpc.mjs";
import { rpcChain } from "../../dstack-compat/secret-release/policy.mjs";

test("attestation chain reads use a healthy provider while the first is cooling down", async () => {
  const calls = [], rpcs = ["https://one.invalid", "https://two.invalid"];
  const rpc = new RpcClient({ rpcs, fetcher: async (url, opts) => {
    const { method } = JSON.parse(opts.body); calls.push([url, method]);
    if (url === rpcs[0]) return new Response("quota", { status: 429 });
    return Response.json({ result: method === "eth_chainId" ? "0x14a34" : "0x" + "0".repeat(63) + "1" });
  } });
  const chain = rpcChain(rpcs[0], "attest", "canary", (method, params) => rpc.request(method, params));
  assert.equal(await chain.category(), 1);
  assert.equal(await chain.burnedImage(new Uint8Array(32)), true);
  assert.deepEqual(calls, [[rpcs[0], "eth_chainId"], [rpcs[1], "eth_chainId"], [rpcs[1], "eth_call"], [rpcs[1], "eth_call"]]);
});
