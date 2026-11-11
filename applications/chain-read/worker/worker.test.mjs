import test from "node:test";
import assert from "node:assert/strict";
import worker from "./worker.mjs";

const RPC = "https://upstream.test/v2/SECRET";
const env = (allow = true) => ({ RPC_URL: RPC, RELAY_URL: "https://relay.test/", LIMITER: { limit: async () => ({ success: allow }) } });
const upstream = [];
globalThis.fetch = async (url, init) => {
  upstream.push({ url, body: init?.body && JSON.parse(init.body) });
  if (url === "https://relay.test/latest") return new Response('{"data":"0x01"}');
  const one = (r) => ({ jsonrpc: "2.0", id: r.id, result: "0x" + r.method }), req = JSON.parse(init.body);
  return new Response(JSON.stringify(Array.isArray(req) ? req.map(one) : one(req)));
};
const post = (body, e = env()) => worker.fetch(new Request("https://site.test/chain-read/rpc", { method: "POST", body: JSON.stringify(body) }), e);

test("forwards allowed reads and answers others with an error, single and batch", async () => {
  upstream.length = 0;
  const r = await post({ jsonrpc: "2.0", id: 7, method: "eth_getProof", params: [] });
  assert.equal(r.headers.get("access-control-allow-origin"), "*");
  assert.deepEqual(await r.json(), { jsonrpc: "2.0", id: 7, result: "0xeth_getProof" });
  const b = await (await post([{ id: 1, method: "eth_call" }, { id: 2, method: "eth_sendRawTransaction" }, { id: 3, method: "eth_chainId" }])).json();
  assert.deepEqual(b.map((x) => [x.id, x.result ?? x.error.message]),
    [[1, "0xeth_call"], [3, "0xeth_chainId"], [2, "method not allowed: eth_sendRawTransaction"]]);
  assert.deepEqual(upstream.map((u) => [u.body].flat().map((x) => x.method)), [["eth_getProof"], ["eth_call", "eth_chainId"]]);
  assert.ok(!Array.isArray(upstream[0].body));
  const d = await (await post({ id: 4, method: "debug_traceCall" })).json();
  assert.equal(d.error.code, -32601);
  assert.equal(upstream.length, 2);
});

test("preflight, relay proxy, rate limit, and the key never appears in a response", async () => {
  const pre = await worker.fetch(new Request("https://site.test/chain-read/rpc", { method: "OPTIONS" }), env());
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-methods"), "GET, POST, OPTIONS");
  const l = await worker.fetch(new Request("https://site.test/chain-read/latest"), env());
  assert.equal(await l.text(), '{"data":"0x01"}');
  assert.equal(l.headers.get("access-control-allow-origin"), "*");
  const limited = await post({ id: 1, method: "eth_call" }, env(false));
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("access-control-allow-origin"), "*");
  globalThis.fetch = async () => new Response("slow down", { status: 429 });
  const busy = await post({ id: 1, method: "eth_call" });
  assert.deepEqual([busy.status, await busy.text()], [429, "slow down"]);
  globalThis.fetch = async () => { throw new Error(`connect ${RPC} failed`); };
  const down = await post({ id: 1, method: "eth_call" });
  assert.equal(down.status, 502);
  assert.ok(!(await down.text()).includes("SECRET"));
});
