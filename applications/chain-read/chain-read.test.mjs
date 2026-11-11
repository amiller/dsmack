// The loader's plumbing around Helios: a fake Helios that passes reads straight to its execution URL and fetches the
// consensus head, so source order, failure reports, the wallet bridge, relay order, head lag and the snapshot cache are
// exercised without a sequencer-signed head. check.mjs runs the real Helios against live sources.
import test from "node:test";
import assert from "node:assert/strict";
import { chainRead, aggregate3 } from "./chain-read.mjs";

const word = (n) => n.toString(16).padStart(64, "0");
const ret = (datas) => "0x" + word(0x20) + word(datas.length) + datas.map((_, i) => word(32 * datas.length + 160 * i)).join("")
  + datas.map((d) => word(1) + word(0x40) + word(32) + d).join("");
const BLOCK = { number: "0x10", hash: "0x" + "ab".repeat(32), timestamp: "0x5" };
const A = "0x" + "11".repeat(20), B = "0x" + "22".repeat(20);

const seen = [];
const answer = (method, params) => {
  if (method === "eth_getBlockByNumber") return BLOCK;
  if (method === "eth_chainId") return "0x14a34";
  if (params[0].to === "0xcA11bde05977b3631167028862bE2a173976CA11") return ret(params[0].data === aggregate3([[A, "0x01"], [B, "0x02"]]) ? [word(1), word(2)] : [word(3)]);
  return "0x" + word(9);
};
globalThis.fetch = async (url, init) => {
  url = String(url);
  seen.push(url);
  if (url === "https://down.test/latest") throw new Error("relay down");
  if (url === "https://relay.test/latest") return new Response('{"data":"0xhead"}');
  if (url === "https://bad.test/") return new Response("busy", { status: 503 });
  const r = JSON.parse(init.body);
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: r.id, result: answer(r.method, r.params) }));
};
const fakeHelios = async ({ executionRpc, network }) => ({
  waitSynced: async () => { await fetch(`https://${network}.operationsolarstorm.org/latest`); },
  request: async (req) => {
    const r = await fetch(executionRpc, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, ...req }) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    if (j.error) throw new Error(j.error.message);
    return j.result;
  },
  shutdown: async () => {},
});
const open = (o) => chainRead({ relays: ["https://down.test", "https://relay.test"], helios: fakeHelios, lagSeconds: 0, wallet: null, ...o });

test("tries sources in order, reports each failure and caches per block", async () => {
  seen.length = 0;
  const cr = await open({ sources: [{ url: "https://bad.test/", name: "bad" }, { url: "https://good.test/", name: "good" }] });
  const s = await cr.snapshot();
  assert.deepEqual(s.block, { number: 16, hash: BLOCK.hash, timestamp: 5 });
  const [a, b] = await s.multicall([[A, "0x01"], [B, "0x02"]]);
  assert.deepEqual([a[31], b[31]], [1, 2]);
  assert.equal((await s.call(B, "0x02"))[31], 2);
  await s.multicall([[A, "0x01"]]);
  assert.deepEqual(cr.diagnostics.reads.map((r) => [r.method, r.source, r.failures]), [
    ["eth_getBlockByNumber", "good", [{ source: "bad", error: "HTTP 503" }]],
    ["eth_call", "good", [{ source: "bad", error: "HTTP 503" }]],
  ]);
  assert.deepEqual(cr.diagnostics.relays["https://down.test"], { ok: 0, failed: 1, error: "relay down" });
  assert.equal(seen.filter((u) => u === "https://good.test/").length, 2);
  await cr.close();
});

test("a read that fails everywhere rejects with every failure", async () => {
  const cr = await open({ sources: [{ url: "https://bad.test/", name: "bad" }] });
  await assert.rejects(cr.snapshot(), (e) => e.failures.length === 1 && /bad: HTTP 503/.test(e.message));
  await cr.close();
});

test("a wallet is used only on the right chain and only for reads", async () => {
  const calls = [];
  const wallet = (chain) => ({ request: async ({ method, params }) => { calls.push(method); return method === "eth_chainId" ? chain : answer(method, params); } });
  const wrong = await open({ sources: [{ name: "wallet", provider: wallet("0x1") }, { url: "https://good.test/", name: "good" }] });
  assert.deepEqual(wrong.diagnostics.skipped, [{ source: "wallet", reason: "on chain 1, not base-sepolia" }]);
  assert.deepEqual(wrong.sources, ["good"]);
  await wrong.close();
  const cr = await open({ sources: [{ name: "wallet", provider: wallet("0x14a34") }] });
  assert.equal((await (await cr.snapshot()).call(A, "0x03"))[31], 9);
  await assert.rejects(cr.read("eth_sendRawTransaction", ["0x00"]), /eth_sendRawTransaction is not a read/);
  assert.deepEqual(calls, ["eth_chainId", "eth_chainId", "eth_getBlockByNumber", "eth_call"]);
  await cr.close();
});

test("the first head is held back until it is lagSeconds old", async () => {
  const t = Date.now();
  const cr = await open({ sources: [{ url: "https://good.test/" }], lagSeconds: 0.3 });
  assert.ok(Date.now() - t >= 300);
  await cr.close();
});
