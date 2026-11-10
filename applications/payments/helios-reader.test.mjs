import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256 } from "./schema.mjs";
import { HeliosReader, sharedSnapshots } from "./helios-reader.mjs";

const escrow = "0x" + "35".repeat(20), code = "0x6000", CHAIN_READ = "https://chain.invalid/layover-chain";
// layover-chain whose head advances one block per /head; `fail` makes the next /head refuse. Counts fetches per path.
function chain() {
  const c = { head: 1000, fetches: [], fail: false };
  globalThis.fetch = async (url) => {
    const u = new URL(url), q = (k) => u.searchParams.get(k), path = u.pathname.split("/").pop();
    c.fetches.push(path + " " + (q("data") ?? q("address") ?? ""));
    if (path === "head") {
      if (c.fail) return Response.json({ error: "helios down" }, { status: 502 });
      c.head++;
      return Response.json({ block: c.head - 30, block_hash: "0x" + (c.head - 30).toString(16).padStart(64, "0"), depth: 30, head: c.head, head_age_s: 2, verified_by: "helios-opstack" });
    }
    const pin = { block_hash: q("block"), verified_by: "helios-opstack" };
    return Response.json(path === "code" ? { ...pin, code } : { ...pin, result: "0x" + q("data").slice(2).padStart(64, "0") });
  };
  return c;
}
const reader = () => new HeliosReader({ escrow, codeHash: keccak256(code), chainRead: CHAIN_READ });
const calls = (c) => c.fetches.filter((f) => f.startsWith("call")).length;

test("a snapshot fetches each read once", async () => {
  const c = chain(), s = await reader().snapshot();
  await Promise.all([s.read("eth_call", [{ to: escrow, data: "0x01" }]), s.read("eth_call", [{ to: escrow, data: "0x01" }]),
    s.read("eth_call", [{ to: escrow, data: "0x02" }])]);
  await s.read("eth_call", [{ to: escrow, data: "0x01" }]);
  assert.equal(calls(c), 2);
});

test("callers share a snapshot for `seconds`; the next replays the previous reads before it is served", async () => {
  const c = chain();
  let t = 0;
  const shared = sharedSnapshots(reader(), 30, () => t);
  const a = await shared.snapshot();
  await a.read("eth_call", [{ to: escrow, data: "0x01" }]);
  t = 29;
  assert.equal(await shared.snapshot(), a);
  assert.equal(c.fetches.filter((f) => f.startsWith("head")).length, 1);

  // Past `seconds` the caller still gets the warm snapshot while the next one is built and warmed.
  t = 31;
  assert.equal(await shared.snapshot(), a);
  await new Promise((r) => setTimeout(r, 10));
  const b = await shared.snapshot();
  assert.notEqual(b, a);
  assert.ok(b.block.number > a.block.number);
  const before = calls(c);
  assert.equal(await b.read("eth_call", [{ to: escrow, data: "0x01" }]), "0x" + "01".padStart(64, "0"));
  assert.equal(calls(c), before, "replayed read is warm");
});

test("a snapshot is never served past 2 * seconds: callers wait for the next and get its error", async () => {
  const c = chain();
  let t = 0;
  const shared = sharedSnapshots(reader(), 30, () => t);
  const a = await shared.snapshot();
  c.fail = true;
  t = 45;
  assert.equal(await shared.snapshot(), a);
  await new Promise((r) => setTimeout(r, 10));
  t = 60;
  await assert.rejects(shared.snapshot(), /layover-chain \/head: HTTP 502 helios down/);
  c.fail = false;
  assert.ok((await shared.snapshot()).block.number > a.block.number);
});

test("a failed read is not kept", async () => {
  const c = chain(), s = await reader().snapshot(), ok = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ error: "timeout" }, { status: 502 });
  await assert.rejects(s.read("eth_call", [{ to: escrow, data: "0x03" }]), /HTTP 502/);
  globalThis.fetch = ok;
  assert.equal(await s.read("eth_call", [{ to: escrow, data: "0x03" }]), "0x" + "03".padStart(64, "0"));
  assert.equal(calls(c), 1);
});
