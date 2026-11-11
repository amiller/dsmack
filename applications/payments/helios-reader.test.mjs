import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256 } from "./schema.mjs";
import { HeliosReader, sharedSnapshots } from "./helios-reader.mjs";

const escrow = "0x" + "35".repeat(20), code = "0x6000";
const bytes = (h) => Uint8Array.from(h.slice(2).match(/../g), (x) => parseInt(x, 16));
// A chain-read stand-in whose head advances one block per snapshot; `fail` makes the next snapshot refuse. Logs reads.
let current;
function chain() {
  const c = current = { head: 1000, fetches: [], fail: false, failCall: false, inFlight: 0, peak: 0, delay: 0 };
  c.instance = {
    snapshot: async () => {
      c.fetches.push("head ");
      if (c.fail) throw new Error("helios down");
      const n = ++c.head;
      return { block: { number: n, hash: "0x" + n.toString(16).padStart(64, "0"), timestamp: Date.now() / 1000 - 2 },
        call: async (to, data) => {
          c.inFlight++; c.peak = Math.max(c.peak, c.inFlight);
          try {
            await new Promise((r) => setTimeout(r, c.delay));
            if (c.failCall) { c.failCall = false; throw new Error("eth_call failed on every source"); }
            c.fetches.push("call " + data);
            return bytes("0x" + data.slice(2).padStart(64, "0"));
          } finally { c.inFlight--; }
        } };
    },
    read: async (method, [address]) => { c.fetches.push("code " + address); return code; },
  };
  return c;
}
const reader = () => new HeliosReader({ escrow, codeHash: keccak256(code), open: async () => current.instance });
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
  await assert.rejects(shared.snapshot(), /helios down/);
  c.fail = false;
  assert.ok((await shared.snapshot()).block.number > a.block.number);
});

test("a failed read is not kept", async () => {
  const c = chain(), s = await reader().snapshot();
  c.failCall = true;
  await assert.rejects(s.read("eth_call", [{ to: escrow, data: "0x03" }]), /failed on every source/);
  assert.equal(await s.read("eth_call", [{ to: escrow, data: "0x03" }]), "0x" + "03".padStart(64, "0"));
  assert.equal(calls(c), 1);
});

test("the next snapshot replays the previous reads one at a time", async () => {
  const c = chain();
  c.delay = 2;
  let t = 0;
  const shared = sharedSnapshots(reader(), 30, () => t);
  const a = await shared.snapshot();
  for (const d of ["0x01", "0x02", "0x03", "0x04"]) await a.read("eth_call", [{ to: escrow, data: d }]);
  c.peak = 0;
  t = 31;
  await shared.snapshot();
  await new Promise((r) => setTimeout(r, 100));
  assert.notEqual(await shared.snapshot(), a);
  assert.equal(c.peak, 1);
});

test("a head older than maxHeadAge is refused, and a failed Helios start is retried", async () => {
  const c = chain();
  let starts = 0;
  const r = new HeliosReader({ escrow, codeHash: keccak256(code), open: async () => { if (starts++ === 0) throw new Error("no relay"); return c.instance; },
    now: () => Date.now() / 1000 + 200 });
  await assert.rejects(r.snapshot(), /no relay/);
  await assert.rejects(r.snapshot(), /Helios head is \d+ s old/);
  assert.equal(starts, 2);
});
