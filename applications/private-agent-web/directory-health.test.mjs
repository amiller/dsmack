import { test } from "node:test";
import assert from "node:assert/strict";
import { monitor, monitorCapacity, checkCapacity } from "./directory-health.mjs";

test("directory outages alert once and recover once; notification failure remains retryable", async () => {
  const root = await Deno.makeTempDir(), messages = [];
  const args = { target: "test", url: "https://empty.example/config.json", state: root + "/state.json",
    notify: message => { messages.push(message); }, check: () => { throw Error("No signed guest entries"); } };
  try {
    await assert.rejects(monitor({ ...args, notify: () => { throw Error("Matrix unavailable"); } }), /Matrix unavailable/);
    await monitor(args); await monitor(args);
    assert.equal(messages.length, 1); assert.match(messages[0], /FAILED/);
    const healthy = { ...args, check: () => ({ nodes: 1, blockNumber: 42 }) };
    await monitor(healthy); await monitor(healthy);
    assert.equal(messages.length, 2); assert.match(messages[1], /RECOVERED/);
  } finally { await Deno.remove(root, { recursive: true }); }
});

test("zero slots or offline Macs require three contiguous minutes, then recover only once", async () => {
  for (const counts of [{ readySlots: 0, macsOnline: 1 }, { readySlots: 2, macsOnline: 0 }]) {
    const root = await Deno.makeTempDir(), messages = [];
    let at = 0;
    const args = { target: "staging", url: "https://broker.example/network", state: root+"/capacity.json",
      now: () => at, check: () => counts, notify: message => { messages.push(message); } };
    try {
      for (at of [0, 60, 120]) await monitorCapacity(args);
      assert.equal(messages.length, 0);
      at = 180; await monitorCapacity(args);
      at = 240; await monitorCapacity(args);
      assert.equal(messages.length, 1); assert.match(messages[0], /capacity FAILED/);
      at = 300; await monitorCapacity({ ...args, check: () => ({ readySlots: 1, macsOnline: 1 }) });
      at = 360; await monitorCapacity({ ...args, check: () => ({ readySlots: 1, macsOnline: 1 }) });
      assert.equal(messages.length, 2); assert.match(messages[1], /capacity RECOVERED/);
    } finally { await Deno.remove(root, { recursive: true }); }
  }
});

test("missing samples reset the capacity streak; failed notifications can be retried", async () => {
  const root = await Deno.makeTempDir(), messages = [];
  let at = 0;
  const args = { target: "staging", url: "https://broker.example/network", state: root+"/capacity.json",
    now: () => at, check: () => ({ readySlots: 0, macsOnline: 0 }), notify: message => { messages.push(message); } };
  try {
    await monitorCapacity(args);
    at = 600; await monitorCapacity(args);
    assert.equal(messages.length, 0);
    for (at of [660, 720]) await monitorCapacity(args);
    at = 780;
    await assert.rejects(monitorCapacity({ ...args, notify: () => { throw Error("Matrix unavailable"); } }), /Matrix unavailable/);
    at = 840;
    await monitorCapacity(args);
    assert.equal(messages.length, 1);
    await assert.rejects(checkCapacity(args.url, { fetcher: () => Response.json({ totals: {} }) }), /invalid/);
  } finally { await Deno.remove(root, { recursive: true }); }
});
