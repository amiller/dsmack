import assert from "node:assert/strict";
import { test } from "node:test";
import { Network, networkSnapshot } from "./network.mjs";

const mac = { publisher: "publisher", operator: "operator", region: { name: "Michigan, US", lat: 42, lon: -84 },
  hardware: { name: "private-hostname", chip: "Apple M4", mem_bytes: 64 * 2 ** 30 },
  config: { max_guests: 4 }, slots: [{ slot_id: 0, state: "busy", run_id: "private-run" },
    { slot_id: 0, state: "ready" }, { slot_id: 1, state: "ready" }, { slot_id: 1, state: "ready" }],
  errors: ["private-error"], signature: "private-envelope", link: { private: true },
  updated_at: 120, received_at: 120, online: true, status: "online" };

test("public network counts rotating logical slots once and excludes offline capacity and private fields", () => {
  const value = networkSnapshot([mac, { ...mac, publisher: "offline", online: false, status: "offline" }], 140);
  assert.deepEqual(value.totals, { macs_online: 1, total_slots: 4, ready_slots: 1, busy_slots: 1, utilization: 0.25 });
  assert.equal(value.macs.length, 2); assert.deepEqual(value.macs[0].region, mac.region);
  assert.equal(value.macs[0].operator, "operator");
  assert(!JSON.stringify(value).includes("private"));
  assert.equal(networkSnapshot([{ ...mac, region: undefined }], 140).macs[0].region, null);
});

test("history retains at most 24 hours of minute samples without inventing missing observations", async () => {
  let now = 120, observed = [mac];
  const monitor = new Network({ now: () => now, read: async at => observed.map(value => ({ ...value, online: at < 180 })) });
  await monitor.sample(); now = 130; await monitor.sample();
  assert.equal(monitor.history().samples.length, 1);
  now = 300; await monitor.sample();
  assert.deepEqual(monitor.history().samples.map(value => value.timestamp), [120, 300]);
  assert.equal(monitor.history().samples[1].macs_online, 0);
  now = 86580; observed = []; await monitor.sample();
  assert.deepEqual(monitor.history().samples.map(value => value.timestamp), [300, 86580]);
  assert.equal(monitor.history().lost_on_restart, true);
  assert.equal(new Network({ now: () => now, read: async () => [] }).history().samples.length, 0);
});

test("network public CORS reads do not accept writes", async () => {
  const monitor = new Network({ now: () => 120, read: async () => [mac] });
  await monitor.sample();
  for (const path of ["/network", "/network/history"]) {
    const response = await monitor.response(new Request("https://broker.test" + path));
    assert.equal(response.status, 200); assert.equal(response.headers.get("access-control-allow-origin"), "*");
    assert.equal((await monitor.response(new Request("https://broker.test" + path, { method: "POST" }))).status, 405);
  }
});
