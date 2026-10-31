import assert from "node:assert/strict";
import test from "node:test";
import { running, summarize } from "./model.mjs";

test("settled incremental credits are summed without counting cumulative guest seconds as earnings", () => {
  const now = 10 * 86400;
  const events = [
    { purchaseId: "1", sequence: 1, operator: "0xA", node: "class-a", runId: "run-a", timestamp: now - 3600, used: "10", operatorCredit: "100" },
    { purchaseId: "1", sequence: 2, operator: "0xA", node: "class-a", runId: "run-a", timestamp: now - 3000, used: "15", operatorCredit: "50" },
    { purchaseId: "2", sequence: 1, operator: "0xA", node: "class-old", runId: "run-old", timestamp: now - 8 * 86400, used: "20", operatorCredit: "200" },
    { purchaseId: "3", sequence: 1, operator: "0xB", node: "class-a", runId: "run-b", timestamp: now - 100, used: "99", operatorCredit: "990" },
  ];
  const macs = [{ operator: "0xa", classes: ["class-a", "class-old"], slots: [] }, { operator: "0xb", classes: ["class-a"], slots: [] }];
  const result = summarize(events, macs, "0xA", now);
  assert.equal(result.all, 350n);
  assert.equal(result.week, 150n);
  assert.equal(result.jobs24h, 1);
  assert.equal(result.jobs.length, 2);
  assert.equal(result.jobs[0].used, "15");
  assert.equal(result.macs.length, 1);
  assert.equal(result.macs[0].chain.all, 350n);
  assert.equal(result.daily.reduce((sum, d) => sum + d.earned, 0n), 150n);
});

test("each Mac gets only its own classes, including rotated historical classes", () => {
  const event = (purchaseId, node) => ({ purchaseId, sequence: 1, operator: "operator", node, runId: purchaseId, timestamp: 100, operatorCredit: "10" });
  const result = summarize([event("1", "mini-old"), event("2", "mini-new"), event("3", "studio")], [
    { operator: "operator", classes: ["mini-old", "mini-new"], slots: [] },
    { operator: "operator", classes: ["studio"], slots: [] },
  ], "operator", 200);
  assert.equal(result.macs[0].chain.all, 20n);
  assert.equal(result.macs[1].chain.all, 10n);
});

test("a draining handover counts one occupied slot; failed slots are not running", () => {
  assert.equal(running({ slots: [{ slot_id: 0, state: "ready" }, { slot_id: 0, state: "draining" }, { slot_id: 1, state: "busy" }, { slot_id: 2, state: "failed" }] }), 2);
});

test("a relink moves the Mac while past settlements stay with the paid operator", () => {
  const macs = [{ operator: "new", payout: "old", classes: ["class"], slots: [] }];
  const event = (purchaseId, operator) => ({ purchaseId, operator, sequence: 1, node: "class", runId: purchaseId, timestamp: 100, operatorCredit: "10" });
  const events = [event("1", "old"), event("2", "new")];
  const former = summarize(events, macs, "old", 200);
  const current = summarize(events, macs, "new", 200);
  assert.equal(former.macs.length, 0);
  assert.equal(former.all, 10n);
  assert.equal(current.macs.length, 1);
  assert.equal(current.macs[0].chain.all, 10n);
});
