import assert from "node:assert/strict";
import { test } from "node:test";
import { rankNodes, busyRetrySeconds } from "./scheduler.mjs";
const now = 2000000000;
const node = (peer, until = now + 600) => ({ kind: "compute", relay_peer: peer, admit_until: until });
const mac = (publisher, peers, extras = {}) => ({ publisher, online: true, received_at: now, updated_at: now,
  slots: peers.map((relay_peer, slot_id) => ({ relay_peer, slot_id, state: "ready" })), ...extras });

test("placement prefers exact snapshot owner, then free slots, then latest admission deadline", () => {
  const nodes = [node("a"), node("b", now + 800), node("c"), node("d")];
  const fleet = [mac("first", ["a", "b"]), mac("second", ["c"]), mac("third", ["d"])];
  assert.deepEqual(rankNodes(nodes, fleet, () => true, { now }).map(n => n.relay_peer), ["b", "a", "c", "d"]);
  const sticky = rankNodes(nodes, fleet, () => true, { now, snapshotOwner: "second" });
  assert.equal(sticky[0].relay_peer, "c");
  assert.equal(sticky[0].scheduler.snapshotLocal, true);
  assert.equal(sticky[1].scheduler.freeSlots, 2);
});

test("stale heartbeats, busy stays and draining guests cannot be offered as free slots", () => {
  const nodes = [node("stale"), node("busy"), node("drain", now + 15), node("new")];
  const fleet = [mac("offline", ["stale"], { received_at: now - 61 }), mac("live", ["busy", "drain", "new"])];
  const ranked = rankNodes(nodes, fleet, n => n.relay_peer !== "busy", { now });
  assert.deepEqual(ranked.filter(n => n.available).map(n => n.relay_peer), ["new"]);
  assert.equal(ranked.find(n => n.relay_peer === "new").scheduler.freeSlots, 1);
  assert.equal(rankNodes(nodes, [], () => true, { now }).some(n => n.available), false);
});

test("full fleet supplies a bounded retry time instead of creating a queued stay", () => {
  assert.equal(busyRetrySeconds([], {}, now), 15);
  assert.equal(busyRetrySeconds([], { held: { final: false, grant: { expires_at: now + 7 } } }, now), 7);
  assert.equal(busyRetrySeconds([], { ended: { final: true, grant: { expires_at: now + 1 } } }, now), 15);
});
