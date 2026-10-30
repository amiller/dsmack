import { test } from "node:test";
import assert from "node:assert/strict";
import { PURCHASE, SETTLED, NetworkChain, decodeEvent, matchingLogs, totals } from "./chain.mjs";
const word = value => BigInt(value).toString(16).padStart(64, "0");
const id = value => "0x" + word(value);
const log = (topic, words, purchaseId = 1, block = 10, index = 0) => ({
  address: "0x" + "a".repeat(40), blockHash: id(block), blockNumber: "0x" + block.toString(16), transactionHash: id(123), transactionIndex: "0x0", logIndex: "0x" + index.toString(16), removed: false,
  topics: [topic, id(purchaseId), ...(topic === PURCHASE ? [id(2), id(3)] : [])], data: "0x" + words.map(word).join(""),
});
test("settlement decoder reads the contract ABI and rejects truncated events", () => {
  assert.equal(decodeEvent(log(PURCHASE, [0, 1, 100, 4, 123])).unit, 1);
  const event = decodeEvent(log(SETTLED, [4, 57, 400, 0, 1]));
  assert.equal(event.used, 57n); assert.equal(event.sequence, 4n); assert.equal(event.final, true);
  assert.throws(() => decodeEvent(log(SETTLED, [4, 57, 400, 0])), /shape/);
  assert.throws(() => decodeEvent(log(SETTLED, [4, 57, 400, 0, 2])), /final/);
});
test("cumulative usage counts deltas in each settlement window and excludes byte purchases", () => {
  const events = [
    { kind: "purchase", id: "1", unit: 1, block: 1, index: 0 },
    { kind: "purchase", id: "2", unit: 0, block: 1, index: 1 },
    { kind: "settled", id: "1", used: 30n, final: false, timestamp: 100000 - 90000, block: 2, index: 0 },
    { kind: "settled", id: "2", used: 999n, final: true, timestamp: 99900, block: 3, index: 0 },
    { kind: "settled", id: "1", used: 55n, final: false, timestamp: 99950, block: 4, index: 0 },
    { kind: "settled", id: "1", used: 60n, final: true, timestamp: 99960, block: 4, index: 1 },
  ];
  assert.deepEqual(totals(events, 100000), [{ seconds: 86400, guestSeconds: "30", jobs: 1 }, { seconds: 604800, guestSeconds: "60", jobs: 1 }]);
  assert.throws(() => totals(events.slice(2), 100000), /matching purchase/);
});
test("two RPC log replies may reorder results but must agree on every event", () => {
  const a = log(PURCHASE, [0, 1, 100, 4, 123]);
  const b = log(SETTLED, [1, 90, 400, 0, 1], 1, 11);
  assert.equal(matchingLogs([a, b], [b, a]).length, 2);
  assert.throws(() => matchingLogs([a, b], [a, { ...b, data: log(SETTLED, [1, 91, 400, 0, 1]).data }]), /disagree/);
  assert.throws(() => matchingLogs([a, b], [a]), /disagree/);
});
test("chain reader withholds a total if providers disagree on the finalized block", async () => {
  const config = { rpcs: ["https://one.example", "https://two.example"], chainId: 84532, deploymentBlock: 10 };
  const reader = new NetworkChain(config, async (url, method) => method === "eth_chainId" ? "0x14a34" : { number: "0xa", hash: id(url.includes("one") ? 1 : 2), timestamp: "0x186a0" });
  await assert.rejects(reader.read(() => {}, 100000), /disagree/);
});
