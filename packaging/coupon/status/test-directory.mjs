import test from "node:test";
import assert from "node:assert/strict";
import {directoryView, readDirectory, directoryEndpoint} from "./directory.mjs";

// Synthetic validation inputs only; these are never served as live observations.
const now = Date.parse("2030-01-01T00:00:00Z") / 1000;
const at = delta => new Date((now + delta) * 1000).toISOString();
const h = (c, n = 64) => "0x" + c.repeat(n);
const report = () => ({schema: 1, type: "dsmack-native-directory", generatedAt: at(0),
  network: {chainId: 84532, registry: "0xd4b33c83576a6049d29c6b849ec73491e52781a0"}, coverage: "explicit-opt-in",
  status: "available", error: null, freshness: {heartbeatTtlSeconds: 90, staleRetentionSeconds: 300, receiptFreshnessSeconds: 120},
  nodes: [{id: h("1"), member: h("2"), account: {status: "verified", address: h("3", 40), participantToken: "1"},
    version: {selfReported: "0.2.0-rc.1", buildNumber: "5", admittedCodeHash: h("4")},
    checkIn: {lastVerifiedAt: at(-10), expiresAt: at(80), status: "fresh"},
    sync: {scope: h("0"), keyEpoch: "1", groupPublicFingerprint: "sha256:" + "5".repeat(64),
      status: "receipt-verified-current-epoch", receiptTransaction: h("6"), receiptCheckedAt: at(-5), receiptBlockTime: at(-20)}}]});

test("fresh check-in and actual receipt time expire independently in the browser", () => {
  const r = report();
  assert.equal(directoryView(r, now).nodes[0].syncLabel, "Recent verified exchange");
  assert.equal(directoryView(r, now + 80).nodes[0].fresh, false);
  assert.equal(directoryView(r, now + 91).status, "stale");
  r.nodes[0].sync.receiptBlockTime = at(-121);
  assert.equal(directoryView(r, now).nodes[0].fresh, true);
  assert.equal(directoryView(r, now).nodes[0].syncLabel, "Historical exchange");
  r.generatedAt = at(30); r.nodes[0].sync.receiptCheckedAt = at(30);
  assert.equal(directoryView(r, now + 30).nodes[0].syncLabel, "Historical exchange");
});

test("empty opt-in directory differs from unavailable and disabled observation", () => {
  const r = report(); r.nodes = [];
  assert.equal(directoryView(r, now).status, "available");
  r.status = "unavailable"; r.error = {code: "RPC_UNAVAILABLE"};
  assert.equal(directoryView(r, now).status, "unavailable");
  r.status = "not-configured"; r.error = {code: "DIRECTORY_DISABLED"};
  assert.equal(directoryView(r, now).status, "not-configured");
  r.error = {code: "private exception"};
  assert.equal(directoryView(r, now).status, "unknown");
});

test("reject fixture markers, unpinned networks, private extras, duplicate IDs and invented evidence", () => {
  for (const mutate of [
    r => {r.fixture = true;}, r => {r.network.chainId = 31337;}, r => {r.network.registry = h("9", 40);},
    r => {r.nodes[0].secret = "private";}, r => {r.nodes.push(structuredClone(r.nodes[0]));},
    r => {r.generatedAt = at(31);}, r => {r.generatedAt = "2030-02-31T00:00:00Z";},
    r => {r.nodes[0].checkIn.expiresAt = at(9999);}, r => {r.nodes[0].checkIn.lastVerifiedAt = at(10);},
    r => {r.nodes[0].sync.receiptBlockTime = null;}, r => {r.nodes[0].sync.receiptTransaction = null;},
    r => {r.nodes[0].sync.receiptCheckedAt = at(31);}, r => {r.nodes[0].sync.groupPublicFingerprint = ["sha256:" + "5".repeat(64)];},
    r => {r.nodes[0].account.status = "unavailable";}, r => {r.nodes[0].version.selfReported = "<script>";},
    r => {r.nodes[0].sync.keyEpoch = "18446744073709551616";}, r => {r.nodes[0].version.buildNumber = true;},
    r => {r.status = "unavailable"; r.error = {code: "RPC_UNAVAILABLE"};},
  ]) {const r = report(); mutate(r); assert.equal(directoryView(r, now).status, "unknown");}
});

test("unbound accounts and unverified exchange never acquire verified labels", () => {
  const r = report();
  r.nodes[0].account = {status: "unavailable", address: null, participantToken: null};
  r.nodes[0].sync = {...r.nodes[0].sync, status: "unverified", receiptTransaction: null, receiptCheckedAt: null, receiptBlockTime: null, groupPublicFingerprint: null};
  assert.equal(directoryView(r, now).nodes[0].syncLabel, "Exchange unverified");
});

test("directory fetch pins endpoint, omits credentials and rejects redirects, oversized and malformed payloads", async () => {
  const good = await readDirectory(async (url, options) => {
    assert.equal(url, directoryEndpoint); assert.equal(options.credentials, "omit"); assert.equal(options.redirect, "error"); assert.equal(options.cache, "no-store");
    return new Response(JSON.stringify(report()));
  });
  assert.equal(good.schema, 1);
  await assert.rejects(readDirectory(async () => new Response("x".repeat(131073))));
  await assert.rejects(readDirectory(async () => new Response(new Uint8Array([255]))));
  await assert.rejects(readDirectory(async () => new Response("{}", {status: 503})));
});
