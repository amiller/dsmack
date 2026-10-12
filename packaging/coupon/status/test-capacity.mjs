import test from "node:test";
import assert from "node:assert/strict";
import {capacityView, drawCapacity, readCapacity, capacityEndpoint} from "./capacity.mjs";
const now = Date.parse("2030-01-01T00:00:00Z") / 1000;
const at = n => new Date((now + n) * 1000).toISOString();
// Synthetic parser inputs only, never served as live public capacity.
const report = () => ({generatedAt: at(0), chainId: 84532, registry: "0xd4b33c83576a6049d29c6b849ec73491e52781a0", protocolVersion: 2, sponsorWritesPaused: false,
  sponsorBudget: {mode: "public-pilot", expiresAt: at(60), expired: false, exhausted: false, additionalPublicEnrollmentCapacity: 1}});
test("bounded slot is locally expired and never a reservation", () => {
  const v = capacityView(report(), now); assert.equal(v.status, "bounded slot advertised"); assert.match(v.message, /not reserved/);
  assert.equal(capacityView(report(), now + 60).status, "unavailable");
  assert.equal(capacityView(report(), now + 91).status, "unknown");
});
test("missing, stale, malformed or wrong-domain observations fail closed", () => {
  assert.equal(capacityView(null, now).status, "unknown");
  for (const change of [r => {r.chainId = 31337;}, r => {r.registry = "0x" + "0".repeat(40);}, r => {r.generatedAt = at(16);}, r => {r.generatedAt = at(-91);}, r => {r.sponsorBudget.additionalPublicEnrollmentCapacity = 2;}, r => {r.sponsorBudget.mode = "qualification";}, r => {r.sponsorBudget.expired = true;}, r => {r.sponsorBudget.exhausted = true;}, r => {delete r.sponsorBudget.exhausted;}, r => {r.sponsorBudget.expiresAt = "invalid";}]) {
    const r = report(); change(r); assert.equal(capacityView(r, now).status, "unknown");
  }
});
test("paused, qualification, consumed and expired are not public join readiness", () => {
  for (const change of [r => {r.sponsorWritesPaused = true;}, r => {r.sponsorBudget.additionalPublicEnrollmentCapacity = 0;}, r => {r.sponsorBudget.mode = "qualification"; r.sponsorBudget.additionalPublicEnrollmentCapacity = 0;}, r => {r.sponsorBudget.expired = true; r.sponsorBudget.additionalPublicEnrollmentCapacity = 0;}]) {
    const r = report(); change(r); assert.equal(capacityView(r, now).status, "unavailable");
  }
});
test("renderer uses text and refreshes expiry without another fetch", () => {
  const nodes = new Map(); const doc = {getElementById: id => {if (!nodes.has(id)) nodes.set(id, {}); return nodes.get(id);}};
  drawCapacity(report(), doc, now); assert.equal(nodes.get("capacity-state").textContent, "bounded slot advertised");
  drawCapacity(report(), doc, now + 60); assert.equal(nodes.get("capacity-state").textContent, "unavailable");
});
test("fetch is anonymous, bounded and rejects redirects/errors/malformed JSON", async () => {
  const good = await readCapacity(async (url, options) => {assert.equal(url, capacityEndpoint); assert.equal(options.credentials, "omit"); assert.equal(options.redirect, "error"); assert.equal(options.cache, "no-store"); return new Response(JSON.stringify(report()));});
  assert.equal(good.chainId, 84532);
  for (const response of [new Response("x", {status: 503}), new Response("x"), new Response("x".repeat(32769))]) await assert.rejects(() => readCapacity(async () => response));
});
