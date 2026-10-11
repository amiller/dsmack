import test from "node:test";
import assert from "node:assert/strict";
import { view, readFeed } from "./status.mjs";
const observation = { state: "ready", observed_at_unix: 1000, claiming_available: true };
test("only a fresh ready operator observation says available", () => {
  assert.equal(view(observation, 1090).claiming, "available");
  for (const state of ["unavailable", "unknown", "maintenance", "reconciliation-required", "approval-renewal-required"]) {
    assert.equal(view({ ...observation, state, claiming_available: false }, 1000).claiming, "unavailable");
    assert.equal(view({ ...observation, state }, 1000).claiming, "unknown");
  }
});
test("time expires locally even without another fetch; malformed/private fields refuse", () => {
  for (const value of [null, { ...observation, secret: "canary" }, { ...observation, state: "other" },
    { ...observation, claiming_available: 1 }, { ...observation, observed_at_unix: 1000.5 }]) {
    assert.equal(view(value, 1000).claiming, "unknown");
  }
  assert.equal(view(observation, 1091).claiming, "unknown");
  assert.equal(view(observation, 969).claiming, "unknown");
  assert.equal(view(observation, 970).claiming, "available");
});
test("fetch is anonymous and bounded; failed or oversized responses refuse", async () => {
  const result = await readFeed(async (url, options) => {
    assert.equal(url.pathname.endsWith("/health.json"), true);
    assert.equal(options.credentials, "omit"); assert.equal(options.redirect, "error");
    assert.equal(options.cache, "no-store");
    return new Response(JSON.stringify(observation));
  });
  assert.deepEqual(result, observation);
  await assert.rejects(readFeed(async () => new Response("x".repeat(4097))));
  await assert.rejects(readFeed(async () => new Response("unavailable", { status: 503 })));
});
