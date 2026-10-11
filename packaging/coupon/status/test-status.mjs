import test from "node:test";
import assert from "node:assert/strict";
import { view, issuerView, readFeed } from "./status.mjs";
const observation = { state: "ready", observed_at_unix: 1000, claiming_available: true };
test("only a fresh ready operator observation says available", () => {
  assert.equal(view(observation, 1090).claiming, "available");
  for (const state of ["unavailable", "unknown", "maintenance", "reconciliation-required", "approval-renewal-required"]) {
    assert.equal(view({ ...observation, state, claiming_available: false }, 1000).claiming, state === "unknown" ? "unknown" : "unavailable");
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
const issuer = {
  identity_profile: "mac-appattest-coupon-v1", schema: "dsmack-issuer-observation-v1", network: "dsmack-public-testnet-v1", observed_at_unix: 1000,
  issuer_status: "issuer-reachable", peer: "/dns4/issuer.example/tcp/443/wss/p2p/" + "a".repeat(32),
  source_revision: "2".repeat(40), trust_profile: "operator-readable-debug",
  bundle_url: "https://example.org/immutable/bundle.json", bundle_sha256: "1".repeat(64),
  approval_expires_at_unix: 2000, claim_window_ends_at_unix: 1900,
};
test("issuer observation has its own lifetime, expiry, and no readiness or census", () => {
  const current = issuerView(issuer, 1300);
  assert.equal(current.status, "issuer-reachable");
  assert.equal(current.freshness, "fresh");
  assert.equal(current.details.claimWindow, "advertised window open");
  assert.equal("claiming" in current, false);
  assert.equal("participants" in current.details, false);
  assert.equal(issuerView(issuer, 1301).status, "stale");
  assert.equal(issuerView(issuer, 969).status, "unknown");
  assert.equal(issuerView(issuer, 970).status, "issuer-reachable");
  assert.equal(issuerView({ ...issuer, observed_at_unix: 2000 }, 2000).status, "expired");
  assert.equal(issuerView({ ...issuer, observed_at_unix: 1900 }, 1900).details.claimWindow, "expired");
  for (const state of ["stale", "refused", "expired"]) {
    assert.equal(issuerView({ ...issuer, issuer_status: state }, 1000).status, state);
  }
  assert.equal(view(observation, 1091).freshness, "stale");
  assert.equal(view({ ...observation, state: "maintenance", claiming_available: false }, 1000).claiming, "unavailable");
});
test("invalid/private issuer inputs cannot create links or peer rows", () => {
  for (const change of [
    { schema: "v2" }, { secret: "canary" }, { network: "<script>" }, { trust_profile: "production-private" },
    { observed_at_unix: 1000.1 }, { observed_at_unix: 1e15 }, { issuer_status: "healthy" },
    { source_revision: "main" }, { peer: "private" }, { bundle_sha256: "bad" },
    { approval_expires_at_unix: -1 }, { claim_window_ends_at_unix: 2001 },
    ...["javascript:alert(1)", "http://example.org/a", "https://u:p@example.org/a", "https://example.org/a?secret=x", "https://example.org/#x", "https://example.org:444/a"].map(bundle_url => ({ bundle_url })),
  ]) {
    assert.equal(issuerView({ ...issuer, ...change }, 1000).status, "unknown", JSON.stringify(change));
    assert.equal(issuerView({ ...issuer, ...change }, 1000).details, null);
  }
  assert.equal(issuerView(null, 1000).details, null);
  assert.equal(issuerView(issuer, Infinity).status, "unknown");
});
test("both independent feeds use anonymous bounded reads; malformed UTF-8 and JSON fail", async () => {
  assert.deepEqual(await readFeed(async url => {
    assert.ok(url.pathname.endsWith("/issuer.json")); return new Response(JSON.stringify(issuer));
  }, "issuer.json"), issuer);
  await assert.rejects(readFeed(async () => new Response(new Uint8Array([255]))));
  await assert.rejects(readFeed(async () => new Response("{")));
  await assert.rejects(readFeed(async () => { throw Error("offline"); }));
  await assert.rejects(readFeed(async () => { throw Error("must not fetch"); }, "../private.json"));
});
