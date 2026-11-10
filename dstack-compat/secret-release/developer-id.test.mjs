import assert from "node:assert/strict";
import { test } from "node:test";
import { checkAssertion, decodeAttestation, unhex } from "./policy.mjs";
import { attest, deviceKey } from "../../applications/relay-broker/fixtures/synthetic-guest.mjs";

async function assertion(category) {
  const key = await deviceKey(), rp = new Uint8Array(32).fill(1), zero = new Uint8Array(32);
  const a = await decodeAttestation(unhex(await attest(key, { os_image_hash: zero, manifest_sha256: zero, run: zero,
    caller: zero, report_data: new Uint8Array(64), rp, cdhash: zero, category })));
  const chain = { key: async () => ({ ...key, counter: 0, enrolled: true, expires: Date.now() / 1000 + 3600 }),
    category: async () => 3, rpIdHash: async () => rp, buildId: async () => zero,
    burnedImage: async () => false, burnedBuild: async () => false };
  return { a, chain };
}
test("Developer ID signed assertion is accepted alongside Apple Development", async () => {
  const { a, chain } = await assertion(6);
  await checkAssertion(a, chain, Date.now());
});
test("App Store category is outside the Mac signing categories", async () => {
  const { a, chain } = await assertion(5);
  await assert.rejects(checkAssertion(a, chain, Date.now()), /validation category/);
});
