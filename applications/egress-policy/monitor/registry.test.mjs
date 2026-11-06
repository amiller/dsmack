import test from "node:test";
import assert from "node:assert/strict";
import registry from "./registry.json" with { type: "json" };
import { canonical, monitorPolicy } from "./registry.mjs";
async function environment(entry) {
  const text = canonical(entry);
  return { DSMACK_MONITOR_POLICY: text, DSMACK_MONITOR_HASH: Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))).toString("hex") };
}
test("browser accepts only registered policies with matching manifest hash", async () => {
  for (const entry of Object.values(registry)) assert.equal((await monitorPolicy(await environment(entry))).name, entry.name);
  await assert.rejects(monitorPolicy(await environment({ name: "operator-spy", policy: "read secrets" })), /Unregistered/);
  const env = await environment(registry.none); env.DSMACK_MONITOR_POLICY = canonical(registry["baseline-pg2"]);
  await assert.rejects(monitorPolicy(env), /hash mismatch/);
});
