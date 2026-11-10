import assert from "node:assert/strict";
import { test, after } from "node:test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { setImmediate } from "node:timers/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";

const app = new URL("./", import.meta.url).pathname;
await mkdir(app + "local-data", { recursive: true });
const temporary = await mkdtemp(app + "local-data/credit-tests-");
after(() => rm(temporary, { recursive: true, force: true }));
await build({ entryPoints: [app + "credit.mjs"], outfile: temporary + "/credit.mjs",
  bundle: true, platform: "node", format: "esm", packages: "external",
  alias: { "@sandbox": resolve(app, "../compute-node/browser/sandbox.mjs"), "npm:ethers@6.17.0": "ethers" }, logLevel: "silent" });
const { Credit } = await import(pathToFileURL(temporary + "/credit.mjs"));

test("deposit credit polling survives stale finalized balances and a temporary outage", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const credit = Object.assign(Object.create(Credit.prototype), { address: "wallet", chatCredit: { grantedNanoUsd: "250000000" } });
  let calls = 0;
  const result = credit.waitForDeposit(1250000000n, async () => {
    calls++;
    if (calls === 2) throw new TypeError("broker offline");
    if (calls === 3) credit.chatCredit.grantedNanoUsd = "1250000000";
  });
  await setImmediate();
  assert.equal(calls, 1);
  t.mock.timers.tick(30000);
  await setImmediate();
  assert.equal(calls, 2);
  t.mock.timers.tick(30000);
  assert.equal(await result, true);
  assert.equal(calls, 3);
});

test("deposit credit polling stops when the wallet changes", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const credit = Object.assign(Object.create(Credit.prototype), { address: "old", chatCredit: { grantedNanoUsd: "0" } });
  let calls = 0;
  const result = credit.waitForDeposit(1000n, async () => { calls++; });
  await setImmediate();
  credit.address = "new";
  t.mock.timers.tick(30000);
  assert.equal(await result, false);
  assert.equal(calls, 1);
});
