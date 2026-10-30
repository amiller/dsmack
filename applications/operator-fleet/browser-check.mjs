import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
const [url, output] = process.argv.slice(2), payout = process.env.PAYOUT_ADDRESS;
assert(url && output && /^0x[0-9a-f]{40}$/i.test(payout || ""), "Usage: PAYOUT_ADDRESS=0x… node browser-check.mjs URL EVIDENCE");
const pageUrl = new URL(url);
if (process.env.LOCAL_PREVIEW !== "1") {
  assert.equal(pageUrl.protocol, "https:");
  assert.match(pageUrl.hostname, /^(b[a-z2-7]+\.ipfs|k[0-9a-z]+\.ipns)\./);
}
const moduleName = process.env.PLAYWRIGHT_MODULE || "playwright";
const { chromium } = await import(isAbsolute(moduleName) ? pathToFileURL(moduleName).href : moduleName);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"], ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}) });
const context = await browser.newContext({ viewport: { width: 1440, height: 1100 }, acceptDownloads: true });
const report = { status: "failed", url, payout, wallet: "read-only EIP-1193 test account", navigationViolations: [], pageErrors: [], failedRequests: [], walletMethods: [], transactionsAttempted: 0 };
await context.addInitScript(address => {
  window.fleetWalletMethods = [];
  window.ethereum = { request: async ({ method }) => { window.fleetWalletMethods.push(method); if (method === "eth_requestAccounts" || method === "eth_accounts") return [address]; throw Error("Read-only account refuses " + method); }, on() {} };
}, payout);
const page = await context.newPage();
page.on("pageerror", e => report.pageErrors.push(e.message));
page.on("requestfailed", r => report.failedRequests.push({ url: r.url(), error: r.failure()?.errorText }));
await context.route("**/*", async route => {
  const request = route.request();
  if (request.resourceType() === "document" && new URL(request.url()).origin !== pageUrl.origin) { report.navigationViolations.push(request.url()); return route.abort(); }
  if (request.method() === "POST") {
    const raw = request.postData();
    if (raw && request.headers()["content-type"]?.includes("application/json")) {
      const body = JSON.parse(raw);
      if ((Array.isArray(body) ? body : [body]).some(r => r.method?.startsWith("eth_send"))) { report.transactionsAttempted++; return route.abort(); }
    }
  }
  return route.continue();
});
try {
  const response = await page.goto(url, { waitUntil: "domcontentloaded" });
  report.gatewayStatus = response.status();
  assert(response.ok(), "gateway page HTTP " + response.status());
  await page.waitForFunction(() => document.documentElement.dataset.ready === "true", null, { timeout: 60000 });
  await page.locator("#connect").click();
  await page.waitForFunction(() => document.documentElement.dataset.loaded === "true" || !document.querySelector("#error").hidden, null, { timeout: 180000 });
  assert.equal(await page.locator("#error").isVisible(), false, await page.locator("#error").textContent());
  assert.match(await page.locator("#wallet").innerText(), new RegExp(payout, "i"));
  assert(await page.locator(".mac-name").count() > 0, "no Mac for payout");
  report.earnedAll = await page.locator("#earned-all").innerText();
  report.earnedWeek = await page.locator("#earned-week").innerText();
  assert.notEqual(report.earnedAll, "—");
  if (process.env.EXPECTED_EARNED) assert.equal(report.earnedAll, process.env.EXPECTED_EARNED);
  report.guests = await page.locator("#guests").innerText();
  report.macs = await page.locator("#macs").innerText();
  const macName = await page.locator(".mac-name").first().textContent();
  await page.locator("#search").fill("no-such-operator-mac");
  assert.equal(await page.locator(".mac-name").count(), 0);
  await page.locator("#search").fill(macName);
  assert(await page.locator(".mac-name").count() > 0);
  await page.locator("#online").check();
  assert(await page.locator(".mac-name").count() > 0, "live Mac missing from online filter");
  report.filters = "search and online passed";
  await page.locator(".mac-name").first().click();
  assert(await page.locator(".slot").count() > 0, "no slots in Mac details");
  report.slots = await page.locator(".slot").allTextContents();
  report.slotIds = [...new Set(report.slots.map(text => Number(text.match(/^Slot (\d+)/)[1])))].sort((a, b) => a - b);
  report.config = JSON.parse(await page.locator(".detail-body > pre").innerText());
  if (process.env.EXPECTED_SLOTS) {
    const slots = Number(process.env.EXPECTED_SLOTS);
    assert.equal(report.config.max_guests, slots);
    assert.deepEqual(report.slotIds, Array.from({ length: slots }, (_, i) => i));
  }
  report.errors = await page.locator(".error-item").allTextContents();
  report.detail = await page.locator("#detail").innerText();
  assert.match(report.detail, /Last ten errors/);
  assert.match(report.detail, /Operator config/);
  report.downloads = [];
  for (const [prefix, filename] of [["attestation-slot-", "attestation.json"], ["receipt-", "receipt.json"]]) {
    const link = page.locator(`a[download^="${prefix}"]`).first();
    if (await link.count()) {
      const event = page.waitForEvent("download"); await link.click();
      const download = await event; await download.saveAs(resolve(output, filename));
      const value = JSON.parse(await readFile(resolve(output, filename), "utf8"));
      if (prefix === "receipt-") assert(value.receipt && value.signature && value.nodeBinding, "signed receipt envelope missing");
      report.downloads.push({ filename, suggested: download.suggestedFilename(), fields: Object.keys(value) });
    }
  }
  await page.screenshot({ path: resolve(output, "fleet.png"), fullPage: true });
  report.walletMethods = await page.evaluate(() => window.fleetWalletMethods);
  assert.deepEqual(report.walletMethods, ["eth_requestAccounts"]);
  assert.equal(report.transactionsAttempted, 0);
  assert.deepEqual(report.navigationViolations, []);
  assert.deepEqual(report.pageErrors, []);
  report.status = "passed";
} catch (e) { report.error = e.stack; throw e; }
finally { await writeFile(resolve(output, "result.json"), JSON.stringify(report, null, 2)); await browser.close(); }
