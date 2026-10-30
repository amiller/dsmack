import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const mainUrl = process.argv[2] || process.env.PAGE_URL, output = process.argv[3] || process.env.EVIDENCE;
const publicGateway = process.env.PUBLIC_GATEWAY === "1";
assert(mainUrl && output && (publicGateway || process.env.ALT_PAGE_URL), "Usage: ALT_PAGE_URL=... or PUBLIC_GATEWAY=1 node ipfs-check.mjs PAGE_URL EVIDENCE");
const pageUrl = new URL(mainUrl);
const alternateUrl = new URL(process.env.ALT_PAGE_URL || mainUrl);
const evidence = resolve(output);
for (const url of [pageUrl, alternateUrl]) {
  if (publicGateway) {
    assert.equal(url.protocol, "https:", "public gateway must use HTTPS");
    assert.match(url.hostname, /^(b[a-z2-7]+\.ipfs|k[0-9a-z]+\.ipns)\./);
  } else {
    assert.equal(url.protocol, "http:", "local gateway must use HTTP localhost");
    assert.match(url.hostname, /^b[a-z2-7]+\.ipfs\..*localhost$/);
  }
  assert.equal(url.pathname, "/", "load the CID root, not a shared path gateway");
  assert(!url.username && !url.password && !url.search && !url.hash);
}
assert.equal(pageUrl.hostname.split(".")[0], alternateUrl.hostname.split(".")[0]);
if (!publicGateway) assert.notEqual(pageUrl.origin, alternateUrl.origin, "alternate gateway needs another origin");
const moduleName = process.env.PLAYWRIGHT_MODULE || "playwright";
const { chromium } = await import(
  isAbsolute(moduleName) ? pathToFileURL(moduleName).href : moduleName
);
await mkdir(evidence, { recursive: true });
const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
  args: ["--no-sandbox"],
});
const context = await browser.newContext({ viewport: { width: 1440, height: 1100 }, acceptDownloads: true });
const page = await context.newPage();
const report = {
  status: "failed",
  pageUrl: pageUrl.href,
  alternatePageUrl: alternateUrl.href,
  manualPolicyUpload: false,
  manualRepoUpload: false,
  manualSettings: false,
  manualDiscoveryClick: false,
  chainTransactionsAttempted: 0,
  requests: [],
  responses: [],
  responseErrors: [],
  requestFailures: [],
  corsErrors: [],
  pageErrors: [],
  navigationViolations: [],
};
const clean = (value) => String(value).replace(/0x[0-9a-f]{64}\b/gi, "[redacted-32-byte-value]");
const address = (url) => {
  const u = new URL(url);
  return { origin: u.origin, path: u.pathname };
};
const responseReads = [];
const allowedOrigins = new Set([pageUrl.origin, alternateUrl.origin]);
await context.route("**/*", async (route) => {
  const request = route.request();
  if (request.resourceType() === "document" && !allowedOrigins.has(new URL(request.url()).origin)) {
    report.navigationViolations.push(address(request.url()));
    return route.abort();
  }
  const raw = request.postData();
  if (request.method() === "POST" && raw && request.headers()["content-type"]?.includes("application/json")) {
    const body = JSON.parse(raw);
    if ((Array.isArray(body) ? body : [body]).some((item) => typeof item?.method === "string" && item.method.startsWith("eth_send"))) {
      report.chainTransactionsAttempted++;
      return route.abort();
    }
  }
  await route.continue();
});
context.on("request", (request) => {
  report.requests.push({ ...address(request.url()), method: request.method(), kind: request.resourceType() });
});
context.on("response", (response) => {
  const headers = response.headers();
  if (response.status() >= 400 && new URL(response.url()).origin === "https://pod.dstack.soc1024.com") {
    responseReads.push(response.text().then((body) => report.responseErrors.push({ ...address(response.url()), status: response.status(), body: clean(body.slice(0, 8192)) }),
      (error) => report.responseErrors.push({ ...address(response.url()), status: response.status(), readError: clean(error.message) })));
  }
  report.responses.push({
    ...address(response.url()),
    method: response.request().method(),
    status: response.status(),
    requestOrigin: response.request().headers().origin || null,
    allowOrigin: headers["access-control-allow-origin"] || null,
    allowMethods: headers["access-control-allow-methods"] || null,
    allowHeaders: headers["access-control-allow-headers"] || null,
    vary: headers.vary || null,
  });
});
context.on("requestfailed", (request) => {
  report.requestFailures.push({ ...address(request.url()), error: clean(request.failure()?.errorText) });
});
function observe(p) {
  p.on("pageerror", (error) => report.pageErrors.push(clean(error.message)));
  p.on("console", (message) => {
    if (/CORS|Cross-Origin|Access-Control|Content Security Policy|connect-src/i.test(message.text())) {
      report.corsErrors.push(clean(message.text()));
    }
  });
}
observe(page);
async function throwAlert(p) {
  if (await p.locator("#alert").isVisible()) {
    throw new Error(await p.locator("#alert").innerText());
  }
}
async function ready(p, url) {
  const response = await p.goto(url.href, { waitUntil: "domcontentloaded" });
  assert(response?.ok(), "gateway page HTTP " + response?.status());
  assert.equal(new URL(p.url()).origin, url.origin, "gateway changed the wallet origin");
  assert.equal(await p.evaluate(() => isSecureContext), true);
  await p.waitForFunction(() => document.documentElement.dataset.ready === "true" || (document.querySelector("#alert") && !document.querySelector("#alert").hidden), null, { timeout: 60000 });
  await throwAlert(p);
  await p.waitForFunction(() => document.querySelector("#service")?.textContent.startsWith("Chat ready") || (document.querySelector("#alert") && !document.querySelector("#alert").hidden), null, { timeout: 60000 });
  await throwAlert(p);
}
async function storage(p, sentinel, write = false) {
  return await p.evaluate(({ sentinel, write }) => new Promise((resolve, reject) => {
    const key = "ipfs-origin-check", open = indexedDB.open("dsmack-private-agent", 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result, tx = db.transaction("wallet", write ? "readwrite" : "readonly"), store = tx.objectStore("wallet");
      if (write) { store.put(sentinel, key); localStorage.setItem(key, sentinel); }
      let hasBurner = false, hasSentinel = false, sentinelMatches = false;
      store.get("burner").onsuccess = (e) => { hasBurner = Boolean(e.target.result); };
      store.get(key).onsuccess = (e) => { hasSentinel = e.target.result !== undefined; sentinelMatches = e.target.result === sentinel; };
      tx.oncomplete = () => { db.close(); resolve({ hasBurner, hasSentinel, sentinelMatches, localStorageHasSentinel: localStorage.getItem(key) !== null, localStorageMatches: localStorage.getItem(key) === sentinel }); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  }), { sentinel, write });
}
async function untouched() {
  assert.equal(await page.locator("#policy").inputValue(), "");
  assert.equal(await page.locator("#repo").inputValue(), "");
  assert.equal(await page.locator(".trust").evaluate((e) => e.open), false);
}
try {
  await ready(page, pageUrl);
  const cfg = await page.evaluate(async () => await (await fetch("./config.json")).json());
  for (const key of ["broker", "rpc", "tunnels"]) assert.equal(new URL(cfg[key]).protocol, "https:", key + " must be explicit HTTPS");
  assert.match(cfg.registry, /^0x[0-9a-f]{40}$/i);
  report.services = { broker: cfg.broker, rpc: cfg.rpc, tunnels: cfg.tunnels, registry: cfg.registry };
  report.tunnels = await page.evaluate(async (url) => {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) throw new Error("Tunnel index HTTP " + response.status);
    const entries = await response.json();
    if (!Array.isArray(entries)) throw new Error("Tunnel index is not an array");
    return { url: response.url, status: response.status, type: response.type, entries: entries.length };
  }, cfg.tunnels);
  await untouched();
  assert.match(await page.locator("#job-prompt").inputValue(), /greet\.txt/);
  assert.match(await page.locator("#wallet").innerText(), /No wallet connected/);
  await page.screenshot({ path: resolve(evidence, "01-first-visit.png"), fullPage: true });
  await page.locator("#burner").click();
  await page.waitForFunction(() => document.querySelector("#chat-credit")?.dataset.remainingNanoUsd || (document.querySelector("#alert") && !document.querySelector("#alert").hidden), null, { timeout: 60000 });
  await throwAlert(page);
  report.wallet = (await page.locator("#wallet").innerText()).trim();
  assert.match(report.wallet, /^0x[0-9a-f]{40}$/i);
  report.creditBeforeNanoUsd = await page.locator("#chat-credit").getAttribute("data-remaining-nano-usd");
  assert(BigInt(report.creditBeforeNanoUsd) > 0n);
  const sentinel = randomUUID();
  await storage(page, sentinel, true);
  await ready(page, pageUrl);
  assert.equal((await page.locator("#wallet").innerText()).trim(), report.wallet);
  report.sameOriginStorage = await storage(page, sentinel);
  assert(report.sameOriginStorage.hasBurner && report.sameOriginStorage.sentinelMatches && report.sameOriginStorage.localStorageMatches);
  await page.screenshot({ path: resolve(evidence, "02-wallet-reloaded.png"), fullPage: true });
  const reply = "IPFS_CHAT_OK", editor = page.locator("agent-interface message-editor");
  await editor.locator("textarea").fill("Reply with exactly IPFS_CHAT_OK.");
  await editor.locator("textarea").press("Enter");
  await page.waitForFunction((reply) => ([...document.querySelectorAll("agent-interface assistant-message")].some((e) => e.textContent.includes(reply)) && document.querySelector("agent-interface message-editor").isStreaming === false) || (document.querySelector("#alert") && !document.querySelector("#alert").hidden), reply, { timeout: 180000 });
  await throwAlert(page);
  await page.waitForFunction((before) => document.querySelector("#chat-credit").dataset.remainingNanoUsd !== before, report.creditBeforeNanoUsd, { timeout: 60000 });
  report.creditAfterNanoUsd = await page.locator("#chat-credit").getAttribute("data-remaining-nano-usd");
  assert(BigInt(report.creditAfterNanoUsd) >= 0n && BigInt(report.creditAfterNanoUsd) < BigInt(report.creditBeforeNanoUsd));
  assert.match(await page.locator("#attestations .badge").last().innerText(), /Broker verified quote.*Browser checked nonce and encryption key/);
  assert.equal(await editor.locator("textarea").inputValue(), "");
  report.chat = { completed: true, reply, quoteVerified: true, nonceAndEncryptionKeyChecked: true };
  await page.screenshot({ path: resolve(evidence, "03-attested-chat.png"), fullPage: true });
  await page.locator("#run").click();
  await page.waitForFunction(() => document.querySelector("#job-status").dataset.patchApplied === "true" || (document.querySelector("#alert") && !document.querySelector("#alert").hidden), null, { timeout: 360000 });
  await throwAlert(page);
  assert.equal(await page.locator('#updated-files pre[data-file="greet.txt"]').innerText(), "Hello from the private agent.\n");
  await page.waitForFunction(() => document.querySelector("#sandbox-credit").dataset.status === "completed");
  const job = JSON.parse(await page.locator("#job-evidence").textContent());
  assert.match(await page.locator("#job-status").innerText(), /Verified job attestation and receipt.*Patch applied/);
  const transcript = (await page.locator("#transcript").textContent()).trim().split("\n").filter(Boolean).map((s) => JSON.parse(s));
  const providerAttestations = transcript.filter((e) => e.type === "provider_attestation").length;
  assert(providerAttestations > 0);
  const [download] = await Promise.all([page.waitForEvent("download"), page.locator("#download").click()]);
  const patchPath = resolve(evidence, "patch.diff");
  await download.saveAs(patchPath);
  const { readFile } = await import("node:fs/promises");
  assert.equal(createHash("sha256").update(await readFile(patchPath)).digest("hex"), job.statement.outputs.patch);
  await writeFile(resolve(evidence, "job-evidence.json"), JSON.stringify(job, null, 2) + "\n");
  report.sandbox = { jobId: job.statement.job_id, secondsUsed: job.statement.seconds_used, patchApplied: true, outputHashes: job.statement.outputs, providerAttestations, status: "completed" };
  await untouched();
  await page.screenshot({ path: resolve(evidence, "04-verified-patch-applied.png"), fullPage: true });
  if (!publicGateway) {
  const alternate = await context.newPage();
  observe(alternate);
  await ready(alternate, alternateUrl);
  assert.match(await alternate.locator("#wallet").innerText(), /No wallet connected/);
  report.otherOriginStorage = await storage(alternate, sentinel);
  assert.deepEqual(report.otherOriginStorage, { hasBurner: false, hasSentinel: false, sentinelMatches: false, localStorageHasSentinel: false, localStorageMatches: false });
  report.origins = { first: pageUrl.origin, alternate: new URL(alternate.url()).origin, sameCid: true, sameBrowserContext: true, secureContexts: true };
  await alternate.screenshot({ path: resolve(evidence, "05-other-gateway-isolated.png"), fullPage: true });
  }
  const jobs = report.requests.filter((r) => r.method === "POST" && r.path.endsWith("/sandbox/jobs"));
  assert.equal(jobs.length, 1, "the flow must not resubmit its sandbox job");
  assert.equal(report.chainTransactionsAttempted, 0);
  assert.deepEqual(report.navigationViolations, []);
  assert.deepEqual(report.pageErrors, []);
  report.status = "passed";
} catch (error) {
  report.error = clean(error.message);
  report.alert = clean(await page.locator("#alert").textContent().catch(() => "alert unavailable"));
  await page.screenshot({ path: resolve(evidence, "failure.png"), fullPage: true }).catch((e) => { report.screenshotError = clean(e.message); });
  process.exitCode = 1;
} finally {
  await Promise.all(responseReads);
  await writeFile(resolve(evidence, "ipfs-browser.json"), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ status: report.status, wallet: report.wallet, origins: report.origins, chat: report.chat, sandbox: report.sandbox, error: report.error }));
  await context.close();
  await browser.close();
}
