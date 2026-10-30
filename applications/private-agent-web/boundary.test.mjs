import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { verifyMessage, Wallet, keccak256 } from "ethers";
import { sealArtifact, sharedScope, viewerSessionId } from "./artifact-share.mjs";
import { artifactTestServer } from "./artifact-test-server.mjs";
const base = process.env.BASE_URL || "http://127.0.0.1:18731/private-agent/";
const evidence = resolve(process.env.EVIDENCE || "local-data/chat-boundaries");
const moduleName = process.env.PLAYWRIGHT_MODULE || "playwright";
const { chromium } = await import(
  isAbsolute(moduleName) ? pathToFileURL(moduleName).href : moduleName
);
const tls = await artifactTestServer({mainRoot:resolve("dist")});
const browser = process.env.PLAYWRIGHT_CDP_URL
  ? await chromium.connectOverCDP(process.env.PLAYWRIGHT_CDP_URL)
  : await chromium.launch({
    headless: true,
    ...(process.env.CHROMIUM_PATH
      ? { executablePath: process.env.CHROMIUM_PATH }
      : {}),
    args: ["--no-sandbox",...tls.args],
  });
await mkdir(evidence, { recursive: true });
const model = "deepseek-ai/DeepSeek-V4-Flash", modelKey = Wallet.createRandom();
const report = {
  scope: "Browser wallet, credit and encryption boundaries",
  cases: [],
};
const canonical = (o) =>
  JSON.stringify(
    Object.fromEntries(Object.keys(o).sort().map((key) => [key, o[key]])),
  );
let partialCredit;
const reservation = (body) => BigInt(
  Buffer.byteLength(JSON.stringify(body)) + 256 +
    64 * body.messages.length + body.max_tokens,
) * 1500n;
const publicHeaders = {
  "content-type": "application/json",
  "access-control-allow-origin": new URL(base).origin,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};
async function backend(page, kind) {
  const cfg = await (await page.request.get(new URL("config.json", base).href))
    .json();
  cfg.syncAnchorCodeHash = keccak256("0x6000");
  await page.route("**/config.json", route => route.fulfill({headers:publicHeaders,body:JSON.stringify(cfg)}));
  await page.route(cfg.rpc, route => {
    const raw = route.request().postDataJSON();
    const reply = r => ({jsonrpc:"2.0",id:r.id,result:r.method==="eth_chainId"?"0x14a34":r.method==="eth_getCode"?"0x6000":"0x"+"0".repeat(128)});
    return route.fulfill({headers:publicHeaders,body:JSON.stringify(Array.isArray(raw)?raw.map(reply):reply(raw))});
  });
  const calls = [];
  let recoveredEnded = false;
  await page.route("**/relay-broker/**", async (route) => {
    const req = route.request(),
      path = new URL(req.url()).pathname.replace("/relay-broker", "");
    const responseHeaders = { ...publicHeaders, "access-control-allow-origin": req.headers().origin || publicHeaders["access-control-allow-origin"] };
    if (req.method() === "OPTIONS") return route.fulfill({status: 204, headers: responseHeaders});
    const body = req.method() === "POST" ? req.postDataJSON() : undefined;
    calls.push({ path, method: req.method(), body });
    const respond = (value, status = 200) =>
      route.fulfill({
        status,
        headers: responseHeaders,
        body: JSON.stringify(value),
      });
    if (path === "/key") {
      return respond({ algorithm: "Ed25519", public_key: cfg.brokerKey });
    }
    if (path === "/payments/key") {
      return respond({
        address: cfg.grantSigner,
        chainId: 84532,
        escrow: cfg.escrow,
        codeHash: cfg.codeHash,
      });
    }
    if (path === "/payments/classes") return respond([]);
    if (path === "/inference/quote") {
      return respond({
        configured: true,
        mode: "broker-e2ee",
        provider: "near",
        model,
        starterCreditNanoUsd: "250000000",
        maxOutputTokens: 512,
        maxNanoUsdPerToken: "1500",
        maxRequestBytes: 32768,
      });
    }
    if (body) {
      const { sig, ...signed } = body;
      assert.equal(
        verifyMessage(canonical(signed), sig).toLowerCase(),
        body.wallet.toLowerCase(),
        "wallet action signature",
      );
    }
    if (path === "/sync/head") return respond({head:null});
    if (path === "/workspaces/head") return respond({head:null});
    if (path.startsWith("/sync/")) return respond({ error: {
      code: "SYNTHETIC_SYNC_UNAVAILABLE",
      message: "Encrypted sync is unavailable in this inference fixture.",
    } }, 503);
    const credit = {
      wallet: body?.wallet?.toLowerCase(),
      model,
      mode: "broker-e2ee",
      grantedNanoUsd: "250000000",
      spentNanoUsd: "0",
      remainingNanoUsd: kind === "insufficient" ? "1" : kind === "partial" ? partialCredit : "250000000",
      reservedNanoUsd: "0",
      usedTokens: "0",
      pendingInferenceId: null,
    };
    if (kind === "recovery" && (path === "/agent/status" || path === "/agent/end")) {
      if (path === "/agent/end") recoveredEnded = true;
      return respond({ sessionId: body.sessionId, active: !recoveredEnded, guestSeconds: 17, credit });
    }
    if (path === "/inference/credit" || path === "/inference/usage") {
      return respond(credit);
    }
    if (path === "/inference/prepare") {
      return respond({
        ...credit,
        sessionId: "12".repeat(16),
        modelPublicKey: kind === "key"
          ? Wallet.createRandom().signingKey.publicKey.slice(4)
          : modelKey.signingKey.publicKey.slice(4),
        expiresAt: Math.floor(Date.now() / 1000) + 60,
        attestation: {
          mode: "broker-e2ee",
          provider: "near",
          model: kind === "model" ? model + "-other" : model,
          verification: "verified",
          verifier: "synthetic-browser-boundary",
          nonce: kind === "nonce" ? "00".repeat(32) : body.attestationNonce,
          verifiedAt: Math.floor(Date.now() / 1000),
          gateway: {
            signingAddress: "0x" + "11".repeat(20),
            tlsFingerprint: "22".repeat(32),
          },
          models: [{ model, signingAddress: modelKey.address }],
          tls: {
            checkedBy: "broker",
            browserObservable: false,
            binding: "spki",
          },
        },
      });
    }
    if (path === "/inference/chat") {
      return respond({
        error: {
          code: "SYNTHETIC_STOP",
          message: "Encrypted request captured; no provider call",
        },
      }, 503);
    }
    throw new Error("Unexpected synthetic route " + path);
  });
  return calls;
}
async function ready(page) {
  await page.goto(base);
  await page.waitForFunction(() =>
    document.documentElement.dataset.ready === "true"
  );
  await page.waitForFunction(() =>
    document.querySelector("#service").textContent.startsWith("Chat ready")
  );
}
async function send(page, text) {
  const editor = page.locator("agent-interface message-editor");
  const input = editor.locator('textarea,[contenteditable="true"]').first();
  await input.fill(text);
  const button = editor.getByRole("button", { name: /send/i });
  if (await button.count()) await button.first().click();
  else await input.press("Enter");
}
async function alert(page, pattern) {
  await page.waitForFunction(
    (source) => {
      const e = document.querySelector("#alert");
      return e && !e.hidden && new RegExp(source, "i").test(e.textContent);
    },
    pattern,
    { timeout: 15000 },
  );
}
async function sharedAppFrame(page) {
  for (let retry = 0; retry < 50; retry++) {
    for (const frame of page.frames()) {
      if (!frame.url().startsWith("blob:")) continue;
      // The native isolation loader also uses a temporary blob probe frame.
      if (await frame.locator("#shared-ready").count().catch(() => 0)) return frame;
    }
    await page.waitForTimeout(100);
  }
}
async function run(name, kind, fn) {
  const ctx = await browser.newContext(),
    page = await ctx.newPage(),
    errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const result = { name, status: "failed" };
  try {
    const calls = await backend(page, kind);
    await ready(page);
    if (name !== "first-visit-requires-choice") {
      await page.locator("#start-fresh").click();
      await page.waitForFunction(() => document.querySelector("#chat-credit").dataset.remainingNanoUsd !== "");
    }
    await fn(page, calls);
    assert.deepEqual(errors, []);
    result.status = "passed";
    await page.screenshot({
      path: resolve(evidence, name + ".png"),
      fullPage: true,
    });
  } catch (e) {
    result.error = e.message;
    result.alert = await page.locator("#alert").textContent();
    result.chatStatus = await page.locator("#chat-status").textContent();
    await page.screenshot({ path: resolve(evidence, name + "-failed.png"), fullPage: true });
  }
  report.cases.push(result);
  await ctx.close();
  console.log(result.status + ": " + name);
}
try {
  await run("shared-viewer-requires-own-wallet-and-keeps-encrypted-state-on-reload", "valid", async (page, calls) => {
    const sealed = await sealArtifact('<!doctype html><button id="shared-ready">Shared app</button>');
    const origin = "https://private-agent.dstack.soc1024.com";
    await page.route(origin + "/**", async route => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith("config.json")) return route.fallback();
      return route.continue();
    });
    await page.route("**/artifacts/share/" + sealed.cid, route => route.fulfill({ headers:{...publicHeaders,"access-control-allow-origin":origin}, body:JSON.stringify({cid:sealed.cid,ciphertext:sealed.ciphertext}) }));
    await page.goto(origin + "/a/#" + new URLSearchParams({cid:sealed.cid,k:sealed.key}));
    await page.waitForSelector("#chat");
    assert(await page.locator("#start-fresh").isVisible());
    assert.equal(await page.locator("#artifacts-host artifacts-panel").count(),0);
    await page.locator("#start-fresh").click();
    await page.waitForFunction(()=>document.querySelector("#artifacts-host artifacts-panel"));
    await page.waitForFunction(()=>Array.from(document.querySelectorAll("iframe")).length>0);
    let app = await sharedAppFrame(page);
    assert(app,"shared HTML opens without a model request");
    await app.waitForFunction(()=>window.dsmack);
    assert.equal(await app.evaluate(()=>dsmack.storage.get("viewer-secret")),null);
    await app.evaluate(()=>dsmack.storage.put("viewer-secret","VIEWER_PRIVATE_STATE"));
    const wallet=(await page.locator("#wallet").textContent()).trim().match(/0x[0-9a-f]{40}/i)[0];
    assert.equal(await page.locator("#chat").getAttribute("data-session-id"),viewerSessionId(wallet,sealed.cid));
    await page.reload();await page.waitForSelector("#chat");
    app = await sharedAppFrame(page);
    assert(app);await app.waitForFunction(()=>window.dsmack);
    assert.equal(await app.evaluate(()=>dsmack.storage.get("viewer-secret")),"VIEWER_PRIVATE_STATE");
    assert.equal(await page.locator("#chat").getAttribute("data-session-id"),viewerSessionId(wallet,sealed.cid));
    assert(!calls.some(call=>call.path==="/inference/chat"),"opening a shared app must not create a model turn");
  });
  await run("directory-outages-preserve-broker-and-chain-errors", "valid", async (page, calls) => {
    let brokerReads = 0;
    const rpcReads = [];
    await page.route("**/relay-broker/nodes*", route => {
      brokerReads++;
      return route.fulfill({ status: 500, headers: publicHeaders, body: "{}" });
    });
    for (const host of ["sepolia.base.org", "base-sepolia-rpc.publicnode.com"]) {
      await page.route(`https://${host}/**`, route => {
        rpcReads.push(host);
        return route.fulfill({ status: 503, headers: publicHeaders, body: "{}" });
      });
    }
    await page.locator("#discover").evaluate(button => { button.closest("details").open = true; });
    await page.locator("#discover").click();
    await alert(page, "Chain directory failed");
    const shown = await page.locator("#directory-status").innerText();
    assert.match(shown, /Directory: chain/);
    assert.match(shown, /Broker guest directory unavailable.*500/);
    assert.match(shown, /Chain directory failed.*503/);
    assert.equal(brokerReads, 1, "Outage discovery must not silently retry the broker");
    assert(new Set(rpcReads).size === 2, "Both chain providers are checked");
    assert(!calls.some(r => r.path === "/agent/open" || r.path.includes("/attestation")));
  });
  await run("first-visit-requires-choice", "valid", async (page, calls) => {
    assert.doesNotMatch(await page.locator("#wallet").textContent(), /^0x/i);
    assert(await page.locator("#start-fresh").isVisible());
    assert.equal(await page.locator("#artifacts-host artifacts-panel").count(), 0,
      "Artifact state and providers wait for the viewer's data key");
    await page.locator("#used-before").click();
    assert(await page.locator("#continuity-panel").isVisible());
    assert(await page.locator("#enroll-email").isDisabled());
    await page.locator("#use-another-device").click();
    await page.locator("#start-fresh").click();
    await page.waitForFunction(() => document.querySelector("#artifacts-host artifacts-panel"));
    await page.waitForFunction(() => document.querySelector("#chat-credit").dataset.remainingNanoUsd !== "");
    await page.waitForFunction(() => document.querySelector("#sync-status").textContent === "Chats checked and synced.");
    assert(!calls.some(r => r.path === "/sync/blob" || r.path === "/sync/commit"), "An empty wallet must not publish system-only chats");
    await ready(page);
    await page.waitForFunction(() => document.querySelector("#sync-status").textContent === "Chats checked and synced.");
    assert(!calls.some(r => r.path === "/sync/blob" || r.path === "/sync/commit"), "Reloading an empty wallet must not commit empty chats");
    const marker = "FIRST_VISIT_PROMPT_STAYS_ENCRYPTED";
    assert.match(await page.locator("#wallet").textContent(), /^0x[0-9a-f]{40}$/i);
    assert.equal(await page.locator("#continuity-panel").isVisible(), false);
    assert.equal(await page.locator("#policy").inputValue(), "");
    assert.match(
      await page.locator("#node-status").textContent(),
      /Approved sandbox policy included/,
    );
    assert.match(await page.locator("#repository-status").textContent(), /greet.txt/);
    await send(page, marker);
    await alert(page, "SYNTHETIC_STOP");
    await page.waitForFunction(() => document.querySelector("#chat").dataset.saved === "true" && !document.querySelector("message-editor").isStreaming);
    await page.waitForFunction(() => document.querySelector("#chat-status").textContent.includes("Sync pending"));
    assert.match(await page.locator("#alert").textContent(), /SYNTHETIC_STOP/,
      "Background sync failure must preserve the model error");
    assert(calls.some((r) => r.path === "/sync/blob"), "Saved chat attempted encrypted synchronization");
    assert(!calls.filter((r) => r.path.startsWith("/sync/")).some((r) => JSON.stringify(r.body).includes(marker)),
      "Plaintext prompt reached chat synchronization");
    assert.match(await page.locator("user-message").innerText(), new RegExp(marker));
    assert.equal(await page.locator("agent-interface message-editor textarea").inputValue(), "");
    assert.match(
      await page.locator("#wallet").textContent(),
      /^0x[0-9a-f]{40}$/i,
    );
    assert(calls.some((r) => r.path === "/inference/credit"));
    const chat = calls.find((r) => r.path === "/inference/chat");
    assert(chat && !JSON.stringify(chat.body).includes(marker));
    partialCredit = (reservation(chat.body.body) - 200n * 1500n).toString();
    assert.equal(await page.locator("#wallet-tools").isVisible(), true);
  });
  await run("guest-is-lazy-until-a-tool-call", "valid", async (page, calls) => {
    assert.equal(await page.locator("#end-session").isDisabled(), true);
    assert.equal(await page.locator("#download").isDisabled(), true);
    await send(page, "A chat request alone must not allocate a guest.");
    await alert(page, "SYNTHETIC_STOP");
    assert(!calls.some(r => r.path.startsWith("/agent/")));
    assert.equal(await page.locator("#guest-status").getAttribute("data-state"), "idle");
  });
  await run("inline-tool-output-and-markdown-code-visible", "valid", async (page, calls) => {
    // Display fixture derived from the real guest script journey. No model or
    // guest request is made: this catches missing custom-element registration.
    await page.evaluate(async () => {
      const chat = document.querySelector("agent-interface"), model = chat.session.state.model;
      const usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
      const assistant = content => ({ role: "assistant", content, api: model.api, provider: model.provider,
        model: model.id, usage, stopReason: "stop", timestamp: Date.now() });
      chat.session.state.messages = [
        assistant([{ type: "toolCall", id: "render-write", name: "write", arguments: { path: "/workspace/proof-script.sh", content: "echo DSMACK_GUEST_SCRIPT_OK" } },
          { type: "toolCall", id: "render-bash", name: "bash", arguments: { command: "bash /workspace/proof-script.sh" } }]),
        { role: "toolResult", toolCallId: "render-write", toolName: "write", isError: false, content: [{ type: "text", text: "Successfully wrote to /workspace/proof-script.sh" }], details: {}, timestamp: Date.now() },
        { role: "toolResult", toolCallId: "render-bash", toolName: "bash", isError: false, content: [{ type: "text", text: "DSMACK_GUEST_SCRIPT_OK\n6 * 7 = 42\n" }], details: {}, timestamp: Date.now() },
        assistant([{ type: "text", text: "Output:\n```text\nDSMACK_GUEST_SCRIPT_OK\n6 * 7 = 42\n```" }]),
      ];
      chat.requestUpdate(); await chat.updateComplete;
    });
    const bash = page.locator("tool-message").filter({ has: page.locator("console-block") });
    await bash.locator("console-block pre").waitFor({ state: "visible" });
    assert.match(await bash.innerText(), /bash · completed/);
    assert.doesNotMatch(await bash.innerText(), /bash · running|Running command/);
    assert.match(await bash.locator("console-block pre").innerText(), /bash \/workspace\/proof-script\.sh[\s\S]*DSMACK_GUEST_SCRIPT_OK[\s\S]*42/);
    const write = page.locator("tool-message").filter({ has: page.locator("code-block") });
    assert.match(await write.innerText(), /Successfully wrote to \/workspace\/proof-script\.sh/);
    const fenced = page.locator("assistant-message markdown-block code-block pre code");
    await fenced.waitFor({ state: "visible" });
    assert.match(await fenced.innerText(), /DSMACK_GUEST_SCRIPT_OK[\s\S]*42/);
    assert(!calls.some(r => r.path.startsWith("/agent/") || r.path === "/inference/chat"));
  });
  await run("held-guest-can-be-ended-after-reload", "recovery", async (page, calls) => {
    await send(page, "Saved conversation survives lease recovery.");
    await alert(page, "SYNTHETIC_STOP");
    await page.waitForFunction(() => document.querySelector("#chat").dataset.saved === "true" && !document.querySelector("message-editor").isStreaming);
    const wallet = (await page.locator("#wallet").textContent()).toLowerCase();
    await page.evaluate(wallet => new Promise((resolve, reject) => {
      const id = document.querySelector("#chat").dataset.sessionId;
      const open = indexedDB.open("dsmack-private-agent-chats", 1);
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result, tx = db.transaction("sessions", "readwrite"), store = tx.objectStore("sessions");
        const get = store.get(id);
        get.onsuccess = () => {
          const data = get.result;
          data.dsmack.guest = { sessionId: "ab".repeat(16), conversationId: id, wallet, active: true,
            guestSeconds: 12, node: { relay_peer: "saved-guest" } };
          if (store.keyPath) store.put(data); else store.put(data, id);
        };
        tx.oncomplete = () => { db.close(); resolve(); };
        tx.onerror = () => { db.close(); reject(tx.error); };
      };
    }), wallet);
    await ready(page);
    await page.waitForFunction(() => document.querySelector("#guest-status").dataset.state === "disconnected-held");
    assert.equal(await page.locator("#end-session").isEnabled(), true);
    assert.equal(await page.locator("#download").isDisabled(), true);
    assert.match(await page.locator("user-message").innerText(), /Saved conversation survives/);
    assert.equal(await page.locator("#attestations .evidence-item").count(), 1);
    await page.locator("#end-session").click();
    await page.waitForFunction(() => document.querySelector("#guest-status").dataset.state === "released");
    assert(calls.some(r => r.path === "/agent/status" && r.body.wallet.toLowerCase() === wallet));
    assert(calls.some(r => r.path === "/agent/end" && r.body.sessionId === "ab".repeat(16)));
    assert(!calls.some(r => r.path === "/agent/open"));
  });
  for (const kind of ["nonce", "key", "model"]) {
    await run(
      "provider-" + kind + "-refused-before-chat",
      kind,
      async (page, calls) => {

        await page.waitForFunction(() =>
          document.querySelector("#chat-credit").textContent ===
            "Chat credit $0.250000"
        );
        await send(
          page,
          "Private fixture prompt refused before any chat POST.",
        );
        await alert(
          page,
          kind === "nonce"
            ? "stale or reused nonce"
            : kind === "key"
            ? "differs from the attested signing address"
            : "invalid or names another model",
        );
        assert(calls.some((r) => r.path === "/inference/prepare"));
        assert(!calls.some((r) => r.path === "/inference/chat"));
      },
    );
  }
  await run("remaining-credit-reduces-encrypted-output-limit", "partial", async (page, calls) => {
    await send(page, "FIRST_VISIT_PROMPT_STAYS_ENCRYPTED");
    await alert(page, "SYNTHETIC_STOP");
    const chat = calls.find((r) => r.path === "/inference/chat");
    assert(chat, "Affordable encrypted request was refused");
    const body = chat.body.body, available = BigInt(partialCredit);
    assert(body.max_tokens >= 64 && body.max_tokens < 512);
    assert(reservation(body) <= available, "Encrypted reservation exceeds remaining credit");
    assert(reservation({ ...body, max_tokens: body.max_tokens + 1 }) > available,
      "Output limit leaves an affordable token unused");
    assert(!JSON.stringify(chat.body).includes("FIRST_VISIT_PROMPT_STAYS_ENCRYPTED"));
  });
  await run("insufficient-reservation-refused-before-chat", "insufficient", async (page, calls) => {

    await page.waitForFunction(() => document.querySelector("#chat-credit").dataset.remainingNanoUsd === "1");
    await send(page, "Private text must stay here when the token reservation exceeds credit.");
    await alert(page, "CREDIT_EXHAUSTED: Chat credit used up\\.");
    assert(calls.some((r) => r.path === "/inference/prepare"));
    assert(!calls.some((r) => r.path === "/inference/chat"), "Underfunded prompt left the browser");
  });
  await run(
    "starter-credit-and-encrypted-wire",
    "valid",
    async (page, calls) => {

      await page.waitForFunction(() =>
        document.querySelector("#chat-credit").textContent ===
          "Chat credit $0.250000"
      );
      const wallet = await page.locator("#wallet").textContent();
      await ready(page);
      assert.equal(await page.locator("#wallet").textContent(), wallet);
      await page.waitForFunction(() =>
        document.querySelector("#chat-credit").textContent ===
          "Chat credit $0.250000"
      );
      const marker = "W1_BROWSER_ONLY_PROMPT_9b5cb2d3";
      await send(page, marker);
      await alert(page, "SYNTHETIC_STOP");
      const chat = calls.find((r) => r.path === "/inference/chat");
      assert(chat, "encrypted chat POST missing");
      assert(
        !JSON.stringify(chat.body).includes(marker),
        "plaintext prompt reached chat transport",
      );
      assert.equal(chat.body.headers["x-signing-algo"], "ecdsa");
      assert.equal(chat.body.headers["x-encrypt-all-fields"], "true");
      assert(
        chat.body.body.messages.every((m) => /^04[0-9a-f]+$/i.test(m.content)),
      );
      assert(chat.body.body.tools.length > 0, "encrypted tool catalog missing");
      for (const tool of chat.body.body.tools) {
        for (const field of ["name", "description", "parameters"]) assert.match(tool.function[field], /^04[0-9a-f]+$/i);
      }
      assert.equal(
        await page.locator("#attestations .evidence-item").count(),
        1,
      );
    },
  );
} finally {
  report.passed = report.cases.every((c) => c.status === "passed");
  await writeFile(
    resolve(evidence, "boundary-results.json"),
    JSON.stringify(report, null, 2),
  );
  await browser.close();
  await tls.close();
}
if (!report.passed) process.exitCode = 1;
