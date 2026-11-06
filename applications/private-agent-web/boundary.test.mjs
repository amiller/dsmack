import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { backend, ready, send, publicHeaders, reservation, partialCredit, setPartialCredit } from "./test-fixtures/browser-broker.mjs";
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

const report = {
  scope: "Browser wallet, credit and encryption boundaries",
  cases: [],
};
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
  if (process.env.BOUNDARY_CASE && process.env.BOUNDARY_CASE !== name) return;
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
  await run("browser-provider-key-bypasses-model-credit-and-restores-selection", "valid", async (page, calls) => {
    const requests = [];
    await page.route("https://model.example/v1/chat/completions", async route => {
      requests.push({ body: route.request().postDataJSON(), headers: route.request().headers() });
      await route.fulfill({ headers: { "content-type": "text/event-stream", "access-control-allow-origin": "*" },
        body: 'data: {"id":"reply","choices":[{"delta":{"role":"assistant","content":"Direct provider reply."},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":2,"total_tokens":4}}\n\ndata: [DONE]\n\n' });
    });
    assert(!(await page.locator("#model").textContent()).includes("sees the conversation"));
    await page.locator("#advanced summary").first().click();
    await page.locator("#provider-settings").click();
    await page.selectOption("#provider-choice", "openai-compatible");
    await page.fill("#provider-model", "my-model");
    await page.fill("#provider-url", "https://model.example/v1");
    await page.fill("#provider-key", "browser-only-provider-secret");
    await page.click("#provider-save");
    await page.locator("#provider-dialog").waitFor({ state: "hidden" });
    assert.equal(requests.length, 1, "saving checks browser connectivity with an isolated prompt");
    assert.equal(requests[0].body.messages.at(-1).content, "Reply OK.");
    assert.match(await page.locator("#model").textContent(), /model.example sees the conversation/);
    assert.equal(await page.locator("#verified").isHidden(), true);
    await page.route("**/relay-broker/inference/credit", route => route.fulfill({ headers: publicHeaders, body: JSON.stringify({
      wallet: route.request().postDataJSON().wallet.toLowerCase(), remainingNanoUsd: "0", spentNanoUsd: "250000000", usedTokens: "0", pendingInferenceId: null,
    }) }));
    await send(page, "Please inspect this conversation.");
    await page.waitForFunction(() => document.querySelector('#chat').session.state.messages.some(m => m.role === 'assistant') && !document.querySelector('#chat').session.state.isStreaming);
    assert.equal(requests.length, 2);
    assert.equal(requests[1].headers.authorization, "Bearer browser-only-provider-secret");
    assert.match(requests[1].body.messages[0].content, /model.example.*sees the conversation/);
    assert(!requests[1].body.messages[0].content.includes("encrypted from the browser to the NEAR model TEE"));
    assert(requests[1].body.tools.some(tool => tool.function.name === "bash"));
    assert(!calls.some(call => ["/inference/prepare", "/inference/chat"].includes(call.path)), "direct model tokens cannot consume broker credit");
    const stores = await page.evaluate(async () => {
      const db = await new Promise((resolve, reject) => { const req = indexedDB.open("dsmack-private-agent-chats"); req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error); });
      const read = name => new Promise((resolve, reject) => { const req = db.transaction(name).objectStore(name).getAll(); req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error); });
      return { keys: await read("provider-keys"), providers: await read("custom-providers"), sessions: await read("sessions"), settings: await read("settings") };
    });
    assert(stores.keys.includes("browser-only-provider-secret"));
    assert(!JSON.stringify([stores.providers, stores.sessions, stores.settings, calls]).includes("browser-only-provider-secret"));
    await page.reload();
    await page.waitForFunction(() => document.documentElement.dataset.ready === "true");
    assert.match(await page.locator("#model").textContent(), /model.example sees the conversation/);
    await page.locator("#advanced summary").first().click();
    await page.locator("#provider-settings").click();
    assert.equal(await page.inputValue("#provider-key"), "");
    await page.selectOption("#provider-choice", "near");
    await page.click("#provider-save");
    await page.locator("#provider-dialog").waitFor({ state: "hidden" });
    assert(!(await page.locator("#model").textContent()).includes("sees the conversation"));
    assert.match(await page.locator("#model-privacy").textContent(), /encrypted.*NEAR model TEE/);
    assert.equal(requests.length, 2, "switching back to NEAR needs no key or connection test");
  });
  await run("anthropic-provider-sends-browser-header-and-accurate-preamble", "valid", async page => {
    const requests = [];
    await page.route("https://api.anthropic.com/v1/messages*", async route => {
      requests.push({ body: route.request().postDataJSON(), headers: route.request().headers() });
      await route.fulfill({ headers: { "content-type": "text/event-stream", "access-control-allow-origin": "*" }, body:
        'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}\n\nevent: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n' });
    });
    await page.locator("#advanced summary").first().click();
    await page.click("#provider-settings");
    await page.selectOption("#provider-choice", "anthropic");
    await page.fill("#provider-key", "sk-ant-browser-only");
    await page.click("#provider-save");
    await page.locator("#provider-dialog").waitFor({ state: "hidden" });
    assert.match(await page.locator("#model").textContent(), /Anthropic sees the conversation/);
    await send(page, "Inspect code with Anthropic.");
    await page.waitForFunction(() => document.querySelector('#chat').session.state.messages.some(m => m.role === 'assistant') && !document.querySelector('#chat').session.state.isStreaming);
    assert.equal(requests.length, 2);
    assert.equal(requests[1].headers["anthropic-dangerous-direct-browser-access"], "true");
    assert.equal(requests[1].headers["x-api-key"], "sk-ant-browser-only");
    assert.match(JSON.stringify(requests[1].body.system), /Anthropic.*sees the conversation/);
    assert(!JSON.stringify(requests[1].body.system).includes("encrypted from the browser to the NEAR model TEE"));
  });
  await run("browser-provider-rejects-unreachable-cors-endpoint", "valid", async page => {
    await page.route("https://blocked.example/**", route => route.abort("failed"));
    await page.locator("#advanced summary").first().click();
    await page.locator("#provider-settings").click();
    await page.selectOption("#provider-choice", "openai-compatible");
    await page.fill("#provider-model", "my-model");
    await page.fill("#provider-url", "https://blocked.example/v1");
    await page.fill("#provider-key", "unsaved-key");
    await page.click("#provider-save");
    await page.waitForFunction(() => document.querySelector("#provider-error").textContent.includes("Browser connection failed"));
    assert(!(await page.locator("#model").textContent()).includes("sees the conversation"));
    await page.click("#provider-cancel");
    await page.waitForFunction(() => document.querySelector("#provider-key").value === "");
  });
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
    await app.evaluate(() => { window.guestCancelled = dsmack.guest.run({command:"printf boundary-only",timeoutSeconds:1}).then(() => "unexpected", error => error.code); });
    await page.locator("#artifact-guest-card [data-guest-confirm]").waitFor({state:"visible"});
    assert.equal(await page.locator("[data-guest-command]").textContent(), "printf boundary-only");
    assert((await page.locator("[data-guest-wallet]").textContent()).toLowerCase().includes((await page.locator("#wallet").textContent()).toLowerCase()));
    await page.locator("[data-guest-cancel]").click();
    assert.equal(await app.evaluate(() => window.guestCancelled), "USER_CANCELLED");
    assert(!calls.some(call => call.path === "/agent/open"), "cancelled app confirmation cannot claim a guest");

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
    await page.locator("#advanced").evaluate(view => { view.open = true; });
    await page.locator("#discover").click();
    await alert(page, "Chain directory failed");
    const shown = await page.locator("#directory-status").innerText();
    assert.equal(await page.locator("#directory-status").getAttribute("data-path"), "chain");
    assert.match(shown, /Broker guest directory unavailable.*500/);
    assert.match(shown, /Chain directory failed.*503/);
    assert.equal(brokerReads, 1, "Outage discovery must not silently retry the broker");
    assert(new Set(rpcReads).size === 2, "Both chain providers are checked");
    assert(!calls.some(r => r.path === "/agent/open" || r.path.includes("/attestation")));
  });
  await run("broker-reads-retry-once-and-signed-posts-never-resend", "valid", async (page) => {
    let reads = 0, writes = 0;
    await page.route("**/relay-broker/inference/quote", route => ++reads === 1 ? route.abort("internetdisconnected") : route.fallback());
    await page.locator("#advanced").evaluate(view => { view.open = true; });
    await page.locator("#refresh").evaluate(button => { button.closest("details").open = true; });
    await page.locator("#refresh").click();
    await page.waitForFunction(() => !document.querySelector("#refresh").disabled);
    assert.equal(reads, 2);
    await page.route("**/relay-broker/inference/credit", route => { writes++; return route.abort("internetdisconnected"); });
    await page.locator("#refresh").click();
    await alert(page, "browser lost its connection");
    assert.equal(writes, 1, "a signed credit request is sent once");
    assert.doesNotMatch(await page.locator("#alert").textContent(), /broker.*restarting/i);
    reads = 0;
    await page.route("**/relay-broker/inference/quote", route => { reads++; return route.abort("internetdisconnected"); });
    await page.locator("#refresh").click();
    await page.waitForFunction(() => !document.querySelector("#refresh").disabled);
    assert.equal(reads, 2, "a second browser failure ends the read");
    assert.equal(writes, 1);
  });
  await run("switch-wallet-requires-recovery-and-confirmation", "valid", async (page) => {
    const wallet = await page.locator("#wallet").textContent();
    await page.locator("#advanced").evaluate(view => { view.open = true; });
    await page.locator("#use-another-device").click();
    await page.locator("#switch-wallet").click();
    await page.locator("#continuity-status").getByText(/Save a passkey or add a recovery email.*before switching/).waitFor();
    assert.equal(await page.locator("#wallet").textContent(), wallet);
    await page.evaluate(() => new Promise((resolve, reject) => {
      const open = indexedDB.open("dsmack-private-agent", 1);
      open.onsuccess = () => {
        const db = open.result, tx = db.transaction("wallet", "readwrite");
        tx.objectStore("wallet").put("saved-credential", "continuity.passkey");
        tx.oncomplete = () => { db.close(); resolve(); }; tx.onerror = () => reject(tx.error);
      };
    }));
    await Promise.all([page.waitForEvent("dialog").then(dialog => dialog.dismiss()), page.locator("#switch-wallet").click()]);
    await page.waitForFunction(() => !document.querySelector("#switch-wallet").disabled);
    assert.equal(await page.locator("#wallet").textContent(), wallet);
    await Promise.all([page.waitForEvent("dialog").then(dialog => { assert.match(dialog.message(), /saved passkey or email/); return dialog.accept(); }),
      page.locator("#switch-wallet").click()]);
    await page.locator("#welcome").waitFor({ state: "visible" });
    await page.waitForFunction(() => document.documentElement.dataset.ready === "true");
    assert.doesNotMatch(await page.locator("#wallet").textContent(), /^0x/i);
    await page.locator("#start-fresh").click();
    await page.waitForFunction(() => document.querySelector("#wallet").textContent.startsWith("0x"));
    assert.notEqual(await page.locator("#wallet").textContent(), wallet);
  });
  await run("first-visit-requires-choice", "valid", async (page, calls) => {
    assert.doesNotMatch(await page.locator("#wallet").textContent(), /^0x/i);
    assert(await page.locator("#start-fresh").isVisible());
    assert.equal(await page.locator("#artifacts-host artifacts-panel").count(), 0,
      "Artifact state and providers wait for the viewer's data key");
    await page.locator("#used-before").click();
    assert(await page.locator("#continuity-panel").isVisible());
    assert(await page.locator("#enroll-email").isDisabled());
    await page.locator("#advanced").evaluate(view => { view.open = true; });
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
    assert.equal(await page.locator("#repo").isEnabled(), true);
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
    setPartialCredit((reservation(chat.body.body) - 200n * 1500n).toString());
    assert.equal(await page.locator("#wallet-tools").getAttribute("hidden"), null);
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
    await page.locator("#sync-status").getByText("Chats checked and synced.", { exact: true }).waitFor({ state: "attached" });
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
    assert.equal(await page.locator("#verified").isVisible(), true);
    await page.locator("#advanced").evaluate(view => { view.open = true; });
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
            ? "nonce"
            : kind === "key"
            ? "differs from the attested signing address"
            : "invalid or names another model",
        );
        assert(calls.some((r) => r.path === "/inference/prepare"));
        assert(!calls.some((r) => r.path === "/inference/chat"));
      },
    );
  }
  await run("duplicate-chat-reconciles-before-offering-retry", "duplicate", async (page, calls) => {
    await send(page, "Reply once.");
    await alert(page, "REQUEST_ALREADY_DISPATCHED");
    await page.locator("#retry-reply").waitFor({state:"visible"});
    await page.waitForFunction(() => !document.querySelector("#chat")?.session?.state.isStreaming);
    assert.match(await page.locator("#reply-recovery").innerText(), /Reconcile provider usage/);
    assert.equal(calls.filter(call => call.path === "/inference/chat").length, 1);
    assert(calls.some(call => call.path === "/inference/usage"), "Duplicate delivery reconciles the original dispatch");
  });
  await run("request-ref-survives-actionable-rendering", "valid", async (page, calls) => {
    await send(page, "Reply once.");
    await alert(page, "SYNTHETIC_STOP");
    const request = calls.find(call => call.path === "/inference/chat");
    const text = await page.locator("#alert").innerText();
    const ref = request.body.nonce.slice(0, 8);
    assert(text.includes("ref " + ref));
    assert.equal(text.match(new RegExp("ref " + ref, "g")).length, 1);
    assert.match(text, /Retry/);
  });
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
      assert.equal(await page.locator("#verified").isVisible(), true);
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
