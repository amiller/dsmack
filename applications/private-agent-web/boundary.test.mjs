import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { verifyMessage, Wallet } from "ethers";
const base = process.env.BASE_URL || "http://127.0.0.1:18731/private-agent/";
const evidence = resolve(process.env.EVIDENCE || "local-data/chat-boundaries");
const moduleName = process.env.PLAYWRIGHT_MODULE || "playwright";
const { chromium } = await import(
  isAbsolute(moduleName) ? pathToFileURL(moduleName).href : moduleName
);
const browser = process.env.PLAYWRIGHT_CDP_URL
  ? await chromium.connectOverCDP(process.env.PLAYWRIGHT_CDP_URL)
  : await chromium.launch({
    headless: true,
    ...(process.env.CHROMIUM_PATH
      ? { executablePath: process.env.CHROMIUM_PATH }
      : {}),
    args: ["--no-sandbox"],
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
  const calls = [];
  let recoveredEnded = false;
  await page.route("**/relay-broker/**", async (route) => {
    const req = route.request(),
      path = new URL(req.url()).pathname.replace("/relay-broker", "");
    if (req.method() === "OPTIONS") return route.fulfill({status: 204, headers: publicHeaders});
    const body = req.method() === "POST" ? req.postDataJSON() : undefined;
    calls.push({ path, method: req.method(), body });
    const respond = (value, status = 200) =>
      route.fulfill({
        status,
        headers: publicHeaders,
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
async function run(name, kind, fn) {
  const ctx = await browser.newContext(),
    page = await ctx.newPage(),
    errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const result = { name, status: "failed" };
  try {
    const calls = await backend(page, kind);
    await ready(page);
    await fn(page, calls);
    assert.deepEqual(errors, []);
    result.status = "passed";
    await page.screenshot({
      path: resolve(evidence, name + ".png"),
      fullPage: true,
    });
  } catch (e) {
    result.error = e.message;
  }
  report.cases.push(result);
  await ctx.close();
  console.log(result.status + ": " + name);
}
try {
  await run("first-send-creates-wallet", "valid", async (page, calls) => {
    const marker = "FIRST_VISIT_PROMPT_STAYS_ENCRYPTED";
    assert.equal(await page.locator("#policy").inputValue(), "");
    assert.match(
      await page.locator("#node-status").textContent(),
      /Approved sandbox policy included/,
    );
    assert.match(await page.locator("#repository-status").textContent(), /greet.txt/);
    await send(page, marker);
    await alert(page, "SYNTHETIC_STOP");
    await page.waitForFunction(() => document.querySelector("#chat").dataset.saved === "true" && !document.querySelector("message-editor").isStreaming);
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
  await run(
    "injected-wallet-switches-to-base-sepolia",
    "valid",
    async (page, calls) => {
      const wallet = Wallet.createRandom();
      await page.exposeFunction(
        "fixtureWalletSign",
        async (hex) => wallet.signMessage(Buffer.from(hex.slice(2), "hex")),
      );
      await page.evaluate((address) => {
        let chainId = "0x1";
        window.fixtureWalletMethods = [];
        window.ethereum = {
          request: async ({ method, params }) => {
            window.fixtureWalletMethods.push(method);
            if (method === "eth_chainId") return chainId;
            if (method === "eth_requestAccounts" || method === "eth_accounts") {
              return [address];
            }
            if (method === "wallet_switchEthereumChain") {
              chainId = params[0].chainId;
              return null;
            }
            if (method === "personal_sign") {
              return window.fixtureWalletSign(params[0]);
            }
            throw new Error("Unexpected synthetic wallet method " + method);
          },
        };
      }, wallet.address);
      await page.locator("#connect").click();
      await page.waitForFunction(() =>
        document.querySelector("#chat-credit").textContent ===
          "Chat credit $0.250000"
      );
      assert.equal(await page.locator("#wallet").textContent(), wallet.address);
      const methods = await page.evaluate(() => window.fixtureWalletMethods);
      assert(methods.includes("wallet_switchEthereumChain"));
      assert(!methods.some((method) => method.startsWith("eth_send")));
      assert(calls.some((request) => request.path === "/inference/credit"));
    },
  );
  await run("guest-is-lazy-until-a-tool-call", "valid", async (page, calls) => {
    assert.equal(await page.locator("#end-session").isDisabled(), true);
    assert.equal(await page.locator("#download").isDisabled(), true);
    await send(page, "A chat request alone must not allocate a guest.");
    await alert(page, "SYNTHETIC_STOP");
    assert(!calls.some(r => r.path.startsWith("/agent/")));
    assert.equal(await page.locator("#guest-status").getAttribute("data-state"), "idle");
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
        await page.locator("#burner").click();
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
    await page.locator("#burner").click();
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
      await page.locator("#burner").click();
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
      assert.equal(chat.body.body.tools.length, 4);
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
}
if (!report.passed) process.exitCode = 1;
