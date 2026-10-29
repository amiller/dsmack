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
  scope:
    "Synthetic browser wallet/signature and E2EE refusal checks; no real inference success claim",
  cases: [],
};
const canonical = (o) =>
  JSON.stringify(
    Object.fromEntries(Object.keys(o).sort().map((key) => [key, o[key]])),
  );
const publicHeaders = { "content-type": "application/json" };
async function backend(page, kind) {
  const cfg = await (await page.request.get(new URL("config.json", base).href))
    .json();
  const calls = [];
  await page.route("**/relay-broker/**", async (route) => {
    const req = route.request(),
      path = new URL(req.url()).pathname.replace("/relay-broker", "");
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
        starterCreditNanoUsd: "10000000",
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
      grantedNanoUsd: "10000000",
      spentNanoUsd: "0",
      remainingNanoUsd: "10000000",
      reservedNanoUsd: "0",
      usedTokens: "0",
      pendingInferenceId: null,
    };
    if (path === "/inference/credit" || path === "/inference/usage") {
      return respond(credit);
    }
    if (path === "/inference/prepare") {
      return respond({
        sessionId: "12".repeat(16),
        modelPublicKey: kind === "key"
          ? Wallet.createRandom().signingKey.publicKey.slice(4)
          : modelKey.signingKey.publicKey.slice(4),
        expiresAt: Math.floor(Date.now() / 1000) + 60,
        attestation: {
          mode: "broker-e2ee",
          provider: "near",
          model,
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
  const editor = page.locator("#chat-editor");
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
    assert.match(await page.locator("#job-prompt").inputValue(), /greet.txt/);
    await send(page, marker);
    await alert(page, "SYNTHETIC_STOP");
    assert.equal(await page.locator("#chat-editor textarea").inputValue(), "");
    assert.match(
      await page.locator("#wallet").textContent(),
      /^0x[0-9a-f]{40}$/i,
    );
    assert(calls.some((r) => r.path === "/inference/credit"));
    const chat = calls.find((r) => r.path === "/inference/chat");
    assert(chat && !JSON.stringify(chat.body).includes(marker));
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
          "Chat credit $0.010000"
      );
      assert.equal(await page.locator("#wallet").textContent(), wallet.address);
      const methods = await page.evaluate(() => window.fixtureWalletMethods);
      assert(methods.includes("wallet_switchEthereumChain"));
      assert(!methods.some((method) => method.startsWith("eth_send")));
      assert(calls.some((request) => request.path === "/inference/credit"));
    },
  );
  await run(
    "completed-sandbox-state-survives-reload",
    "valid",
    async (page) => {
      await page.locator("#burner").click();
      await page.waitForFunction(() =>
        document.querySelector("#chat-credit").textContent ===
          "Chat credit $0.010000"
      );
      const wallet = (await page.locator("#wallet").textContent())
        .toLowerCase();
      await page.evaluate((wallet) =>
        new Promise((resolve, reject) => {
          const open = indexedDB.open("dsmack-private-agent", 1);
          open.onerror = () => reject(open.error);
          open.onsuccess = () => {
            const db = open.result, tx = db.transaction("wallet", "readwrite");
            tx.objectStore("wallet").put(
              { status: "completed" },
              "sandbox-starter:" + wallet,
            );
            tx.oncomplete = () => {
              db.close();
              resolve();
            };
            tx.onerror = () => {
              db.close();
              reject(tx.error);
            };
          };
        }), wallet);
      await ready(page);
      await page.waitForFunction(() =>
        document.querySelector("#sandbox-credit").dataset.status === "completed"
      );
      assert.equal(
        await page.locator("#sandbox-credit").textContent(),
        "Starter sandbox completed. Your verified result is ready.",
      );
      assert.equal(
        await page.locator("#sandbox-credit").getAttribute(
          "data-remaining-jobs",
        ),
        "0",
      );
    },
  );
  for (const kind of ["nonce", "key"]) {
    await run(
      "provider-" + kind + "-refused-before-chat",
      kind,
      async (page, calls) => {
        await page.locator("#burner").click();
        await page.waitForFunction(() =>
          document.querySelector("#chat-credit").textContent ===
            "Chat credit $0.010000"
        );
        await send(
          page,
          "Private fixture prompt refused before any chat POST.",
        );
        await alert(
          page,
          kind === "nonce"
            ? "stale or reused nonce"
            : "differs from the attested signing address",
        );
        assert(calls.some((r) => r.path === "/inference/prepare"));
        assert(!calls.some((r) => r.path === "/inference/chat"));
      },
    );
  }
  await run(
    "starter-credit-and-encrypted-wire",
    "valid",
    async (page, calls) => {
      await page.locator("#burner").click();
      await page.waitForFunction(() =>
        document.querySelector("#chat-credit").textContent ===
          "Chat credit $0.010000"
      );
      const wallet = await page.locator("#wallet").textContent();
      await ready(page);
      assert.equal(await page.locator("#wallet").textContent(), wallet);
      await page.waitForFunction(() =>
        document.querySelector("#chat-credit").textContent ===
          "Chat credit $0.010000"
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
      assert.equal(
        await page.locator("#attestations .evidence-item").count(),
        1,
      );
      assert(
        !calls.some((r) =>
          r.path === "/inference/mint" || r.path === "/inference/close"
        ),
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
