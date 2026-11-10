import assert from "node:assert/strict";
import { verifyMessage, Wallet, keccak256 } from "ethers";
const base = process.env.BASE_URL || "http://127.0.0.1:18731/private-agent/";
import { report, model, replayNear } from "./near.mjs";
const modelPublicKey = report.model_attestations[0].signing_public_key;
const canonical = (o) =>
  JSON.stringify(
    Object.fromEntries(Object.keys(o).sort().map((key) => [key, o[key]])),
  );
export const networkFixture = {
  updated_at: 1793456360, capacity: "reported",
  macs: [{ publisher: "0x" + "ab".repeat(20), operator: "0x" + "cd".repeat(20),
    region: { name: "Michigan, US", lat: 42, lon: -84 }, chip: "Apple M4 Pro",
    slots: 4, ready: 4, busy: 0, online: true }],
  totals: { macs_online: 1, total_slots: 4, ready_slots: 4, busy_slots: 0, utilization: 0 },
};
export let partialCredit;
export const setPartialCredit = value => { partialCredit = value; };
export const reservation = (body) => BigInt(
  Buffer.byteLength(JSON.stringify(body)) + 256 +
    64 * body.messages.length + body.max_tokens,
) * 1500n;
export const publicHeaders = {
  "content-type": "application/json",
  "access-control-allow-origin": new URL(base).origin,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};
export async function backend(page, kind) {
  await replayNear(page);
  const cfg = await (await page.request.get(new URL("config.json", base).href))
    .json();
  cfg.broker = cfg.broker.replace("/relay-broker-staging", "/relay-broker");
  if (kind === "ux") cfg.broker = new URL("/relay-broker", base).href;
  cfg.syncAnchor = "0x" + "11".repeat(20);
  cfg.syncAnchorCodeHash = keccak256("0x6000");
  await page.route("**/config.json", route => route.fulfill({headers:publicHeaders,body:JSON.stringify(cfg)}));
  await page.route(new URL(cfg.rpc).href, route => {
    const raw = route.request().postDataJSON();
    const reply = r => ({jsonrpc:"2.0",id:r.id,result:r.method==="eth_chainId"?"0x14a34":r.method==="eth_getCode"?"0x6000":"0x"+"0".repeat(128)});
    return route.fulfill({headers:publicHeaders,body:JSON.stringify(Array.isArray(raw)?raw.map(reply):reply(raw))});
  });
  await page.route("**/continuity/email/status", route => route.fulfill({ headers: publicHeaders, body: JSON.stringify({ pending: null }) }));
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
    if (path === "/network") return respond(networkFixture);
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
          : modelPublicKey,
        expiresAt: Math.floor(Date.now() / 1000) + 60,
        attestation: {
          report: { ...report, gateway_attestation: { ...report.gateway_attestation,
            request_nonce: kind === "nonce" ? "00".repeat(32) : report.gateway_attestation.request_nonce } },
          mode: "broker-e2ee",
          provider: "near",
          model: kind === "model" ? model + "-other" : model,
          verification: "verified",
        },
      });
    }
    if (path === "/inference/chat" && kind === "ux") return route.continue();
    if (path === "/inference/chat" && kind === "duplicate") {
      return respond({code:"REQUEST_ALREADY_DISPATCHED", status:"already-dispatched",
        sessionId:body.sessionId, inferenceId:"original-request",
        message:"This request was already dispatched. Reconcile provider usage before sending again."}, 202);
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
export async function ready(page) {
  await page.goto(base);
  await page.waitForFunction(() =>
    document.documentElement.dataset.ready === "true"
  );
  await page.waitForFunction(() =>
    document.documentElement.dataset.servicesReady === "true"
  );
}
export async function send(page, text) {
  const editor = page.locator("agent-interface message-editor");
  const input = editor.locator('textarea,[contenteditable="true"]').first();
  await input.fill(text);
  const button = editor.getByRole("button", { name: /send/i });
  if (await button.count()) await button.first().click();
  else await input.press("Enter");
}
