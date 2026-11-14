// The page's own NEAR AI Cloud account, bought and paid from its own wallet, the route the ZCON stick used
// (abalone portable/funding/near_fund): an implicit NEAR account activated with 0.01 NEAR bought through 1Click,
// NEP-413 sign-in to NEAR AI Cloud, a PingPay invoice paid in Base USDC, and an inference key with a spend limit.
import { Contract, JsonRpcProvider, Wallet, formatEther, formatUnits } from "ethers";
import { API as ONECLICK, BASE_USDC, BASE_USDC_CONTRACT, checkQuote, encode58, swapStatus } from "./intents-funding.mjs";
import { store } from "./wallet-store.mjs";

export const CLOUD = "https://cloud-api.near.ai";
export const NEAR_RPC = "https://rpc.mainnet.near.org";
export const BASE_RPC = "https://mainnet.base.org";
export const BASE_ETH = "nep141:base.omft.near";
export const NEAR_USDC = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
export const TREASURY = "jasnah-treasury.sputnik-dao.near";
// USDC kept after paying NEAR AI, for x402 tool calls such as run_code.
export const TOOL_USDC = 250000n;
const ACTIVATION_YOCTO = 10n ** 22n, MAX_ACTIVATION_WEI = 3n * 10n ** 13n, GAS_RESERVE_WEI = 2n * 10n ** 13n;
const need = (ok, message) => { if (!ok) throw new Error(message); };
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const json = async (r, what) => {
  const text = await r.text();
  need(r.ok, `${what}: HTTP ${r.status} ${text.slice(0, 300)}`);
  return JSON.parse(text);
};

// NEP-413: borsh(tag 2^31+413, message, 32-byte nonce, recipient, no callback), sha256, Ed25519.
export function nep413Bytes(message, nonce, recipient) {
  const m = new TextEncoder().encode(message), r = new TextEncoder().encode(recipient);
  const out = new Uint8Array(4 + 4 + m.length + 32 + 4 + r.length + 1), v = new DataView(out.buffer);
  v.setUint32(0, 2 ** 31 + 413, true);
  v.setUint32(4, m.length, true); out.set(m, 8);
  out.set(nonce, 8 + m.length);
  v.setUint32(40 + m.length, r.length, true); out.set(r, 44 + m.length);
  return out;
}
export async function signInBody(seed, nonce) {
  const pkcs8 = Uint8Array.from([...Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), ...seed]);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", await publicOf(key)));
  const message = "Sign in to NEAR AI Cloud", recipient = "cloud.near.ai";
  const digest = await crypto.subtle.digest("SHA-256", nep413Bytes(message, nonce, recipient));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, digest));
  return { signed_message: { accountId: hex(pub), publicKey: "ed25519:" + encode58(pub), signature: btoa(String.fromCharCode(...signature)) },
    payload: { message, nonce: [...nonce], recipient } };
}
async function publicOf(privateKey) {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, true, ["verify"]);
}

// PingPay's prepared payment must pay the asked USD amount of NEAR USDC to NEAR AI's treasury for this invoice,
// from Base USDC sent by this wallet. Mirrors near_fund/payment.py prepare().
export function checkPayment(p, { sessionId, units, payer }) {
  const q = p.quote, pay = p.payment, r = q.quoteRequest;
  need(pay.status === "PENDING" && pay.paymentMethod === "DEPOSIT", "PingPay payment is not a pending deposit");
  need(pay.request.recipient.address === TREASURY, "PingPay pays someone other than NEAR AI");
  need(pay.request.idempotencyKey === "session:" + sessionId, "PingPay payment is for another invoice");
  need(r.originAsset === BASE_USDC && r.destinationAsset === NEAR_USDC, "PingPay swap assets differ");
  need(q.amountOut === String(units), "PingPay output differs from the invoice");
  need(pay.request.payer.address.toLowerCase() === payer.toLowerCase(), "PingPay names another payer");
  need(/^0x[0-9a-fA-F]{40}$/.test(p.depositAddress) && pay.depositAddress === p.depositAddress && q.depositAddress === p.depositAddress,
    "PingPay deposit addresses differ");
  need(/^[1-9]\d*$/.test(q.amountIn) && BigInt(q.amountIn) <= units * 11n / 10n, "PingPay asks more than 10% over the invoice");
  return { depositAddress: p.depositAddress, amountIn: BigInt(q.amountIn) };
}

// NEAR AI accepts a sign-in nonce that starts with the current time: 8-byte big-endian milliseconds, then 24 random
// bytes (as near_fund/account.py builds it). A fully random nonce is refused with invalid_auth.
export function signInNonce(now = Date.now()) {
  const n = new Uint8Array(32);
  new DataView(n.buffer).setBigUint64(0, BigInt(now));
  n.set(crypto.getRandomValues(new Uint8Array(24)), 8);
  return n;
}
export class NearAccount {
  constructor({ privateKey, relay, fetcher = (...a) => fetch(...a), rpc = new JsonRpcProvider(BASE_RPC, 8453, { staticNetwork: true }) }) {
    this.wallet = new Wallet(privateKey, rpc);
    this.usdc = new Contract(BASE_USDC_CONTRACT, ["function balanceOf(address) view returns (uint256)", "function transfer(address,uint256) returns (bool)"], this.wallet);
    this.relay = relay;
    this.fetch = fetcher;
  }
  async load() {
    let seed = await store("near.seed");
    if (!seed) await store("near.seed", seed = hex(crypto.getRandomValues(new Uint8Array(32))));
    this.seed = Uint8Array.from(seed.match(/../g), (b) => parseInt(b, 16));
    this.accountId = (await signInBody(this.seed, new Uint8Array(32))).signed_message.accountId;
    this.session = await store("near.session");
    this.activation = await store("near.activation");
    this.payment = await store("near.payment");
    this.usdcSwap = await store("near.usdcSwap");
    return this;
  }
  async balances() {
    const [eth, usdc] = await Promise.all([this.wallet.provider.getBalance(this.wallet.address), this.usdc.balanceOf(this.wallet.address)]);
    return { eth: formatEther(eth), usdc: formatUnits(usdc, 6), ethWei: eth, usdcUnits: usdc };
  }
  async nearRpc(params) {
    return json(await this.fetch(NEAR_RPC, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "query", params: { finality: "final", ...params } }) }), "NEAR RPC");
  }
  async activated() {
    const r = await this.nearRpc({ request_type: "view_account", account_id: this.accountId });
    if (r.error) { need(r.error.cause?.name === "UNKNOWN_ACCOUNT", "NEAR RPC: " + JSON.stringify(r.error)); return false; }
    return true;
  }
  // A 1Click EXACT_OUTPUT quote, checked against its signature and the request (intents-funding.mjs checkQuote).
  async swap({ originAsset, destinationAsset, amount, recipient, refundTo, decimals }, now = Date.now()) {
    const request = { dry: false, swapType: "EXACT_OUTPUT", slippageTolerance: 100, originAsset, depositType: "ORIGIN_CHAIN",
      destinationAsset, amount: String(amount), refundTo, refundType: "ORIGIN_CHAIN", recipient, recipientType: "DESTINATION_CHAIN",
      deadline: new Date(Math.floor(now / 1000) * 1000 + 3600000).toISOString() };
    const r = await this.fetch(ONECLICK + "/quote", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request) });
    const raw = await r.text();
    need(r.ok, `1Click quote: HTTP ${r.status} ${raw.slice(0, 200)}`);
    return checkQuote(raw, request, { decimals, sentAt: now, now: Date.now() });
  }
  // The one payment a person makes: any 1Click token, swapped to `wei` of Base ETH for this wallet.
  fundingQuote(token, wei, refundTo) {
    return this.swap({ originAsset: token.assetId, destinationAsset: BASE_ETH, amount: wei, recipient: this.wallet.address, refundTo, decimals: token.decimals });
  }
  // Exactly 0.01 NEAR to this account, paid in Base ETH by this wallet.
  async activationQuote() {
    const q = await this.swap({ originAsset: BASE_ETH, destinationAsset: "nep141:wrap.near", amount: ACTIVATION_YOCTO,
      recipient: this.accountId, refundTo: this.wallet.address, decimals: 18 });
    need(BigInt(q.amountIn) <= MAX_ACTIVATION_WEI, `Activation costs ${formatEther(q.amountIn)} ETH, above the ${formatEther(MAX_ACTIVATION_WEI)} ETH bound`);
    return { to: q.depositAddress, wei: BigInt(q.amountIn), deadline: q.deadline };
  }
  // Base ETH → `units` of Base USDC back to this wallet, for the PingPay invoice.
  async swapToUsdc(units) {
    const q = await this.swap({ originAsset: BASE_ETH, destinationAsset: BASE_USDC, amount: units, recipient: this.wallet.address,
      refundTo: this.wallet.address, decimals: 18 });
    const { ethWei } = await this.balances();
    need(BigInt(q.amountIn) + GAS_RESERVE_WEI <= ethWei, `The USDC swap needs ${formatEther(q.amountIn)} ETH plus gas; the wallet holds ${formatEther(ethWei)}.`);
    const tx = await this.wallet.sendTransaction({ to: q.depositAddress, value: BigInt(q.amountIn) });
    await store("near.usdcSwap", this.usdcSwap = { depositAddress: q.depositAddress, txHash: tx.hash });
    return tx.hash;
  }
  async activate(quote) {
    need(!this.activation?.txHash, "Activation was already sent: " + this.activation?.txHash);
    const tx = await this.wallet.sendTransaction({ to: quote.to, value: quote.wei });
    await store("near.activation", this.activation = { depositAddress: quote.to, txHash: tx.hash });
    return tx.hash;
  }
  activationStatus() { return swapStatus(this.activation.depositAddress, this.fetch); }

  async cloud(method, path, { token = this.session?.access_token, body } = {}) {
    return json(await this.fetch(CLOUD + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) }), `NEAR AI ${method} ${path}`);
  }
  // The single owner organization and workspace NEAR AI creates for a wallet sign-in.
  async me(token) {
    const me = await this.cloud("GET", "/v1/users/me", { token });
    need(me.auth_provider === "near" && me.email === this.accountId + "@near", "NEAR AI signed in another account");
    const orgs = me.organizations.filter((o) => o.is_active && o.role === "owner");
    need(orgs.length === 1, "NEAR AI account has no single owned organization");
    const work = me.workspaces.filter((w) => w.is_active && w.organization_id === orgs[0].id);
    need(work.length === 1, "NEAR AI organization has no single workspace");
    return { organizationId: orgs[0].id, workspaceId: work[0].id };
  }
  async signIn() {
    const reply = await this.cloud("POST", "/v1/auth/near", { token: null, body: await signInBody(this.seed, signInNonce()) });
    const ids = await this.me(reply.access_token);
    await store("near.session", this.session = { access_token: reply.access_token, refresh_token: reply.refresh_token,
      refresh_token_expiration: reply.refresh_token_expiration, ...ids });
  }
  async fresh() {
    need(this.session, "Sign in to NEAR AI first.");
    const exp = JSON.parse(atob(this.session.access_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).exp;
    if (exp * 1000 - Date.now() > 120000) return;
    const reply = await this.cloud("POST", "/v1/users/me/access-tokens", { token: this.session.refresh_token });
    const ids = await this.me(reply.access_token);
    need(ids.organizationId === this.session.organizationId, "NEAR AI refresh returned another organization");
    await store("near.session", this.session = { ...this.session, access_token: reply.access_token, refresh_token: reply.refresh_token,
      refresh_token_expiration: reply.refresh_token_expiration });
  }
  async credit() {
    await this.fresh();
    return this.cloud("GET", `/v1/organizations/${this.session.organizationId}/usage/balance`);
  }

  // The two PingPay calls that don't allow browser origins go through the page server's pass-through.
  async pay(path, body) {
    return json(await this.fetch(this.relay + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }), "PingPay " + path);
  }
  // A NEAR AI invoice for `usd` dollars and PingPay's checked Base USDC deposit for it. Nothing is sent.
  async invoice(usd) {
    await this.fresh();
    const units = BigInt(Math.round(usd * 1e6));
    need(units >= 1000000n && units <= 10000000n, "Buy between $1 and $10.");
    const { sessionId } = await this.pay("/checkout", { signIn: await signInBody(this.seed, signInNonce()),
      organizationId: this.session.organizationId, amount: Number(units / 10000n) }); // cents
    need(/^[A-Za-z0-9_-]{1,128}$/.test(sessionId), "NEAR AI returned no invoice");
    const s = (await this.pay("/session", { json: { sessionId } })).json.session;
    need(s.sessionId === sessionId && s.metadata.organizationId === this.session.organizationId && s.amount.amount === String(units) &&
      s.amount.decimals === 6 && s.amount.assetId === NEAR_USDC && ["CREATED", "PENDING"].includes(s.status), "Invoice terms differ");
    const prepared = (await this.pay("/prepare", { json: { input: { sessionId, payerAsset: { amount: "0", asset: { chain: "base", symbol: "USDC",
      contractAddress: BASE_USDC_CONTRACT } }, payer: { address: this.wallet.address }, idempotencyKey: "session:" + sessionId, paymentMethod: "DEPOSIT" } } })).json;
    return { sessionId, units, ...checkPayment(prepared, { sessionId, units, payer: this.wallet.address }) };
  }
  async payInvoice(inv) {
    need(!this.payment?.txHash || this.payment.sessionId !== inv.sessionId, "This invoice was already paid: " + this.payment?.txHash);
    const before = await this.credit();
    const tx = await this.usdc.transfer(inv.depositAddress, inv.amountIn);
    await store("near.payment", this.payment = { sessionId: inv.sessionId, depositAddress: inv.depositAddress, txHash: tx.hash,
      units: String(inv.units), baseline: String(BigInt(before.remaining) + BigInt(before.total_spent)) });
    return tx.hash;
  }
  // Credit counted from the payment's baseline: remaining + spent grows by the invoice once NEAR AI credits it.
  async paymentCredited() {
    const b = await this.credit();
    return BigInt(b.remaining) + BigInt(b.total_spent) >= BigInt(this.payment.baseline) + BigInt(this.payment.units) * 1000n;
  }
  // An inference key that may spend everything the account holds (nano-USD); raised after each top-up.
  async apiKey() {
    const b = await this.credit(), ws = this.session.workspaceId;
    let saved = await store("near.key");
    if (saved) {
      const row = (await this.cloud("GET", `/v1/workspaces/${ws}/api-keys`)).api_keys.find((k) => k.id === saved.id);
      need(row?.is_active, "This page's NEAR AI key was revoked.");
      await this.cloud("PATCH", `/v1/workspaces/${ws}/api-keys/${saved.id}/spend-limit`,
        { body: { spendLimit: { amount: row.usage.amount + b.remaining, currency: "USD" } } });
      return saved.key;
    }
    const v = await this.cloud("POST", `/v1/workspaces/${ws}/api-keys`,
      { body: { name: "Abalone private agent", spendLimit: { amount: b.remaining, currency: "USD" } } });
    need(/^sk-/.test(v.key) && v.workspace_id === ws, "NEAR AI returned no inference key");
    await store("near.key", saved = { key: v.key, id: v.id });
    return saved.key;
  }
  // Everything after the one payment: activate, sign in, swap to USDC, pay a $usd invoice, wait for the credit, return
  // the key. Each step is recorded in IndexedDB, so a reload resumes where it stopped without paying twice.
  async run(usd, say, sleep = (ms) => new Promise((r) => setTimeout(r, ms))) {
    while (!await this.activated()) {
      if (!this.activation) {
        const q = await this.activationQuote();
        say(`Activating the NEAR account: ${formatEther(q.wei)} ETH to 1Click for 0.01 NEAR.`);
        await this.activate(q);
      } else say(`Activating the NEAR account: 1Click ${(await this.activationStatus()).status}.`);
      await sleep(5000);
    }
    if (!this.session) { say("Signing in to NEAR AI."); await this.signIn(); }
    // An account that already holds the credit (a payment that landed before its record was saved) is not charged again.
    if (!this.payment && BigInt((await this.credit()).remaining) < BigInt(Math.round(usd * 1e9 / 2))) {
      const inv = await this.invoice(usd);
      for (;;) {
        const short = inv.amountIn + TOOL_USDC - (await this.balances()).usdcUnits;
        if (short <= 0n) break;
        const status = this.usdcSwap && (await swapStatus(this.usdcSwap.depositAddress, this.fetch)).status;
        if (!this.usdcSwap || ["SUCCESS", "REFUNDED", "FAILED"].includes(status)) {
          say(`Swapping ETH for ${formatUnits(short, 6)} USDC through 1Click.`);
          await this.swapToUsdc(short);
        } else say(`Swapping ETH for USDC: 1Click ${status}.`);
        await sleep(5000);
      }
      say(`Paying NEAR AI's $${usd} invoice: ${formatUnits(inv.amountIn, 6)} USDC to PingPay.`);
      await this.payInvoice(inv);
    }
    while (this.payment && !await this.paymentCredited()) { say("Waiting for NEAR AI to add the credit."); await sleep(5000); }
    say("Creating this page's NEAR AI key.");
    return this.apiKey();
  }
}
// Base ETH the one payment should deliver for `usd` of NEAR AI credit: the invoice with 6% for swap fees and price
// moves, $0.25 of USDC left for x402 tool calls, the 0.01 NEAR activation, and gas for three Base sends.
export function fundingWei(usd, ethUsd) {
  return BigInt(Math.ceil((usd * 1.06 + 0.1 + Number(TOOL_USDC) / 1e6) / ethUsd * 1e18)) + MAX_ACTIVATION_WEI + 2n * GAS_RESERVE_WEI;
}
