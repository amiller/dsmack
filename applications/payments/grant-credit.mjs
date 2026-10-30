// Issue or retry an explicit operator gift to an existing private-agent wallet.
import { Wallet } from "./schema.mjs";
import { canonical } from "../relay-broker/grants.mjs";
import { creditGrantPrefix } from "../relay-broker/inference.mjs";

export async function grantCredit(args) {
  const [configPath, keyPath, brokerUrl, recipient, amount, output, send] = args;
  const need = (ok, message) => { if (!ok) throw Error(message); };
  need(output && (!send || send === "--send"),
    "usage: grant-credit.mjs FULL_BROKER_CONFIG FUNDING_KEY BROKER_URL RECIPIENT NANO_USD VOUCHER_JSON [--send]");
  const cfg = JSON.parse(await Deno.readTextFile(configPath)), payments = cfg.payments;
  need(/^[0-9a-f]{64}$/.test(cfg.brokerKey ?? ""), "full broker config must pin brokerKey before signing a gift");
  need(/^0x[0-9a-fA-F]{40}$/.test(recipient ?? "") && /^[1-9][0-9]*$/.test(amount ?? "") &&
    amount.length <= 39 && BigInt(amount) < (1n << 128n), "recipient and positive uint128 nano-USD amount required");
  need(payments?.fundingAddress && payments.escrow && payments.grantSigner, "full broker config needs payment identities");
  const broker = brokerUrl.replace(/\/$/, "");
  const [key, identity] = await Promise.all(["/key", "/payments/key"].map(async path => {
    const response = await fetch(broker + path, { redirect: "error", signal: AbortSignal.timeout(15000) });
    need(response.ok, "broker identity lookup failed"); return response.json();
  }));
  need(key.public_key === cfg.brokerKey && identity.chainId === 84532 &&
    identity.address?.toLowerCase() === payments.grantSigner.toLowerCase() &&
    identity.escrow?.toLowerCase() === payments.escrow.toLowerCase() && identity.codeHash === payments.codeHash,
    "broker differs from the configured key/payment identity");
  const info = await Deno.stat(keyPath);
  need(info.mode !== null && !(info.mode & 0o077), "funding key must be mode 600");
  let wallet;
  try { wallet = new Wallet((await Deno.readTextFile(keyPath)).trim()); }
  catch { throw Error("cannot read a valid funding wallet key"); }
  need(wallet.address.toLowerCase() === payments.fundingAddress.toLowerCase(), "key is not the configured funding wallet");
  let voucher;
  try { voucher = JSON.parse(await Deno.readTextFile(output)); }
  catch (error) { if (!(error instanceof Deno.errors.NotFound)) throw error; }
  if (voucher) {
    const grant = voucher.grant;
    need(grant?.wallet === recipient.toLowerCase() && grant.amountNanoUsd === amount &&
      grant.brokerKey === cfg.brokerKey && grant.escrow === payments.escrow.toLowerCase(),
      "saved voucher has different terms; do not overwrite an uncertain gift");
  } else {
    const grant = { v: 1, chainId: 84532, escrow: payments.escrow.toLowerCase(), brokerKey: cfg.brokerKey,
      wallet: recipient.toLowerCase(), amountNanoUsd: amount,
      nonce: Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, "0")).join(""),
      expiresAt: Math.floor(Date.now() / 1000) + 600 };
    voucher = { grant, signature: await wallet.signMessage(creditGrantPrefix + canonical(grant)) };
    // Keep the exact authorization before dispatch. Repeating this command with
    // this file retries the same nonce and cannot add the gift twice.
    await Deno.writeTextFile(output, JSON.stringify(voucher, null, 2) + "\n", { createNew: true, mode: 0o600 });
  }
  if (send === "--send") {
    const response = await fetch(broker + "/inference/grant-credit", { method: "POST", redirect: "error",
      headers: { "content-type": "application/json" }, body: JSON.stringify(voucher), signal: AbortSignal.timeout(15000) });
    const result = await response.json();
    need(response.ok, result.error?.message ?? "credit gift failed; retain voucher and retry the same file");
    console.log(JSON.stringify(result));
  } else console.log(JSON.stringify({ voucher: output, wallet: recipient.toLowerCase(), amountNanoUsd: amount, sent: false }));

}
if (import.meta.main) await grantCredit(Deno.args);
