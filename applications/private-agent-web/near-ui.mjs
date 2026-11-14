// Add credit → Pay once with any token. One 1Click deposit puts Base ETH in this page's wallet; the page then buys
// its own NEAR AI account and credit (near-account.mjs run()) and switches chat to it.
import QRCode from "qrcode";
import { formatEther } from "ethers";
import { NearAccount, BASE_ETH, fundingWei } from "./near-account.mjs";
import { tokens, swapStatus } from "./intents-funding.mjs";
import { nearOwnModel } from "./model-provider.mjs";
import { store } from "./wallet-store.mjs";

export function nearOwnAccount({ $, cfg, ensureWallet, use }) {
  let account, list, running;
  const say = (text) => { $("near-status").textContent = text; };
  const finish = async (usd) => {
    if (running) return;
    running = true;
    try {
      const key = await account.run(usd, say);
      const models = (await (await fetch("https://cloud-api.near.ai/v1/models")).json()).data;
      const model = models.find((m) => m.id === $("near-model").value);
      if (!model) throw new Error("NEAR AI does not list " + $("near-model").value);
      await use(nearOwnModel(model), key);
      await store("near.funding", null);
      const c = await account.credit();
      say(`Ready: chat now uses this page's own NEAR AI account ($${(c.remaining / 1e9).toFixed(2)} credit).`);
      $("near-pay").hidden = true;
    } finally { running = false; }
  };
  // Wait for the one deposit, then run the rest. Also resumes after a reload.
  const watch = async () => {
    const f = await store("near.funding");
    if (!f) return;
    await show(f);
    for (;;) {
      if (account.activation || (await account.balances()).ethWei >= BigInt(f.wei) * 95n / 100n) return finish(f.usd);
      if (f.depositAddress) say(`Waiting for your payment: 1Click ${(await swapStatus(f.depositAddress)).status}.`);
      await new Promise((r) => setTimeout(r, 10000));
    }
  };
  const show = async (f) => {
    $("near-pay").hidden = false;
    $("near-send").textContent = `${f.amountIn} ${f.symbol} (${f.chain})`;
    $("near-address").textContent = f.depositAddress || account.wallet.address;
    $("near-memo").textContent = f.depositMemo ? "Include this memo: " + f.depositMemo : "";
    $("near-qr").src = await QRCode.toDataURL(f.depositAddress || account.wallet.address, { errorCorrectionLevel: "M", margin: 2, width: 240 });
  };
  const open = async () => {
    await ensureWallet({ claim: false });
    account ||= await new NearAccount({ privateKey: await store("burner"), relay: new URL(cfg.nearPay, location.href).href }).load();
    $("near-wallet").textContent = account.wallet.address;
    list ||= await tokens();
    const pick = $("near-token");
    if (pick.options.length < 2) pick.replaceChildren(...list.map((t, i) => new Option(`${t.symbol} (${t.blockchain})`, i, false, t.assetId === BASE_ETH)));
    if (await store("near.key")) say("This page already has its own NEAR AI account. Pay again to add credit.");
    await watch();
  };
  $("near-quote").onclick = async () => {
    $("near-quote").disabled = true;
    try {
      const t = list[$("near-token").value], usd = Number($("near-usd").value);
      if (!(usd >= 1 && usd <= 10)) throw new Error("Buy between $1 and $10 of NEAR AI credit.");
      const wei = fundingWei(usd, list.find((x) => x.assetId === BASE_ETH).price);
      let f;
      if (t.assetId === BASE_ETH) f = { usd, wei: String(wei), amountIn: formatEther(wei), symbol: "ETH", chain: "base" };
      else {
        const q = await account.fundingQuote(t, wei, $("near-refund").value.trim());
        f = { usd, wei: String(wei), depositAddress: q.depositAddress, depositMemo: q.depositMemo, amountIn: q.amountInFormatted,
          symbol: t.symbol, chain: t.blockchain, deadline: q.deadline };
      }
      await store("near.funding", f);
      await store("near.payment", null);
      account.payment = null;
      watch().catch((e) => say(e.message));
    } catch (e) { say(e.message); } finally { $("near-quote").disabled = false; }
  };
  $("near-account").addEventListener("toggle", () => { if ($("near-account").open) open().catch((e) => say(e.message)); });
  $("near-copy").onclick = () => navigator.clipboard.writeText($("near-address").textContent);
}
