// Add credit → Fund with any token: wires intents-funding.mjs to the page. The pending swap is kept in localStorage
// per wallet so a reload after paying still shows its deposit address and progress.
import QRCode from "qrcode";
import { tokens, quote, swapStatus, baseUsdcBalance } from "./intents-funding.mjs";

const BASE_WORKER = "https://chain-read-base.socrates1024.workers.dev/chain-read";
const DONE = new Set(["SUCCESS", "REFUNDED", "FAILED"]);
const LABEL = { PENDING_DEPOSIT: "Waiting for your deposit", KNOWN_DEPOSIT_TX: "Deposit seen, waiting for confirmations",
  PROCESSING: "Swapping", INCOMPLETE_DEPOSIT: "Deposit was less than the quote; it will be refunded", SUCCESS: "Done: USDC sent to this wallet",
  REFUNDED: "Refunded to your refund address", FAILED: "Swap failed" };

export function intentsFunding({ $, wallet, ensureWallet }) {
  let list, timer, reader;
  const key = () => "dsmack/intents/" + wallet()?.toLowerCase();
  const load = () => { try { return JSON.parse(localStorage.getItem(key()) || "null"); } catch { return null; } };
  const save = (v) => { try { localStorage.setItem(key(), JSON.stringify(v)); } catch { /* the swap still shows until reload */ } };
  const say = (text) => { $("intents-status").textContent = text; };

  const show = async (p) => {
    $("intents-pay").hidden = false;
    $("intents-send").textContent = `${p.amountInFormatted} ${p.symbol} (${p.chain}, about $${Number(p.amountInUsd).toFixed(2)})`;
    $("intents-address").textContent = p.depositAddress;
    $("intents-memo").hidden = !p.depositMemo;
    $("intents-memo").textContent = p.depositMemo ? "Include this memo: " + p.depositMemo : "";
    $("intents-deadline").textContent = `For ${Number(p.amountOut) / 1e6} USDC on Base to ${wallet()}. Pay before ${new Date(p.deadline).toLocaleString()}; about ${Math.ceil(p.timeEstimate / 60)} min after your deposit confirms. Fees ${p.feeBps / 100}%.`;
    $("intents-qr").src = await QRCode.toDataURL(p.depositAddress, { errorCorrectionLevel: "M", margin: 2, width: 240 });
  };
  const poll = async () => {
    clearTimeout(timer);
    const p = load();
    if (!p) return;
    try {
      const s = await swapStatus(p.depositAddress);
      const tx = s.swapDetails?.destinationChainTxHashes?.[0]?.hash;
      say((LABEL[s.status] ?? s.status) + (tx ? ` · Base tx ${tx}` : ""));
      if (DONE.has(s.status)) { save({ ...p, finished: s.status }); if (s.status === "SUCCESS") balance(); return; }
    } catch (e) { say("Could not read swap status: " + e.message); }
    timer = setTimeout(poll, 10000);
  };
  const balance = async () => {
    $("intents-balance").textContent = "Reading Base mainnet, verified by Helios…";
    try {
      reader ??= import("../chain-read/chain-read.mjs").then((m) => m.chainRead({ network: "base", worker: BASE_WORKER }));
      reader.catch(() => { reader = undefined; });
      const b = await baseUsdcBalance(await reader, wallet());
      $("intents-balance").textContent = `${Number(b.units) / 1e6} USDC on Base in this wallet (block ${b.block.number})`;
    } catch (e) { $("intents-balance").textContent = "Could not read the balance: " + e.message; }
  };

  $("add-credit").addEventListener("toggle", async () => {
    if (!$("add-credit").open || list) return;
    try {
      list = await tokens();
      $("intents-token").replaceChildren(...list.map((t, i) => Object.assign(document.createElement("option"),
        { value: String(i), textContent: `${t.symbol} on ${t.blockchain}`, selected: t.symbol === "ZEC" && t.blockchain === "zec" })));
    } catch (e) { say("Could not load NEAR Intents tokens: " + e.message); }
    const p = wallet() && load();
    if (p) { await show(p); if (!p.finished) poll(); else say(LABEL[p.finished]); }
  });
  $("intents-quote").addEventListener("click", async () => {
    try {
      await ensureWallet({ claim: false });
      const t = list[Number($("intents-token").value)];
      const usdc = Math.round(Number($("intents-amount").value) * 1e6);
      if (!(usdc >= 1e6)) throw new Error("Ask for at least 1 USDC.");
      say("Asking NEAR Intents for a quote…");
      const q = await quote({ originAsset: t.assetId, usdc: String(usdc), recipient: wallet(), refundTo: $("intents-refund").value },
        { decimals: t.decimals });
      const p = { ...q, symbol: t.symbol, chain: t.blockchain, at: Date.now() };
      save(p);
      await show(p);
      say("Quote checked: 1Click signed it and it pays this wallet. " + LABEL.PENDING_DEPOSIT + ".");
      timer = setTimeout(poll, 10000);
    } catch (e) { say(e.message); }
  });
  $("intents-copy").addEventListener("click", () => {
    navigator.clipboard.writeText($("intents-address").textContent).catch(() => getSelection().selectAllChildren($("intents-address")));
  });
  $("intents-check-balance").addEventListener("click", balance);
}
