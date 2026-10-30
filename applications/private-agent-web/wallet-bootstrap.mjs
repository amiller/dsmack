import "./theme.mjs";
import { computeAddress } from "ethers";
import { store } from "./wallet-store.mjs";

// This entry runs independently of the large chat SDK and all network checks.
const start = performance.now();
if (window.top !== window.self) {
  document.getElementById("wallet").textContent = "Open the private agent in its own tab to use your wallet.";
} else try {
  const [bundle, legacy] = await Promise.all([store("continuity.keys"), store("burner")]);
  const key = bundle?.walletKey || legacy;
  document.getElementById("wallet").textContent = key
    ? computeAddress(key) : "Choose Start fresh or recover your wallet.";
  document.getElementById("welcome").hidden = !!key;
  if (key) {
    document.getElementById("chat-credit").textContent = "Chat credit · Checking balance…";
    document.getElementById("chat-credit-status").textContent = "Your wallet is loaded. Checking your current credit…";
  }
  document.documentElement.dataset.walletLoaded = "true";
  performance.measure("startup:wallet-visible", { start, end: performance.now() });
} catch {
  document.getElementById("wallet").textContent = "Your wallet couldn’t load. Allow browser storage, then reload.";
}
