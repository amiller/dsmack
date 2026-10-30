import "./theme.mjs";
import { computeAddress } from "ethers";
import { store } from "./wallet-store.mjs";

// This entry runs independently of the large chat SDK and all network checks.
const start = performance.now();
try {
  const [bundle, legacy] = await Promise.all([store("continuity.keys"), store("burner")]);
  const key = bundle?.walletKey || legacy;
  document.getElementById("wallet").textContent = key
    ? computeAddress(key) : "Choose Start fresh or recover your wallet.";
  document.getElementById("welcome").hidden = !!key;
  document.documentElement.dataset.walletLoaded = "true";
  performance.measure("startup:wallet-visible", { start, end: performance.now() });
} catch {
  document.getElementById("wallet").textContent = "Your wallet couldn’t load. Allow browser storage, then reload.";
}
