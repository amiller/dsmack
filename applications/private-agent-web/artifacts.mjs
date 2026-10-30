import { ArtifactsPanel } from "@pi-components/tools/artifacts/artifacts.js";
import { SandboxIframe } from "@pi-components/components/SandboxedIframe.js";
import { RUNTIME_MESSAGE_ROUTER } from "@pi-components/components/sandbox/RuntimeMessageRouter.js";
import { ArtifactBridge } from "./artifact-bridge.mjs";

export const ARTIFACT_ORIGIN = "https://artifacts.private-agent.dstack.soc1024.com";
export const ARTIFACT_PROMPT = `Use the artifacts tool for runnable browser apps, with a .html filename. Write one complete self-contained HTML document: inline JavaScript and CSS, minimal styles, explicit background and readable text. Keep it concise (aim below 150 lines and 8000 characters). No imports, CDNs, remote fonts, fetch, external links, or browser storage. Use DOM controls. The tool returns browser console logs; fix reported errors. These apps run in the browser and do not need a guest.
The host injects frozen window.dsmack; never define or override it. If absent, show a useful offline view. await dsmack.ready(), then dsmack.capabilities.has('storage.get') before a capability call. storage.get(key) returns JSON or null; storage.put(key,value) and storage.list() persist encrypted state scoped to this app. agent.complete({messages:[{role:'user',content:'...'}],maxTokens:512}) returns {text,model,usage}; it uses the viewer's once-granted app budget shown above the app. Handle NOT_AVAILABLE/PERMISSION_DENIED by asking the viewer to allow a budget in the host bar. credit.balance() returns read-only nano-USD strings; diagnostics.log(message) reports to the console. Catch DsmackBridgeError with code/message/retryable; never loop on denied calls. Host model calls treat app content as untrusted and never send a chat turn.`;

// Pi routes messages by a caller-supplied ID. Bind each ID to its actual opaque
// iframe before the upstream listener can see console or lifecycle messages.
const frames = new Map();
const setIframe = RUNTIME_MESSAGE_ROUTER.setSandboxIframe.bind(RUNTIME_MESSAGE_ROUTER);
RUNTIME_MESSAGE_ROUTER.setSandboxIframe = (id, frame) => { frames.set(id, frame); setIframe(id, frame); };
const unregister = RUNTIME_MESSAGE_ROUTER.unregisterSandbox.bind(RUNTIME_MESSAGE_ROUTER);
RUNTIME_MESSAGE_ROUTER.unregisterSandbox = (id) => { frames.delete(id); unregister(id); };
// HTML's parser already repairs malformed markup. Skip upstream's parsererror
// fallback, which inserts generated error text into an unsandboxed srcdoc.
SandboxIframe.prototype.validateHtml = () => null;
window.addEventListener("message", (event) => {
  const data = event.data;
  if (!data || typeof data !== "object") { event.stopImmediatePropagation(); return; }
  if (data.type === "open-external-url") { event.stopImmediatePropagation(); return; }
  if (!data.sandboxId) return;
  const frame = frames.get(data.sandboxId);
  if (!frame || event.source !== frame.contentWindow || event.origin !== "null" || !["console", "execution-complete", "execution-error", "dsmack-request"].includes(data.type)) event.stopImmediatePropagation();
}, true);

// Own the URL handshake so upstream's external-navigation handler is never
// installed. No same-origin, popups, forms, downloads or modal permissions.
SandboxIframe.prototype.loadViaSandboxUrl = function(id, code) {
  this.artifactReadyCleanup?.();
  const frame = document.createElement("iframe");
  frame.sandbox.add("allow-scripts");
  frame.title = "Generated app";
  frame.style.cssText = "width:100%;height:100%;border:0;background:white";
  frame.src = `${ARTIFACT_ORIGIN}/loader.html`;
  this.iframe = frame;
  RUNTIME_MESSAGE_ROUTER.setSandboxIframe(id, frame);
  const ready = (event) => {
    if (event.source !== frame.contentWindow || event.origin !== "null" || event.data?.type !== "sandbox-ready") return;
    window.removeEventListener("message", ready);
    this.artifactReadyCleanup = undefined;
    frame.contentWindow.postMessage({ type: "sandbox-load", sandboxId: id, code }, "*");
  };
  window.addEventListener("message", ready);
  this.artifactReadyCleanup = () => window.removeEventListener("message", ready);
  this.append(frame);
};
const disconnected = SandboxIframe.prototype.disconnectedCallback;
SandboxIframe.prototype.disconnectedCallback = function() {
  this.artifactReadyCleanup?.();
  disconnected.call(this);
};

export function createArtifacts(agent, { state, models, credit, scopeForFilename = filename => JSON.stringify(["preview", filename]), error = console.error } = {}) {
  const panel = new ArtifactsPanel();
  panel.agent = agent;
  panel.sandboxUrlProvider = () => `${ARTIFACT_ORIGIN}/loader.html`;
  let runtimeFilename;
  const createElement = panel.getOrCreateArtifactElement.bind(panel);
  panel.getOrCreateArtifactElement = (filename, content) => {
    runtimeFilename = filename;
    try { return createElement(filename, content); } finally { runtimeFilename = undefined; }
  };
  panel.getHtmlArtifactRuntimeProviders = () => {
    const filename = runtimeFilename;
    return [new ArtifactBridge({ scope: scopeForFilename(filename), state, models, credit,
      diagnostics: text => {
        const element = panel.artifactElements.get(filename);
        if (element) { element.logs = [...element.logs, { type: "log", text }]; element.requestUpdate(); }
      },
    })];
  };
  // These apps have no cross-artifact reads. Reloading every app on a write
  // would erase another app's UI and interrupt its outstanding model request.
  panel.reloadAllHtmlArtifacts = () => {};
  const budgetBar = document.createElement("div");
  budgetBar.className = "artifact-budget";
  budgetBar.hidden = !models;
  const title = document.createElement("strong"), status = document.createElement("span"),
    input = document.createElement("input"), grant = document.createElement("button");
  input.type = "text"; input.inputMode = "decimal"; input.value = "0.02";
  input.setAttribute("aria-label", "App budget in USD");
  grant.textContent = "Allow app budget";
  budgetBar.append(title, status, input, grant);
  const usd = value => "$" + (Number(BigInt(value || "0")) / 1e9).toFixed(6);
  let selection;
  async function refreshBudget(scope) {
    const filename = panel._activeFilename;
    if (!state || !filename || (scope && scope !== scopeForFilename(filename))) return;
    const current = selection = {};
    const { budget } = await state.read(scopeForFilename(filename));
    if (selection !== current) return;
    title.textContent = filename;
    status.textContent = budget.limitNanoUsd === null ? "Choose this app's model budget" :
      `Limit ${usd(budget.limitNanoUsd)} · Spent ${usd(budget.spentNanoUsd)} · Pending ${usd(budget.reservedNanoUsd)}${budget.pending ? " · Usage unresolved" : ""}`;
    input.hidden = grant.hidden = budget.limitNanoUsd !== null;
  }
  let refreshing, refreshingScope;
  function refreshSelectedBudget() {
    const filename = panel._activeFilename;
    if (!state || !filename) return Promise.resolve();
    const scope = scopeForFilename(filename);
    if (refreshing && refreshingScope === scope) return refreshing;
    title.textContent = filename; status.textContent = "Checking app budget…";
    input.hidden = grant.hidden = true;
    refreshingScope = scope;
    const operation = Promise.resolve().then(() => models?.refresh?.(scope)).then(() => refreshBudget(scope));
    refreshing = operation;
    const clear = () => { if (refreshing === operation) refreshing = undefined; };
    operation.then(clear, clear);
    return operation;
  }
  grant.onclick = async () => {
    const filename = panel._activeFilename;
    if (!filename) return;
    const match = /^(\d{1,6})(?:\.(\d{1,9}))?$/.exec(input.value.trim());
    if (!match) { status.textContent = "Enter a positive USD amount with up to nine decimal places."; return; }
    const amount = BigInt(match[1]) * 1000000000n + BigInt((match[2] || "").padEnd(9, "0"));
    grant.disabled = true;
    try { await models.grant(scopeForFilename(filename), amount.toString()); await refreshBudget(); }
    catch (e) { status.textContent = e.message; }
    finally { grant.disabled = false; }
  };
  const showArtifact = panel.showArtifact.bind(panel);
  panel.showArtifact = filename => { showArtifact(filename); refreshSelectedBudget().catch(error); };
  const original = panel.tool;
  const tool = {
    ...original,
    description: ARTIFACT_PROMPT,
    execute: async (...args) => {
      if (typeof args[1]?.filename !== "string" || !/\.html$/i.test(args[1].filename)) throw new Error("Unsupported artifact type. Use a .html filename and a complete single-file HTML app.");
      return original.execute(...args);
    },
  };
  return { panel, tool, budgetBar, refreshBudget, refreshSelectedBudget };
}
