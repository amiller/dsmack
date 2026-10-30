import { ArtifactsPanel } from "@pi-components/tools/artifacts/artifacts.js";
import { SandboxIframe } from "@pi-components/components/SandboxedIframe.js";
import { RUNTIME_MESSAGE_ROUTER } from "@pi-components/components/sandbox/RuntimeMessageRouter.js";

export const ARTIFACT_ORIGIN = "https://artifacts.private-agent.dstack.soc1024.com";
export const ARTIFACT_PROMPT = `Use the artifacts tool for runnable browser apps, with a .html filename. Write one complete self-contained HTML document: inline JavaScript and CSS, minimal styles, explicit background and readable text. Keep it concise (aim below 150 lines and 8000 characters). No imports, CDNs, remote fonts, fetch, links to external sites, or browser storage. Network and host APIs are unavailable. Use DOM controls and in-memory state. The tool returns browser console logs; fix reported errors. These apps run in the browser and do not need a guest.`;

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
  if (!frame || event.source !== frame.contentWindow || event.origin !== "null" || data.type !== "console") event.stopImmediatePropagation();
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

export function createArtifacts(agent) {
  const panel = new ArtifactsPanel();
  panel.agent = agent;
  panel.sandboxUrlProvider = () => `${ARTIFACT_ORIGIN}/loader.html`;
  panel.getHtmlArtifactRuntimeProviders = () => [];
  const original = panel.tool;
  const tool = {
    ...original,
    description: ARTIFACT_PROMPT,
    execute: async (...args) => {
      if (typeof args[1]?.filename !== "string" || !/\.html$/i.test(args[1].filename)) throw new Error("Unsupported artifact type. Use a .html filename and a complete single-file HTML app.");
      return original.execute(...args);
    },
  };
  return { panel, tool };
}
