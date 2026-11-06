import { checkPageVersion } from "./page-version.mjs";
import "@mariozechner/mini-lit/dist/MarkdownBlock.js";
import { renderToolProgress, configureSandboxMac } from "./tool-renderers.mjs";
import { macFor, sandboxLabel, networkSummary } from "./network-context.mjs";
import { AgentInterface } from "@pi-components/components/AgentInterface.js";
import { SessionListDialog } from "@pi-components/dialogs/SessionListDialog.js";
import { UserMessage, AssistantMessage } from "@pi-components/components/Messages.js";
import { Agent } from "@earendil-works/pi-agent-core";
import { createArtifacts, ARTIFACT_PROMPT } from "./artifacts.mjs";
import { ArtifactGuests } from "./artifact-guests.mjs";
import { ArtifactState } from "./artifact-state.mjs";
import { ArtifactModels } from "./artifact-models.mjs";
import { createSessionPersistence } from "./artifact-persistence.mjs";
import { sealArtifact, openArtifact, artifactLink, parseArtifactLink, sharedScope, viewerSessionId } from "./artifact-share.mjs";
import { html, render as renderHtml } from "lit";
import { installMessageFeedback } from "./chat-feedback.mjs";
import { createChatStorage, saveChat, exportChats } from "./chat-storage.mjs";
import { DeviceKeys } from "./keys.mjs";
import { ChatSync } from "./chat-sync.mjs";
import { SavedWorkspace } from "./workspaces.mjs";
import { continuityUI } from "./continuity-ui.mjs";
import {
  Credit,
  formatEther,
  formatNanoUsd,
  require,
  store,
  walletBody,
} from "./credit.mjs";
import { loadProvider, saveProvider, directModel, modelBadge, modelPrivacy, providerStream, checkProvider, anthropicModels, defaultAnthropicModel } from "./model-provider.mjs";
import { brokerStream } from "./inference.mjs";
import { referenceError, replyFailure, retryCandidate, meteredReply, settleInterruptedReply, failOrphanedTools } from "./reply-recovery.mjs";
import * as sandbox from "@sandbox";
import { heliosChain } from "../compute-node/browser/helios-chain.mjs";
import { brokerOwners } from "../compute-node/browser/owners.mjs";
import approvedSandboxPolicy from "./sandbox-policy.json";
import { monitorLabel } from "../egress-policy/monitor/registry.mjs";
import { GuestSession } from "./agent-tools.mjs";
import { chainDirectoryCache } from "./chain-directory.mjs";
import { readWithRetry, pause as waitForRead } from "./network-read.mjs";
import { fetchDirectAttestation } from "./direct-attestation.mjs";
import { piToolCatalog, defaultAgentEnvironment, buildAgentPrompt } from "./pi-prompt.mjs";
const $ = (id) => document.getElementById(id),
  decode = new TextDecoder(),
  guests = new Map(), artifactGuests = new Map();
let keys, sync, continuity, cfg, sharedLink, sharedBundle, activeArtifactView,
  credit,
  quote,
  policy,
  node,
  repoFiles,
  guest,
  agent,
  chat,
  storage,
  persistSession,
  currentSession,
  unsubscribeChat,
  lastSave = Promise.resolve(),
  selectedModel,
  chatBusy = false;
async function startupStep(name, task) {
  const start = performance.now();
  try { return await task(); }
  finally { performance.measure("startup:" + name, { start, end: performance.now() }); }
}
let networkSnapshot;
function macInfo(verified) {
  const mac = verified?.networkMac || macFor(networkSnapshot, verified);
  return mac && { publisher: mac.publisher, chip: mac.chip, region: mac.region };
}
configureSandboxMac(() => macInfo(guest?.node));
function updateSandboxLabels() {
  const mac = macInfo(guest?.node);
  for (const id of ["sandbox-mac", "sandbox-evidence-mac"]) $(id).textContent = sandboxLabel(mac);
  for (const view of chat?.querySelectorAll("tool-message") || []) {
    let label = view.querySelector(".sandbox-label");
    if (label && !label.hasAttribute("data-network-label")) continue;
    if (!label) {
      label = document.createElement("a"); label.className = "sandbox-label";
      label.setAttribute("data-network-label", "");
      label.href = "./network/index.html"; view.prepend(label);
    }
    const result = view.result;
    label.textContent = sandboxLabel(result?.details?.dsmackMac || (!result || result.isPartial ? mac : undefined));
  }
}
async function refreshNetwork(signal) {
  try { networkSnapshot = await api("/network", undefined, { signal }); }
  catch { networkSnapshot = undefined; }
  $("network-link").textContent = networkSummary(networkSnapshot);
  updateSandboxLabels();
  return networkSnapshot;
}
function connectionStatus(stage, verified) {
  const region = macInfo(verified)?.region?.name;
  $("capacity-status").dataset.stage = stage;
  $("capacity-status").textContent = stage === "connecting"
    ? `Connecting peer-to-peer to a Mac${region ? " in " + region : ""}…`
    : "Verified this Mac's Apple attestation.";
}
function capacityMessage(empty, retry) {
  const count = networkSnapshot?.totals?.total_slots;
  return empty ? `No Macs on the Dsmack network are online right now; retrying in ${retry}s`
    : `All ${count === undefined ? "" : count + " "}slots on the Dsmack network are busy; retrying in ${retry}s`;
}
async function openAddCredit() {
  try { await ensureWallet({ claim: false }); }
  catch (e) { error(e); return; }
  $("advanced").open = true;
  $("add-credit").open = true;
  $("add-credit").scrollIntoView({ block: "center" });
  $("deposit-amount").focus({ preventScroll: true });
}
function addCreditAction() {
  return html` <button class="link add-credit-action" @click=${openAddCredit}>Add credit</button>`;
}
function error(e) {
  const failure = e.replyFailure || replyFailure(e);
  renderHtml(html`${failure.message}${failure.addCredit ? addCreditAction() : ""}`, $("alert"));
  $("alert").title = failure.detail || e.message || String(e);
  $("alert").hidden = false;
}
let sendingMessage;
function sendStatus(text, detail = "", stage = "") {
  if (!sendingMessage) return;
  sendingMessage.sendStatus = text;
  sendingMessage.sendDetail = detail;
  sendingMessage.sendStage = stage;
  for (const view of chat.querySelectorAll("user-message")) view.requestUpdate();
}
function sendFailure(e) {
  const failure = e.replyFailure || replyFailure(e);
  if (sendingMessage) {
    sendingMessage.sendAddCredit = !!failure.addCredit;
    sendStatus(failure.message, failure.detail || e.message, "error");
  } else error(e);
}
// Pi renders usage per reply by default. Keep its message renderer and omit
// that optional field only during rendering; the ledger and chat total retain it.
const renderAssistant = AssistantMessage.prototype.render;
AssistantMessage.prototype.render = function () {
  const { usage, errorMessage, stopReason } = this.message;
  this.message.usage = undefined;
  if (this.message.failure) {
    this.message.errorMessage = undefined;
    this.message.stopReason = "stop";
  }
  try { return renderAssistant.call(this); }
  finally { Object.assign(this.message, { usage, errorMessage, stopReason }); }
};
const renderUser = UserMessage.prototype.render;
UserMessage.prototype.render = function () {
  return html`${renderUser.call(this)}${this.message.sendStatus ? html`<p
    id=${this.message === sendingMessage ? "send-status" : ""} class="send-status" role="status"
    data-stage=${this.message.sendStage || ""} title=${this.message.sendDetail || ""}>${this.message.sendStatus}${this.message.sendAddCredit ? addCreditAction() : ""}</p>` : ""}`;
};
function syncFailure(e) {
  $("chat-status").hidden = false;
  $("chat-status").textContent = "Couldn't sync this chat. It is saved here.";
  $("chat-status").title = e.message;
}
function clearError() {
  $("alert").hidden = true;
}
function action(id, fn) {
  $(id).addEventListener("click", async () => {
    clearError();
    $(id).disabled = true;
    try {
      await fn();
    } catch (e) {
      error(e);
    } finally {
      $(id).disabled = id === "end-session" ? !guest?.lease : false;
    }
  });
}
function details(parent, title, value) {
  const d = document.createElement("details"),
    s = document.createElement("summary"),
    p = document.createElement("pre");
  s.textContent = title;
  p.textContent = JSON.stringify(
    value,
    (_, v) =>
      v instanceof Uint8Array
        ? sandbox.hex(v)
        : typeof v === "bigint"
        ? String(v)
        : v,
    2,
  );
  d.append(s, p);
  parent.append(d);
  return d;
}
async function api(path, body, opts = {}) {
  const ref = typeof body?.nonce === "string" && /^[0-9a-f]{32}$/.test(body.nonce) ? body.nonce.slice(0, 8) : undefined;
  try {
    const read = async () => {
      const response = await fetch(cfg.broker + path, {
        method: body === undefined ? "GET" : "POST",
        headers: body === undefined ? {} : { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        cache: "no-store",
        signal: opts.signal,
      });
      if (!response.ok) {
        const raw = await response.text();
        let e;
        try {
          e = JSON.parse(raw).error;
        } catch {}
        const code = typeof e === "object" ? e?.code : e;
        const friendly = path.startsWith("/sandbox/nodes/") && path.includes("/attestation") && response.status >= 500
          ? `The broker could not fetch the guest's fresh attestation (HTTP ${response.status}). Directory: broker.`
          : code === "starter_sandbox_used"
          ? "Your starter sandbox allowance has already been used by this wallet. Additional starter time is not available for this trial."
          : code === "diagnostic_node_not_live"
          ? "The selected sandbox retired before your job was reserved. No repository or task was sent."
          : undefined;
        const message = friendly || (typeof e === "object"
          ? [e?.code, e?.message].filter(Boolean).join(": ")
          : e) ||
          `Broker ${path}: HTTP ${response.status}`;
        throw Object.assign(new Error(message), { code, status: response.status,
          retryAfterSeconds: typeof e === "object" ? e?.retryAfterSeconds : undefined });
      }
      return opts.stream ? response : await response.json();
    };
    // Attestation asks the guest to sign a fresh challenge; never resend it.
    return body === undefined && !path.startsWith("/sandbox/nodes/")
      ? await readWithRetry(read, opts.signal) : await read();
  } catch (error) {
    throw referenceError(error, ref);
  }
}
function render() {
  $("wallet").textContent = credit.address || "Your wallet is created when you send your first message.";
  document.documentElement.dataset.walletLoaded = "true";
  continuity?.update().catch(error);
  $("wallet-tools").hidden = !credit.address;
  renderChatCredit();
}
function renderChatCredit() {
  const c = credit.chatCredit;
  $("chat-credit").dataset.remainingNanoUsd = c?.remainingNanoUsd || "";
  $("chat-credit").dataset.spentNanoUsd = c?.spentNanoUsd || "";
  $("chat-credit").textContent = c
    ? `$${(Number(c.remainingNanoUsd) / 1e9).toFixed(2)} credit`
    : credit.address ? "Checking credit…" : "Credit on first send";
  $("chat-credit-status").textContent = c?.pendingInferenceId ? "Usage pending" : "";
}
async function claimChatCredit() {
  require(
    selectedModel || quote?.configured,
    "Private inference is not configured on this broker.",
  );
  await credit.checkBroker(api);
  const result = await api(
    "/inference/credit",
    await walletBody(credit, "credit"),
  );
  require(
    result.wallet?.toLowerCase() === credit.address.toLowerCase(),
    "Chat credit belongs to another wallet.",
  );
  credit.chatCredit = result;
  render();
  if (sharedLink) activeArtifactView?.refreshSelectedBudget().catch(error);
  if (guest) await guest.restore();
}
async function ensureWallet({ claim = true } = {}) {
  if (!credit.signer) {
    await keys.create();
    await credit.init();
    currentSession.dsmack.wallet = credit.address.toLowerCase();
    if (cfg.syncAnchor) sync = new ChatSync({ cfg, credit, keys: keys.bundle, storage, api });
    currentSession.messages = agent.state.messages;
    if (!await loadSharedViewer()) await useSession(currentSession);
    if (sendingMessage && !agent.state.messages.includes(sendingMessage)) {
      agent.state.messages = [...agent.state.messages, sendingMessage];
      chat.requestUpdate();
    }
    render();
  }
  if (claim) await claimChatCredit();
}
async function refreshServices() {
  await startupStep("broker-identity", () => credit.checkBroker(api));
  quote = await startupStep("inference-quote", () => api("/inference/quote"));
  require(
    quote.mode === "broker-e2ee" && quote.provider === "near" &&
      typeof quote.model === "string",
    "Broker does not offer browser-encrypted NEAR chat.",
  );
  setModel();
  if (credit.signer && (quote.configured || selectedModel)) await startupStep("wallet-credit", claimChatCredit);
  $("pins").textContent = JSON.stringify(
    {
      chainId: 84532,
      escrow: cfg.escrow,
      codeHash: cfg.codeHash,
      brokerKey: cfg.brokerKey,
      grantSigner: cfg.grantSigner,
    },
    null,
    2,
  );
  render();
  document.documentElement.dataset.servicesReady = "true";
}
async function usage() {
  require(credit.signer, "Create or connect a wallet first.");
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const result = await api(
        "/inference/usage",
        await walletBody(credit, "usage"),
      );
      require(
        result.wallet?.toLowerCase() === credit.address.toLowerCase(),
        "Provider usage belongs to another wallet.",
      );
      credit.chatCredit = result;
      renderChatCredit();
      $("usage").textContent =
        `Credit: ${result.usedTokens} model tokens · ${result.spentNanoUsd} nano-USD total charged · ${
          formatNanoUsd(result.remainingNanoUsd)
        } available`;
      details($("usage"), "Metered wallet credit", result);
      return result;
    } catch (e) {
      if (!e.message.startsWith("USAGE_PENDING:")) throw e;
      $("chat-credit-status").textContent =
        "Usage pending";
      if (attempt === 29) {
        throw new Error(
          "USAGE_PENDING: The last charge is still being confirmed. Try again in a minute.",
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}
function renderEvidence(e) {
  if (e.type !== "guest-run") $("verified").hidden = !!selectedModel || e.browser?.fullQuoteVerifiedBy !== "browser";
  $("attestations").replaceChildren();
  details($("attestations"), "Latest verification details", e);
}
function setModel() {
  if (!agent) return;
  agent.state.model = selectedModel || {
    id: quote?.model || "unavailable",
    name: quote?.model || "NEAR TEE model",
    api: "dsmack-inference",
    provider: "near",
    baseUrl: cfg.broker + "/inference",
    reasoning: false,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: quote?.contextWindow || 1048576,
    maxTokens: quote?.maxOutputTokens || 512,
  };
  $("model").textContent = modelBadge(agent.state.model);
  $("model-privacy").textContent = modelPrivacy(agent.state.model);
  $("verified").hidden = !!selectedModel || !currentSession.dsmack.evidence.some(e =>
    e.model === agent.state.model.id && e.browser?.fullQuoteVerifiedBy === "browser");
  chat?.requestUpdate();
}
async function saveCurrentChat(publish = false) {
  const session = currentSession;
  chat.dataset.saved = "false";
  const task = persistSession(session, agent);
  lastSave = task;
  try {
    const data = await task;
    if (currentSession === session) {
      $("session-title").textContent = data.messages.some(m => m.role === "user") ? data.title : "";
      chat.dataset.saved = "true";
      continuity?.update().catch(error);
    }
    if (publish && sync) {
      try {
        chat.dataset.synced = "false";
        await sync.push(data.id);
        if (currentSession === session) {
          chat.dataset.synced = "true";
          $("chat-status").hidden = true;
        }
      } catch (e) {
        syncFailure(e);
      }
    }
  } catch (e) {
    $("chat-status").hidden = false;
    $("chat-status").textContent = "Couldn’t save this chat. Check your browser storage.";
    error(e);
    throw e;
  }
}
async function addEvidence(e) {
  currentSession.dsmack.evidence.push(e);
  renderEvidence(e);
  await saveCurrentChat();
}
function setChatBusy(busy) {
  chatBusy = busy;
  if (!busy) $("capacity-status").textContent = "";
  $("new-chat").disabled = busy;
  $("sessions").disabled = busy;
  $("provider-settings").disabled = busy;
  renderReplyRecovery();
}
function renderReplyRecovery() {
  const panel = $("reply-recovery");
  if (!panel) return;
  const reply = retryCandidate(agent?.state.messages || []);
  panel.hidden = !reply;
  if (!reply) return;
  panel.dataset.category = reply.failure.category;
  const user = agent.state.messages.findLast(message => message.role === "user");
  $("reply-recovery-message").hidden = user?.sendStage === "error" && !!user.sendStatus;
  $("reply-recovery-message").textContent = reply.failure.message;
  $("reply-recovery-message").title = reply.failure.detail || "";
  $("reply-recovery-charge").textContent = reply.provider === "near" ? meteredReply(reply.billing) : "Model tokens are billed by your provider. Guest seconds use chat credit.";
  $("retry-reply").disabled = chatBusy || agent.state.isStreaming;
}
async function retryReply() {
  const originalAgent = agent, reply = retryCandidate(agent.state.messages);
  if (!reply || chatBusy || agent.state.isStreaming) return;
  setChatBusy(true);
  clearError();
  sendingMessage = agent.state.messages.findLast(message => message.role === "user");
  chat.setAutoScroll(true);
  try {
    if (reply.provider === "near") {
      $("reply-recovery-charge").textContent = "Checking the last charge before retrying…";
      const ledger = await usage();
      require(!ledger.pendingInferenceId, "USAGE_PENDING: Provider cost is still pending.");
      if (settleInterruptedReply(reply, ledger)) await saveCurrentChat();
    }
    await chat.onBeforeSend();
    require(agent === originalAgent && retryCandidate(agent.state.messages) === reply,
      "This conversation changed. Select its latest interrupted reply before retrying.");
    // Pi accepts an empty prompt list. No duplicate user message is appended:
    // inference.modelTranscript omits the failed assistant and resends the last
    // user/tool context while preserving the interrupted text in local history.
    $("reply-recovery").hidden = true;
    await agent.prompt([]);
    if (!retryCandidate(agent.state.messages)) sendStatus("");
  } catch (e) {
    sendFailure(e);
  } finally {
    await saveCurrentChat().catch(error);
    sendingMessage = undefined;
    setChatBusy(false);
    chat.requestUpdate();
  }
}
const guestIndexKey = wallet => `artifact-guest-pending:${wallet.toLowerCase()}`;
let guestCard;
function taskCard() {
  if (guestCard) return guestCard;
  guestCard = document.createElement("section"); guestCard.id = "artifact-guest-card"; guestCard.className = "dsmack-sandbox"; guestCard.hidden = true;
  const label = document.createElement("p"); label.className = "sandbox-label"; label.textContent = "Dsmack sandbox"; guestCard.append(label);
  const title = document.createElement("h3"); title.textContent = "Run app command in a fresh guest";
  guestCard.append(title);
  for (const [tag, attribute] of [["p","guest-filename"],["p","guest-wallet"],["p","guest-credit"],["p","guest-timeout"],["pre","guest-command"],["p","guest-status"]]) {
    const element = document.createElement(tag); element.dataset[attribute.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = ""; guestCard.append(element);
  }
  for (const [attribute, label] of [["guest-confirm","Run command"],["guest-cancel","Cancel"],["guest-release","Finish releasing task guest"]]) {
    const button = document.createElement("button"); button.dataset[attribute.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = ""; button.textContent = label; guestCard.append(button);
  }
  $("artifacts-host").before(guestCard); return guestCard;
}
function showTask(record, service) {
  const card = taskCard(); card.hidden = false;
  card.dataset.state = record.state; card.dataset.sessionId = record.sessionId || "";
  card.dataset.active = String(record.status?.active ?? !!record.sessionId);
  card.dataset.usageUnresolved = String(!!record.status?.usageUnresolved);
  card.querySelector("[data-guest-filename]").textContent = record.filename;
  card.querySelector("[data-guest-wallet]").textContent = "Viewer wallet: " + record.wallet;
  card.querySelector("[data-guest-command]").textContent = record.command;
  card.querySelector("[data-guest-timeout]").textContent = `Command timeout: ${record.timeoutSeconds} seconds. Guest time is charged separately from the app model budget.`;
  card.querySelector("[data-guest-status]").textContent = record.state === "released" ? "Task guest released; final metering received." + (record.error ? " " + record.error : "") : record.error || record.state;
  const release = card.querySelector("[data-guest-release]"); release.hidden = record.state !== "release-pending";
  release.onclick = async () => { release.disabled = true; try { await service.finish(record); await usage(); render(); } catch (e) { error(e); } finally { release.disabled = false; } };
  card.querySelector("[data-guest-confirm]").hidden = record.state !== "confirming";
  card.querySelector("[data-guest-cancel]").hidden = ["released","release-pending","cancelled"].includes(record.state);
  card.querySelector("[data-guest-cancel]").onclick = () => service.dispose();
}
async function appArtifactGuests(session, state) {
  if (artifactGuests.has(session.id)) return artifactGuests.get(session.id);
  const taskScope = JSON.stringify(["host-guest-tasks", session.id]);
  const initial = Object.values((await state.read(taskScope)).tasks || {});
  let service;
  service = new ArtifactGuests({ credit, api, authorize: walletBody, initial,
    mainHeld: () => [...guests.values()].some(value => value.lease || value.opening || value.savedLease?.active) ||
      [...artifactGuests.values()].some(value => value !== service && value.busy),
    createSession: options => new GuestSession({ ...options, cfg, discover, reverify, catalog: piToolCatalog }),
    confirm: (record, signal) => new Promise(resolve => {
      showTask(record, service);
      const card = taskCard(), approve = card.querySelector("[data-guest-confirm]"), cancel = card.querySelector("[data-guest-cancel]");
      card.querySelector("[data-guest-credit]").textContent = "Available viewer credit: " + formatNanoUsd(record.credit);
      card.scrollIntoView({ block: "nearest" });
      const finish = approved => { signal.removeEventListener("abort", aborted); approve.onclick = cancel.onclick = null; resolve(approved); };
      const aborted = () => finish(false);
      approve.onclick = () => finish(true); cancel.onclick = () => finish(false);
      if (signal.aborted) aborted(); else signal.addEventListener("abort", aborted, { once: true });
    }),
    persist: async record => {
      await state.update(taskScope, data => { (data.tasks ||= {})[record.id] = record; });
      const key = guestIndexKey(record.wallet), entries = (await store(key) || []).filter(entry => entry.id !== record.id);
      if (record.sessionId && record.state !== "released") entries.push({ ownerSessionId: session.id, id: record.id, scope: record.scope, conversationId: record.conversationId, sessionId: record.sessionId, wallet: record.wallet });
      await store(key, entries);
    },
    evidence: async evidence => { if (currentSession.id === session.id) renderEvidence(evidence); },
    changed: record => { showTask(record, service); if (record.state === "released") usage().then(render).catch(error); },
  });
  artifactGuests.set(session.id, service);
  return service;
}
async function recoverArtifactGuests() {
  const entries = await store(guestIndexKey(credit.address)) || [];
  for (const entry of entries) {
    if (artifactGuests.has(entry.ownerSessionId)) {
      const service = artifactGuests.get(entry.ownerSessionId), record = service.records.get(entry.id);
      if (record) showTask(record, service);
      continue;
    }
    const saved = await storage.sessions.get(entry.ownerSessionId);
    if (!saved) { error(Error("The owned task record is unavailable; recover its original chat before releasing it.")); continue; }
    const snapshot = { state: { messages: saved.messages, model: saved.model, thinkingLevel: saved.thinkingLevel } };
    const state = new ArtifactState({ dataKey: keys.bundle.dk,
      getRecord: async scope => (await storage.sessions.get(saved.id))?.dsmack?.artifactState?.[scope],
      saveRecord: async (scope, envelope) => { await persistSession(saved, snapshot, {scope,envelope}); if (sync) try { await sync.push(saved.id); } catch(e) { error(e); } },
    });
    const service = await appArtifactGuests(saved, state), record = service.records.get(entry.id);
    if (record) showTask(record, service);
  }
}
addEventListener("pagehide", () => { for (const service of artifactGuests.values()) service.dispose(); });
async function useSession(data) {
  if (agent) await agent.waitForIdle();
  await lastSave;
  unsubscribeChat?.();
  currentSession = data || {
    id: crypto.randomUUID(), title: "New chat", createdAt: new Date().toISOString(),
    messages: [], dsmack: { evidence: [], wallet: credit.address?.toLowerCase() },
  };
  for (const message of currentSession.messages) {
    if (message !== sendingMessage && message.sendStage !== "error") {
      delete message.sendStatus;
      delete message.sendStage;
      delete message.sendDetail;
    }
  }
  const conversationId = currentSession.id;
  const sessionRecord = currentSession;
  guest = guests.get(conversationId);
  if (!guest) {
    const workspace = new SavedWorkspace({
      workspaceId: conversationId, credit, dataKey: () => keys.bundle?.dk,
      request: async (operation, fields) => api("/workspaces/" + operation, await walletBody(credit, "workspace-" + operation, fields)),
      head: sessionRecord.dsmack.workspace,
      persist: async head => {
        const held = guests.get(conversationId);
        const record = held?.record;
        require(record, "Conversation is not ready to save its workspace.");
        record.session.dsmack.workspace = head;
        const saved = lastSave.catch(() => {}).then(() => persistSession(record.session, record.agent));
        lastSave = saved;
        await saved;
        if (sync) await sync.push(conversationId);
      },
      changed: status => {
        const held = guests.get(conversationId);
        if (held) held.workspaceStatus = status;
        if (currentSession.id === conversationId) renderWorkspace(status);
      },
    });
    guest = new GuestSession({
      api, cfg, credit, conversationId, discover, reverify, workspace, savedLease: currentSession.dsmack.guest, macInfo,
      connectionStatus: (stage, verified) => { if (currentSession.id === conversationId) connectionStatus(stage, verified); },
      changed: (status) => {
        const held = guests.get(conversationId);
        if (held) {
          held.statusSnapshot = status;
          if (status.lease && held.record && (status.active !== undefined || ["connecting", "released", "held", "disconnected-held"].includes(status.state))) {
            const record = held.record;
            record.session.dsmack.guest = {
              sessionId: status.lease.sessionId, conversationId,
              wallet: credit.address.toLowerCase(), active: status.active ?? !["released"].includes(status.state),
              node: status.node || held.node?.registration, mac: macInfo(held.node),
              environment: status.environment || held.environment,
              guestSeconds: status.guestSeconds || 0,
            };
            lastSave = lastSave.catch(() => {}).then(() => persistSession(record.session, record.agent));
          }
        }
        if (currentSession.id === conversationId) renderGuest(status);
      },
      repository: () => repoFiles, catalog: piToolCatalog,
    });
    guests.set(conversationId, guest);
  }
  renderGuest(guest.statusSnapshot || { state: "idle" });
  renderWorkspace(guest.workspaceStatus || { head: sessionRecord.dsmack.workspace });
  let artifacts, artifactAgent;
  activeArtifactView?.dispose?.();
  activeArtifactView = undefined;
  const artifactHost = $("artifacts-host");
  artifactHost.replaceChildren();
  artifactHost.hidden = true;
  $("open-artifacts").hidden = true;
  $("open-artifacts").onclick = null;
  if (keys.bundle && credit.signer) {
    const artifactSession = currentSession;
    const saveArtifact = async (scope, envelope) => {
      const task = persistSession(artifactSession, artifactAgent, { scope, envelope });
      lastSave = task;
      await task;
      if (sync) try { await sync.push(artifactSession.id); }
      catch (e) { error(e); }
    };
    const artifactState = new ArtifactState({ dataKey: keys.bundle.dk,
      getRecord: async scope => (await storage.sessions.get(artifactSession.id))?.dsmack?.artifactState?.[scope],
      saveRecord: saveArtifact,
    });
    const artifactModels = new ArtifactModels({ state: artifactState, credit, api, cfg, quote: () => quote, usage,
      evidence: async evidence => {
        artifactSession.dsmack.evidence.push(evidence);
        if (currentSession === artifactSession) renderEvidence(evidence);
        const task = persistSession(artifactSession, artifactAgent);
        lastSave = task;
        await task;
        if (sync) try { await sync.push(artifactSession.id); } catch (e) { error(e); }
      },
      changed: scope => artifacts?.refreshBudget(scope).catch(error),
    });
    const taskGuests = await appArtifactGuests(artifactSession, artifactState);
    artifacts = createArtifacts(undefined, { state: artifactState, models: artifactModels, guests: taskGuests, credit,
      scopeForFilename: filename => filename === "shared.html" && artifactSession.dsmack.sharedArtifactCid
        ? sharedScope(artifactSession.dsmack.sharedArtifactCid) : JSON.stringify([artifactSession.id, filename]), error,
      share: async html => {
        const sealed = await sealArtifact(html);
        const result = await api("/artifacts/share", await walletBody(credit, "artifact-share", { ciphertext: sealed.ciphertext }));
        require(result.cid === sealed.cid && result.pinned === true, "The encrypted app was not pinned with its expected CID.");
        return artifactLink(sealed);
      },
    });
    activeArtifactView = artifacts;
    artifactHost.replaceChildren(artifacts.budgetBar, artifacts.shareBar, artifacts.panel);
    artifactHost.hidden = true;
    const openArtifacts = () => {
      artifactHost.hidden = false; artifacts.panel.collapsed = false;
      artifacts.refreshSelectedBudget().catch(error);
    };
    artifacts.panel.onOpen = openArtifacts;
    artifacts.panel.onClose = () => { artifactHost.hidden = true; };
    artifacts.panel.onArtifactsChange = () => { $("open-artifacts").hidden = !artifacts.panel.artifacts.size; };
    $("open-artifacts").onclick = openArtifacts;
  }
  const systemPrompt = ({ model = agent.state.model, runtime }) => buildAgentPrompt({
    config: cfg, pageUrl: window.location.href,
    runtime: { preamble: "You are Abalone, a coding assistant in the Abalone private agent page. Use the provided tools to inspect and change the attested Mac-hosted Linux workspace. " + modelPrivacy(model) + "\n\n" + runtime + "\n\nThe application supplies these runtime facts. Your self-report is not proof; refer to the verified attestation shown by the page." },
    environment: guest.environment || measuredEnvironment(),
    attestation: guest.node ? { verification: "Browser verified Apple enrollment, build, measured compose and bound Noise peer", guestPeer: guest.node.registration.relay_peer, manifestHash: guest.node.registration.manifest_sha256, imageHash: guest.node.registration.os_image_hash, cdhash: guest.node.registration.cdhash } : { status: "Guest attestation will be verified before the first tool call.", cdhash: policy.cdhash },
    repository: "Initial repository snapshot; use the read tool for current workspace contents.\n" + [...repoFiles].map(([name, text]) => `${name}\n${text.length < 4096 ? text : "Read this file with the read tool."}`).join("\n"),
  }) + "\n\n" + ARTIFACT_PROMPT;
  const preflight = (context, signal) => guest.preflight(context, signal, policy.manifest);
  agent = new Agent({
    initialState: {
      systemPrompt: "You are the Abalone private agent. Use your tools to inspect and change the attested workspace.",
      messages: currentSession.messages,
      thinkingLevel: "off",
      tools: [...guest.tools(), ...(artifacts ? [artifacts.tool] : [])],
    },
    toolExecution: "sequential",
    getApiKey: provider => provider === "near" ? undefined : storage.providerKeys.get(provider),
    streamFn: providerStream({ preflight, systemPrompt, startedAt: currentSession.createdAt, near: brokerStream({
      credit, api, cfg, quote: () => quote, evidence: addEvidence, usage, error: sendFailure, status: sendStatus,
      billingUpdated: async answer => {
        const reply = artifactAgent.state.messages.findLast(message => message.role === "assistant" &&
          message.billing?.sessionId === answer.billing.sessionId);
        if (!reply) return;
        reply.billing = { ...answer.billing };
        reply.usage = structuredClone(answer.usage);
        lastSave = persistSession(sessionRecord, artifactAgent);
        await lastSave;
        if (currentSession === sessionRecord) { chat.requestUpdate(); renderReplyRecovery(); }
      },
      preflight, systemPrompt,
      startedAt: currentSession.createdAt,
    }) }),
  });
  artifactAgent = agent;
  if (artifacts) {
    artifacts.panel.agent = agent;
    const imported = sharedBundle && sharedLink && currentSession.dsmack.sharedArtifactCid === sharedLink.cid
      ? [{ role: "artifact", action: "create", filename: "shared.html", content: sharedBundle.html }] : [];
    await artifacts.panel.reconstructFromMessages([...currentSession.messages.filter((message) =>
      message.role !== "artifact" || /\.html$/i.test(message.filename || "")), ...imported]);
    $("open-artifacts").hidden = !artifacts.panel.artifacts.size;
    if (imported.length) { artifactHost.hidden = false; artifacts.panel.openArtifact("shared.html"); }
  }
  failOrphanedTools(agent.state.messages, "Lost the connection to the sandbox before this command finished. It was not run again.");
  guest.record = { session: currentSession, agent };
  if (keys.bundle && credit.signer) await recoverArtifactGuests();
  if (credit.signer) {
    try { await guest.restore(); }
    catch (e) { renderGuest({ state: guest.lease ? "disconnected-held" : "error", error: e.message }); }
  }
  setModel();
  $("attestations").replaceChildren();
  $("verified").hidden = true;
  for (const e of currentSession.dsmack.evidence) renderEvidence(e);
  for (const record of artifactGuests.get(currentSession.id)?.records.values() || []) if (record.sessionId) renderEvidence({ ...record, type: "guest-run" });
  chat.session = agent;
  chat.dataset.sessionId = currentSession.id;
  if (!chat.isConnected) $("chat-host").append(chat);
  await chat.updateComplete;
  chat.querySelector("message-editor").prepend($("code-attachment"));
  let firstPartial = true;
  unsubscribeChat = agent.subscribe((event, signal) => {
    renderToolProgress(chat, agent, event);
    if (event.type === "message_start") firstPartial = true;
    if (firstPartial && event.type === "message_update" && event.message.role === "assistant" &&
      event.message.content.some(part => part.type === "text" && part.text)) {
      firstPartial = false;
      sendStatus("");
      // Pi 0.75's clear-before-stream flag drops its first batched partial. Core
      // 1.4 keeps it in streamingMessage until message_end. Show the first text
      // immediately in Pi's component, leaving later deltas to native batching.
      const container = chat.querySelector("streaming-message-container");
      container.isStreaming = agent.state.isStreaming;
      container.setMessage({ ...event.message }, true);
    }
    // Pi's message list observes array references; the agent appends in place.
    if (event.type === "message_end") {
      if (event.message.role === "assistant") {
        if (event.message.failure) sendFailure({ replyFailure: event.message.failure });
        else sendStatus("");
      }
      agent.state.messages = [...agent.state.messages];
      chat.requestUpdate();
      renderReplyRecovery();
    }
    if (event.type === "agent_end") {
      failOrphanedTools(agent.state.messages, signal.aborted
        ? "Cancelled before a tool result was received. Execution was not retried."
        : "Lost the connection to the sandbox before this command finished. It was not run again.");
      agent.state.messages = [...agent.state.messages];
    }
    // Core 1.4 awaits listeners before becoming idle. Remote sync must not
    // hold the composer busy, including after cancellation during an outage.
    if (event.type === "message_end" || event.type === "agent_end") saveCurrentChat(event.type === "agent_end").catch(error);
  });
  await saveCurrentChat();
  await storage.settings.set("chat.active", currentSession.id);
  renderReplyRecovery();
}
async function loadSharedViewer() {
  if (!sharedLink || !keys.bundle || !credit.signer) return false;
  if (!sharedBundle) {
    const response = await api("/artifacts/share/" + encodeURIComponent(sharedLink.cid));
    require(response.cid === sharedLink.cid, "The shared app response identifies a different CID.");
    sharedBundle = await openArtifact({ ...response, key: sharedLink.key });
  }
  const id = viewerSessionId(credit.address, sharedLink.cid);
  const saved = await storage.sessions.get(id);
  await useSession(saved || { id, title: "Shared app", createdAt: new Date().toISOString(), messages: [],
    dsmack: { evidence: [], wallet: credit.address.toLowerCase(), sharedArtifactCid: sharedLink.cid } });
  return true;
}
function initProviderSettings() {
  const dialog = $("provider-dialog"), form = $("provider-form"), provider = $("provider-choice");
  const showFields = () => {
    $("provider-fields").hidden = provider.value === "near";
    $("provider-url-label").hidden = provider.value !== "openai-compatible";
    $("provider-model").setAttribute("list", provider.value === "anthropic" ? "anthropic-models" : "");
  };
  for (const id of anthropicModels) {
    const option = document.createElement("option"); option.value = id; $("anthropic-models").append(option);
  }
  provider.onchange = () => {
    $("provider-key").value = "";
    $("provider-model").value = provider.value === "anthropic" ? defaultAnthropicModel : "";
    $("provider-url").value = "https://api.openai.com/v1";
    showFields();
  };
  action("provider-settings", () => {
    provider.value = selectedModel?.provider === "anthropic" ? "anthropic" : selectedModel ? "openai-compatible" : "near";
    $("provider-model").value = selectedModel?.id || defaultAnthropicModel;
    $("provider-url").value = selectedModel?.baseUrl || "https://api.openai.com/v1";
    $("provider-key").value = "";
    $("provider-error").textContent = "";
    showFields(); dialog.showModal();
  });
  $("provider-cancel").onclick = () => dialog.close();
  dialog.addEventListener("close", () => { $("provider-key").value = ""; });
  form.onsubmit = async event => {
    event.preventDefault();
    $("provider-save").disabled = true;
    $("provider-cancel").disabled = true;
    $("provider-error").textContent = "";
    try {
      const model = provider.value === "near" ? undefined : directModel(provider.value, $("provider-model").value, $("provider-url").value);
      const key = $("provider-key").value.trim() || (model && await storage.providerKeys.get(model.provider)) || "";
      if (model) await checkProvider(model, key);
      await saveProvider(storage, model, key);
      selectedModel = model;
      setModel();
      await saveCurrentChat();
      dialog.close();
    } catch (e) {
      const failure = replyFailure(e);
      $("provider-error").textContent = failure.message;
      $("provider-error").title = failure.detail;
    }
    finally { $("provider-save").disabled = false; $("provider-cancel").disabled = false; }
  };
}
async function initChat() {
  storage = createChatStorage();
  selectedModel = await loadProvider(storage);
  initProviderSettings();
  persistSession = createSessionPersistence({ storage, save: saveChat });
  if (keys.bundle && cfg.syncAnchor) sync = new ChatSync({ cfg, credit, keys: keys.bundle, storage, api });
  installMessageFeedback(() => ({ session: currentSession, messages: agent.state.messages }));
  chat = new AgentInterface();
  chat.addEventListener("message-feedback", event => {
    const record = {
      id: crypto.randomUUID(), ...event.detail, createdAt: new Date().toISOString(),
      pageVersion: document.querySelector('meta[name="page-bundle-cid"]').content,
      ...(guest?.lease ? { guestId: guest.lease.sessionId } : {}),
    };
    currentSession.feedback = [...(currentSession.feedback || []), record];
    for (const control of chat.querySelectorAll("message-feedback")) control.records = currentSession.feedback;
    saveCurrentChat(true).catch(error);
  });
  chat.id = "chat";
  // Pi 0.75's icon buttons have no accessible name. Refresh after child render.
  const emptyChat = $("empty-chat");
  chat.updated = () => {
    updateSandboxLabels();
    emptyChat.hidden = agent.state.messages.some(message => message.role === "user");
    chat.querySelector("message-list")?.before(emptyChat);
    const editor = chat.querySelector("message-editor");
    if (editor) editor.updateComplete.then(() => {
      const button = editor.querySelector("button:last-child");
      button?.setAttribute("aria-label", chat.session.state.isStreaming ? "Cancel reply" : "Send message");
    });
  };
  chat.enableAttachments = false;
  chat.enableModelSelector = false;
  chat.enableThinkingSelector = false;
  const recoveryPanel = document.createElement("div");
  recoveryPanel.id = "reply-recovery";
  recoveryPanel.className = "reply-recovery";
  recoveryPanel.hidden = true;
  recoveryPanel.setAttribute("role", "status");
  const message = document.createElement("p"), charge = document.createElement("p"), retry = document.createElement("button");
  message.id = "reply-recovery-message";
  charge.id = "reply-recovery-charge";
  charge.className = "small muted";
  retry.id = "retry-reply";
  retry.textContent = "Retry";
  retry.addEventListener("click", retryReply);
  recoveryPanel.append(message, charge, retry);
  $("chat-host").before(recoveryPanel);
  // NEAR uses wallet credit; direct providers resolve browser-only keys in Agent.
  chat.onApiKeyRequired = async () => true;
  chat.onBeforeSend = async () => {
    clearError();
    sendStatus("Checking credit…", "", "credit");
    await credit.checkBroker(api);
    if (!selectedModel) require(quote?.configured, "Private inference is not configured on this broker.");
    await ensureWallet();
    if (!selectedModel) {
      if (credit.chatCredit.pendingInferenceId) await usage();
      require(!credit.chatCredit.pendingInferenceId,
        "USAGE_PENDING: The last charge is still being confirmed. Try again in a minute.");
      require(BigInt(credit.chatCredit.remainingNanoUsd) > 0n,
        "CREDIT_EXHAUSTED: Chat credit used up.");
    }
    if (!await storage.settings.get("chat.persistenceRequested")) {
      await storage.requestPersistence();
      await storage.settings.set("chat.persistenceRequested", true);
    }
  };
  chat.sendMessage = async input => {
    if (!input.trim() || chatBusy || agent.state.isStreaming) return;
    setChatBusy(true);
    sendingMessage = { role: "user", content: input, timestamp: Date.now(), sendStatus: "Checking credit…", sendStage: "credit" };
    agent.state.messages = [...agent.state.messages, sendingMessage];
    const editor = chat.querySelector("message-editor");
    editor.value = "";
    chat.setAutoScroll(true);
    let retainMessage = false;
    chat.requestUpdate();
    try {
      // Render the accepted message before the first asynchronous credit check.
      await chat.updateComplete;
      await chat.querySelector("message-list").updateComplete;
      chat.querySelector("user-message:last-of-type")?.scrollIntoView({ block: "nearest" });
      await chat.onBeforeSend();
      require(agent.state.messages.includes(sendingMessage), "Your message is no longer in this chat. Please send it again.");
      retainMessage = true;
      chat.setAutoScroll(true);
      await agent.prompt([]);
      const replies = agent.state.messages.slice(agent.state.messages.indexOf(sendingMessage) + 1)
        .filter(message => message.role !== "system");
      const refused = replies.length === 1 && replies[0].failure && replies[0].billing?.dispatched === false
        ? replies[0] : undefined;
      if (refused) {
        agent.state.messages = agent.state.messages.filter(message => message !== refused);
        retainMessage = false;
        throw Object.assign(new Error(refused.failure.message), { replyFailure: refused.failure });
      }
    } catch (e) {
      if (!retainMessage) {
        agent.state.messages = agent.state.messages.filter(message => message !== sendingMessage);
        chat.querySelector("message-editor").value = input;
        chat.requestUpdate();
        error(e);
      } else sendFailure(e);
    }
    finally {
      await saveCurrentChat().catch(error);
      sendingMessage = undefined;
      setChatBusy(false);
      chat.requestUpdate();
    }
  };
  chat.renderStats = () => {
    const total = (agent?.state.messages || []).reduce((sum, message) =>
      sum + (message.role === "assistant" ? message.usage?.cost?.total || 0 : 0), 0);
    const amount = total > 0 && total < 0.0001 ? "<$0.0001" : "$" + total.toFixed(4);
    return html`<div class="text-xs text-muted-foreground text-right h-5">${amount} used this chat</div>`;
  };
  const active = await storage.settings.get("chat.active") || await storage.sessions.getLatestSessionId();
  const saved = active ? await storage.sessions.get(active) : null;
  const sameWallet = credit.address && (!saved?.dsmack?.wallet || saved.dsmack.wallet === credit.address.toLowerCase());
  if (!await loadSharedViewer()) await useSession(sameWallet ? saved : null);
  action("new-chat", () => useSession());
  action("sessions", async () => {
    const dialog = new SessionListDialog();
    dialog.onSelectCallback = id => (async () => {
      const data = await storage.sessions.get(id);
      require(data, "This saved chat has been deleted.");
      await useSession(data);
    })().catch(error);
    dialog.onDeleteCallback = id => { if (id === currentSession.id) useSession().catch(error); };
    const content = dialog.renderContent.bind(dialog);
    const download = async sessionId => {
      await saveCurrentChat();
      const jsonl = await exportChats(storage, credit.address, sessionId);
      const url = URL.createObjectURL(new Blob([jsonl], { type: "application/x-ndjson" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = sessionId ? `chat-${sessionId}.jsonl` : "chats.jsonl";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    dialog.renderContent = () => html`<div class="chat-exports"><span>Export chats</span>
      <button class="secondary" @click=${() => download(currentSession.id).catch(error)}>Current chat</button>
      <button class="secondary" @click=${() => download().catch(error)}>All chats</button>
    </div>${content()}`;
    dialog.open();
    await dialog.loadSessions();
  });
}

// On-chain mode (the default) pins code only: the guest's App Attest key is read from AppleAttestRegistry through
// layover-chain (Helios) and must have a MacLink to the payee, so a Mac's key rotation needs no new policy.
function loadPolicy(raw) {
  const onChain = (raw?.enrollmentMode ?? "on-chain") === "on-chain";
  require(
    raw && typeof raw.manifest === "string" && (onChain || raw.enrollment),
    "Sandbox policy needs exact manifest bytes, and Apple enrollment bytes in apple-root mode.",
  );
  const p = {
    ...raw,
    manifest: sandbox.unhex(raw.manifest),
    operatorsOf: brokerOwners(cfg.broker + "/fleet/ownership", cfg.escrow),
  };
  if (onChain) p.chain = heliosChain(raw);
  else {
    p.enrollment = {
      attestation: sandbox.unhex(raw.enrollment.attestation),
      keyId: raw.enrollment.keyId,
      clientData: sandbox.unhex(raw.enrollment.clientData),
    };
  }
  require(
    p.brokerKey === cfg.brokerKey &&
      p.grantSigner?.toLowerCase() === cfg.grantSigner.toLowerCase(),
    "Wrong broker key or payment signer in sandbox policy.",
  );
  require(
    p.rpc === cfg.rpc,
    "Sandbox policy must use the pinned Base Sepolia RPC.",
  );
  policy = p;
  node = undefined;
  $("node-status").textContent =
    "Approved sandbox policy included. A guest will be verified before tools execute.";
}
function showDirectory(path, brokerFailure, chainFailure) {
  let label = $("directory-status");
  if (!label) {
    label = document.createElement("p");
    label.id = "directory-status";
    label.className = "small";
    label.setAttribute("role", "status");
    $("node-status").before(label);
  }
  label.dataset.path = path;
  label.textContent = [brokerFailure, chainFailure ? `Chain directory failed: ${chainFailure}` : ""].filter(Boolean).join(" · ");
}
function directoryFailure(e) {
  return "Broker guest directory unavailable" + (e.status ? ` (HTTP ${e.status})` : "") +
    (e.message && !e.message.startsWith("Broker /nodes") ? `: ${e.message}` : ".");
}
let chainLookup;
function directoryLookup() {
  return chainLookup ||= chainDirectoryCache({ config: cfg, publisherOnline: async signal => {
    const network = await api("/network", undefined, { signal });
    return network.macs.some(mac => mac.online && mac.publisher.toLowerCase() === cfg.chainDirectory.publisher.toLowerCase());
  } });
}
async function reverify({ registration: prior, signal, directory, browserPeer }) {
  const peer = prior.relay_peer;
  const challenge = sandbox.hex(crypto.getRandomValues(new Uint8Array(32)));
  performance.mark("dsmack:attestation:start", { detail: { peer } });
  let chain, direct;
  if (directory === "chain") {
    chain = await directoryLookup().read({ signal });
    const selected = chain.nodes.find(node => node.relay_peer === peer);
    require(selected, "Chain directory no longer lists this guest.");
    try { direct = await fetchDirectAttestation({ peer: browserPeer, selected, challenge, policy, signal }); }
    catch (error) { directoryLookup().invalidate(); throw error; }
  }
  try {
    const registration = direct?.registration || await api("/sandbox/nodes/" + encodeURIComponent(peer) + "/attestation?challenge=" + challenge, undefined, { signal });
    performance.mark("dsmack:attestation:response", { detail: { peer } });
    require(registration.relay_peer === peer, "Guest attestation identifies a different peer.");
    if (chain) await chain.verifyRegistration(registration, signal);
    const checked = await sandbox.verifyNode(registration, { ...policy, challenge });
    require(registration.payments?.challenge === challenge, "Node challenge mismatch. Stale attestation refused.");
    require(Number(registration.admit_until) * 1000 >= Date.now() + 30000 &&
      registration.payments.runExpires * 1000 >= Date.now() + 30000,
      "Guest is too close to drain to reconnect.");
    performance.mark("dsmack:attestation:verified", { detail: { peer } });
    if (direct) Object.assign(checked, { chainTunnels: direct.entries, connection: direct.connection, directory: "chain", invalidateDirectory: () => directoryLookup().invalidate() });
    return checked;
  } catch (error) {
    await direct?.connection.close().catch(() => {});
    throw error;
  }
}
async function discover({ peer: browserPeer, wait = false, deadline = Date.now() + (wait ? 90000 : 0), exclude = new Set(), signal, workspace, claim } = {}) {
  require(policy, "The bundled sandbox policy could not load. Refresh the page before sending a job.");
  const manifestHash = sandbox.hex(new Uint8Array(await crypto.subtle.digest("SHA-256", policy.manifest)));
  const query = workspace ? "?" + new URLSearchParams({ workspaceId: workspace.workspaceId,
    version: String(workspace.version), hash: workspace.hash }) : "";
  const setupSeconds = 30 + (workspace ? Math.ceil(workspace.size / (512 * 1024)) : 0);
  let lastRefusal, chainDirectory, brokerFailure;
  const mark = (stage, detail) => performance.mark("dsmack:" + stage, { detail });
  const pause = milliseconds => waitForRead(milliseconds, signal);
  let endedOther = false;
  discovery: for (;;) {
    signal?.throwIfAborted();
    $("capacity-status").dataset.stage = "finding";
    $("capacity-status").textContent = "Finding a free Mac on the Dsmack network…";
    await refreshNetwork(signal);
    mark("discovery:start");
    let nodes;
    try {
      nodes = await api("/nodes" + query, undefined, { signal });
      await credit.checkBroker(api);
      showDirectory("broker");
    } catch (e) {
      mark("discovery:end", { error: e.code || e.message });
      if (signal?.aborted) throw e;
      if (["FLEET_BUSY", "FLEET_EMPTY"].includes(e.code)) {
        const retry = Number(e.retryAfterSeconds) || 15;
        showDirectory("broker");
        const message = capacityMessage(e.code === "FLEET_EMPTY", retry);
        $("capacity-status").dataset.stage = e.code === "FLEET_EMPTY" ? "empty" : "busy";
        $("capacity-status").textContent = message;
        if (!wait || Date.now() + retry * 1000 > deadline) throw Object.assign(new Error(message), {
          code: e.code, status: e.status, ref: e.ref, retryAfterSeconds: e.retryAfterSeconds });
        await pause(retry * 1000);
        continue;
      }
      brokerFailure = directoryFailure(e);
      showDirectory("chain", brokerFailure);
      try {
        chainDirectory = await directoryLookup().read({ signal });
        nodes = chainDirectory.nodes;
      } catch (chainError) {
        showDirectory("chain", brokerFailure, chainError.message);
        throw new Error(`${brokerFailure} Directory: chain. Chain directory failed: ${chainError.message}`);
      }
    }
    mark("discovery:end", { candidates: nodes.length });
    $("capacity-status").textContent = "";
    // Keep the broker's order. Placement hints never replace these local pins.
    const candidates = nodes.filter(entry => entry.kind === "compute" &&
      entry.available !== false && !exclude.has(entry.relay_peer) &&
      (chainDirectory || (entry.manifest_sha256 === manifestHash && entry.cdhash === policy.cdhash &&
      Number(entry.admit_until) * 1000 >= Date.now() + setupSeconds * 1000)));
    for (const selected of candidates) {
      signal?.throwIfAborted();
      $("node-status").textContent = "Checking the sandbox's Apple attestation, approved build and bound keys…";
      const challenge = sandbox.hex(crypto.getRandomValues(new Uint8Array(32)));
      const peer = selected.relay_peer;
      let release;
      if (claim) {
        try { release = await claim(selected); }
        catch (e) {
          if (e.code === "SESSION_SAVING") {
            const retry = Math.max(1, Math.min(60, Number(e.retryAfterSeconds) || 5));
            $("node-status").textContent = `Saving workspace. Retry in ${retry} seconds.`;
            if (!wait || Date.now() + retry * 1000 > deadline) throw e;
            await pause(retry * 1000);
            continue discovery;
          }
          if (!["GUEST_BUSY", "NODE_NOT_LIVE"].includes(e.code)) {
            const path = chainDirectory ? `${brokerFailure} Directory: chain.` : "Directory: broker.";
            if (e.code === "SESSION_ACTIVE" && !endedOther) {
              // Another chat (often one already closed) holds the wallet's guest. End it and claim again.
              endedOther = true;
              $("node-status").textContent = "Ending your other chat's guest session…";
              for (const sessionId of String(e.message).match(/[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{32,64}/gi) || [])
                await api("/agent/end", await walletBody(credit, "agent-end", { sessionId }));
              continue discovery;
            }
            if (e.code === "SESSION_ACTIVE")
              throw new Error("Another of your chats still holds a guest and is finishing its session. Retry in a minute. " + e.message);
            throw new Error(`${path} The broker could not reserve the discovered guest (${e.code || "HTTP " + e.status}): ${e.message}`);
          }
          exclude.add(peer);
          mark("grant:unavailable", { peer, error: e.code });
          continue;
        }
      }
      mark("attestation:start", { peer });
      let direct;
      try {
        if (chainDirectory) {
          require(browserPeer, "Direct guest attestation needs a browser peer connection.");
          connectionStatus("connecting", selected);
          mark("attestation:direct", { peer, challenge });
          try { direct = await fetchDirectAttestation({ peer: browserPeer, selected, challenge, policy, signal }); }
          catch (error) { directoryLookup().invalidate(); throw error; }
        }
        const registration = direct ? direct.registration : await api("/sandbox/nodes/" + encodeURIComponent(peer) +
          "/attestation?challenge=" + challenge, undefined, { signal });
        mark("attestation:response", { peer });
        require(registration.relay_peer === peer, "Guest attestation identifies a different peer.");
        if (chainDirectory) await chainDirectory.verifyRegistration(registration, signal);
        const checked = await sandbox.verifyNode(registration, { ...policy, challenge });
        require(!registration.payments || registration.payments.challenge === challenge,
          "Node challenge mismatch. Stale attestation refused.");
        require(Number(registration.admit_until) * 1000 >= Date.now() + setupSeconds * 1000 &&
          (!registration.payments || registration.payments.runExpires * 1000 >= Date.now() + setupSeconds * 1000),
          "Guest is too close to drain. Trying another approved guest.");
        mark("attestation:verified", { peer });
        // The attestation endpoint omits scheduler hints; retain them for sealed
        // workspace placement without treating them as verified evidence.
        checked.placement = selected.scheduler;
        checked.networkMac = macInfo(selected);
        if (direct) {
          checked.chainTunnels = direct.entries;
          checked.connection = direct.connection;
          checked.directory = "chain";
          checked.invalidateDirectory = () => directoryLookup().invalidate();
        }
        node = checked;
        $("node-status").textContent = "Node verified · Apple enrollment (" +
          (checked.enrollmentMode || checked.policy.enrollmentMode || "on-chain") +
          "), approved build, compose, image, broker and bound keys · " + monitorLabel(checked.policy.monitor);
        $("node-evidence").textContent = JSON.stringify(registration, null, 2);
        return checked;
      } catch (e) {
        // No MCP stream or private data exists yet. Revoke this unused grant
        // before trying another guest so failed attestations cannot hold credit.
        await direct?.connection.close().catch(() => {});
        await release?.();
        if (signal?.aborted) throw e;
        mark("attestation:refused", { peer, error: e.message });
        exclude.add(peer);
        lastRefusal = new Error((chainDirectory ? `${brokerFailure} Directory: chain. Direct guest verification failed: ` :
          "Guest verification through the broker failed: ") + e.message + ". No repository or task was sent.");
        if (chainDirectory) throw lastRefusal;
      }
    }
    if (lastRefusal) throw lastRefusal;
    if (chainDirectory) throw new Error(`${brokerFailure} Directory: chain. No live approved guest was found on chain.`);
    require(wait && Date.now() + 2000 <= deadline,
      capacityMessage(!nodes.length, 2));
    $("capacity-status").dataset.stage = nodes.length ? "busy" : "empty";
    $("capacity-status").textContent = capacityMessage(!nodes.length, 2);
    await pause(2000);
  }
}
function measuredEnvironment() {
  if (!policy) return {};
  const manifest = JSON.parse(decode.decode(policy.manifest));
  const compose = JSON.parse(manifest.docker_compose_file);
  const service = compose.services.node;
  const env = service.environment || {};
  return {
    ...defaultAgentEnvironment,
    persistence: "This conversation's guest; released after five idle minutes or End session.",
    commandTimeoutSeconds: Number(env.AGENT_COMMAND_TIMEOUT_SECONDS || 120),
    outputCapBytes: Number(env.AGENT_OUTPUT_CAP_BYTES || 51200),
    allowlist: typeof env.AGENT_NETWORK_ALLOWLIST === "string" ? JSON.parse(env.AGENT_NETWORK_ALLOWLIST) : [],
  };
}
function renderGuest(status) {
  updateSandboxLabels();
  for (const view of chat?.querySelectorAll("tool-message") || []) view.requestUpdate();
  if (["held", "released"].includes(status.state)) void refreshNetwork();
  const held = ["held", "connecting", "reconnecting", "disconnected-held", "handover"].includes(status.state);
  $("end-session").disabled = !held;
  $("repo").disabled = held;
  $("repo").title = held ? "Stop the sandbox to attach different code" : "";
  $("guest-seconds").textContent = `${status.guestSeconds || 0} guest seconds`;
  $("guest-status").dataset.state = status.state;
  $("guest-status").title = status.error || "";
  $("guest-status").textContent = status.error ? replyFailure(Error(status.error)).message : ({
    idle: "Guest starts when the agent first uses a tool.",
    verifying: "Verifying an available guest…",
    connecting: "Connecting to the verified guest…",
    reconnecting: "Reconnecting to this conversation’s guest…",
    held: "Guest held for this conversation: " + status.node?.relay_peer,
    "disconnected-held": "Connection paused. The next tool call reconnects to this conversation’s guest.",
    handover: "Saving workspace and moving to the next guest…",
    sealing: "Saving workspace and releasing the guest…",
    released: status.closedReason === "credit" ? "Credit used up. Add credit to continue with your saved workspace."
      : status.closedReason === "idle" ? "Workspace saved. Guest released after five idle minutes."
      : "Guest released. The next tool call restores this conversation’s saved workspace.",
    ending: "Ending session; waiting for the guest’s signed final usage…",
    disconnected: "Guest stream closed.",
  }[status.state] || status.state);
  if (status.node) {
    $("node-evidence").textContent = JSON.stringify(status.node, null, 2);
    $("guest-attestation").hidden = false;
  }
  if (credit) renderChatCredit();
}
function renderWorkspace(status) {
  const messages = { saving: "Saving workspace…", "save-error": "Workspace save paused. Try Save workspace again.", restoring: "Restoring saved workspace…", opening: "Opening workspace…" };
  $("workspace-status").textContent = messages[status.state] || (status.head
    ? `Workspace version ${status.head.version} saved · Kept for 30 days after last use`
    : "Files will be saved with this conversation.");
  $("workspace-status").dataset.version = String(status.head?.version || 0);
  $("workspace-status").dataset.state = status.state || "ready";
}
function emptyRepository() {
  repoFiles = new Map();
  $("repository-status").textContent = "";
}
async function readRepository(file) {
  require(file?.size <= 16 * 1024 * 1024, "Repository exceeds the 16 MiB input limit.");
  let bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
    const chunks = []; let size = 0;
    for (;;) {
      const { value, done } = await reader.read(); if (done) break;
      size += value.length; require(size <= 16 * 1024 * 1024, "Expanded repository exceeds 16 MiB."); chunks.push(value);
    }
    bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  }
  const files = new Map(), text = new TextDecoder("utf-8", { fatal: true });
  const field = (header, from, to) => text.decode(header.subarray(from, to)).replace(/\0.*$/s, "").trim();
  for (let offset = 0; offset + 512 <= bytes.length;) {
    const header = bytes.subarray(offset, offset + 512); offset += 512;
    if (header.every(b => b === 0)) break;
    const prefix = field(header, 345, 500), name = [prefix, field(header, 0, 100)].filter(Boolean).join("/").replace(/^\.\//, "");
    const size = parseInt(field(header, 124, 136) || "0", 8), kind = header[156];
    require(Number.isSafeInteger(size) && size >= 0 && offset + size <= bytes.length, "Invalid repository archive entry.");
    require(name && !name.startsWith("/") && !name.split("/").some(p => p === ".." || p === ".git") && !name.includes("\\"), "Repository archive contains an unsafe path.");
    if (kind === 0 || kind === 48) files.set(name, text.decode(bytes.subarray(offset, offset + size)));
    else require(kind === 53, "Repository snapshots support regular UTF-8 files and directories.");
    offset += Math.ceil(size / 512) * 512;
  }
  require(files.size, "Repository archive has no files.");
  return files;
}

async function refund() {
  $("prepaid-status").textContent = await credit.closeAccount();
}
async function checkSync() {
  if (!sync) return;
  const checking = sync;
  try {
    await startupStep("sync-pull", () => checking.pull());
    // A recovered wallet may need to select its newest verified remote chat.
    const imported = await store("continuity.imported");
    if (!chatBusy && !sharedLink) {
      const remoteIds = new Set(Object.keys(checking.state?.sessions || {}));
      const all = await storage.sessions.getAllMetadata();
      const latest = all.filter(m => remoteIds.has(m.id)).sort((a, b) => b.lastModified.localeCompare(a.lastModified))[0];
      const id = (imported || !agent.state.messages.some(m => m.role === "user")) && latest ? latest.id : currentSession.id;
      const data = await storage.sessions.get(id);
      if (data && (id !== currentSession.id || JSON.stringify(data.messages) !== JSON.stringify(agent.state.messages) || JSON.stringify(data.feedback) !== JSON.stringify(currentSession.feedback))) await useSession(data);
      if (imported && latest) await store("continuity.imported", false);
    }
    await startupStep("sync-flush", () => checking.flush());
    $("chat-status").hidden = true;
  } catch (e) {
    syncFailure(e);
  }
}
async function main() {
  require(window.top === window.self, "Open the private agent in its own tab to use your wallet.");
  require(
    !/^\/(ipfs|ipns)\//.test(window.location.pathname),
    "Open this app through a CID or IPNS subdomain gateway. Shared path gateways cannot isolate your wallet from other sites.",
  );
  const response = await startupStep("configuration", () => fetch("./config.json", { cache: "no-store" }));
  require(response.ok, "Page configuration could not load.");
  cfg = await response.json();
  if (cfg.pageBundleRegistry) {
    const checkVersion = () => checkPageVersion({ ownCID: document.querySelector('meta[name="page-bundle-cid"]').content,
      config: cfg.pageBundleRegistry, banner: $("page-version") }).catch(e => {
        $("page-version").hidden = false;
        $("page-version").textContent = "Page version check failed: " + e.message;
      });
    void checkVersion();
    setInterval(checkVersion, 60000);
  }
  sharedLink = parseArtifactLink(window.location.href);
  for (const name of ["broker", "rpc"]) {
    require(/^https:\/\//.test(cfg[name]), `${name} must be an explicit HTTPS service address.`);
  }
  cfg.sandboxPolicy = { ...approvedSandboxPolicy, registry: cfg.registry, rpc: cfg.rpc };
  require(cfg.chainId === 84532, "This page is restricted to Base Sepolia.");
  keys = await startupStep("local-wallet", () => new DeviceKeys().init());
  $("wallet").textContent = keys.address || "Your wallet is created when you send your first message.";
  document.documentElement.dataset.walletLoaded = "true";
  let client = await startupStep("local-client", () => store("client"));
  if (!client) {
    client = await sandbox.createClient();
    await store("client", client);
  }
  credit = await startupStep("local-credit", () => new Credit(cfg, client, render).init());
  continuity = continuityUI({ keys, credit, cfg, api, error, beforeSwitch: async () => {
    require(!agent?.state.isStreaming, "Cancel the current reply before switching wallets.");
    await saveCurrentChat();
    if (guest?.lease) await guest.end();
    if (sync) await sync.flush();
  }, beforeExport: async () => {
    require(keys.bundle, "Start fresh or recover your wallet first.");
    if (sync) await sync.flush();
  } });
  render();
  await startupStep("local-chat", initChat);
  render();
  $("recover-device").disabled = false;
  $("open-add-credit").addEventListener("click", openAddCredit);
  action("copy-address", async () => {
    require(credit.address, "Create or connect a wallet first.");
    await navigator.clipboard.writeText(credit.address);
    $("copy-address").textContent = "Address copied";
  });
  action("balance", async () => {
    require(credit.address, "Create or connect a wallet first.");
    $("eth").textContent =
      formatEther(await credit.rpc.getBalance(credit.address)) +
      " Base Sepolia ETH";
  });
  action("deposit", async () => {
    await ensureWallet({ claim: false });
    try { await claimChatCredit(); }
    catch (e) { if (e.code !== "STARTER_BUDGET_EXHAUSTED") throw e; }
    const { minimumGranted } = await credit.deposit($("deposit-amount").value.trim());
    $("prepaid-status").textContent = "USDC deposited. Credit usually appears in about 15 minutes, once the network finishes confirming it. Checking in the background…";
    credit.waitForDeposit(minimumGranted, claimChatCredit).then(credited => {
      if (credited) $("prepaid-status").textContent = "USDC deposited. Credit is available.";
    }).catch(error);
  });
  action("refund", refund);
  action("verified", async () => { $("advanced").open = true; $("attestations").scrollIntoView({ block: "nearest" }); });
  action("end-session", () => guest.end());
  $("repo").onchange = async (event) => {
    try {
      repoFiles = await readRepository(event.target.files[0]);
      $("repository-status").textContent = `${repoFiles.size} files attached`;
    } catch (e) {
      emptyRepository();
      error(e);
    }
  };
  loadPolicy(cfg.sandboxPolicy);
  emptyRepository();
  document.documentElement.dataset.ready = "true";
  // Network verification follows local rendering and never gates the wallet.
  void refreshNetwork();
  refreshServices().catch(error);
  checkSync().catch(error);
}
main().catch((e) => {
  error(e);
  document.body.dataset.failed = "true";
});
