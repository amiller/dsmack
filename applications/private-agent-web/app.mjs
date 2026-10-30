import "@mariozechner/mini-lit/dist/MarkdownBlock.js";
import { renderToolProgress } from "./tool-renderers.mjs";
import { AgentInterface } from "@pi-components/components/AgentInterface.js";
import { SessionListDialog } from "@pi-components/dialogs/SessionListDialog.js";
import { PersistentStorageDialog } from "@pi-components/dialogs/PersistentStorageDialog.js";
import { Agent } from "@earendil-works/pi-agent-core";
import { createArtifacts, ARTIFACT_PROMPT } from "./artifacts.mjs";
import { createChatStorage, saveChat } from "./chat-storage.mjs";
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
import { brokerStream, PRIVACY } from "./inference.mjs";
import * as sandbox from "@sandbox";
import approvedSandboxPolicy from "./sandbox-policy.json";
import { GuestSession, createGuestPeer } from "./agent-tools.mjs";
import { discoverChainNodes } from "./chain-directory.mjs";
import { fetchDirectAttestation } from "./direct-attestation.mjs";
import { piToolCatalog, defaultAgentEnvironment, buildAgentPrompt } from "./pi-prompt.mjs";
const $ = (id) => document.getElementById(id),
  decode = new TextDecoder(),
  guests = new Map();
let keys, sync, continuity, cfg,
  credit,
  quote,
  policy,
  node,
  repoFiles,
  guest,
  agent,
  chat,
  storage,
  currentSession,
  unsubscribeChat,
  lastSave = Promise.resolve(),
  chatBusy = false;
async function startupStep(name, task) {
  const start = performance.now();
  try { return await task(); }
  finally { performance.measure("startup:" + name, { start, end: performance.now() }); }
}
function error(e) {
  $("alert").textContent = e.message || String(e);
  $("alert").hidden = false;
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
  return opts.stream ? response : response.json();
}
function render() {
  $("wallet").textContent = credit.address || "Choose Start fresh or recover your wallet.";
  document.documentElement.dataset.walletLoaded = "true";
  continuity?.update({ hasValue: BigInt(credit.chatCredit?.remainingNanoUsd || "0") > 0n || currentSession?.messages?.some(m => m.role === "user") || agent?.state.messages.some(m => m.role === "user") }).catch(error);
  $("wallet-tools").hidden = !credit.address;
  const list = $("purchases");
  list.replaceChildren();
  if (!credit.purchases.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No purchases yet.";
    list.append(p);
  }
  for (const p of credit.purchases.filter((p) => p.unit === 1)) {
    const div = document.createElement("div");
    div.className = "purchase";
    const title = document.createElement("strong");
    title.textContent = `${
      p.status === "confirmed" ? "Confirmed" : "Pending"
    } · ${p.amount} seconds`;
    const label = document.createElement("p");
    label.className = "small";
    label.textContent = `${
      p.closed
        ? "Closed"
        : p.uncertain
        ? "Usage unresolved"
        : `${BigInt(p.amount) - BigInt(p.used || 0)} remaining`
    } · ${p.paidWei} wei`;
    const link = document.createElement("a");
    link.href = "https://sepolia.basescan.org/tx/" + p.txHash;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "View purchase on Basescan ↗";
    link.className = "small";
    div.append(title, label, link);
    for (
      const [key, label] of [["settlementHash", "Settlement"], [
        "refundHash",
        "Refund",
      ]]
    ) {
      if (p[key]) {
        const a = link.cloneNode();
        a.href = "https://sepolia.basescan.org/tx/" + p[key];
        a.textContent = " · " + label + " ↗";
        div.append(a);
      }
    }
    list.append(div);
  }
  renderChatCredit();
}
function renderChatCredit() {
  const c = credit.chatCredit;
  $("chat-credit").dataset.remainingNanoUsd = c?.remainingNanoUsd || "";
  $("chat-credit").dataset.spentNanoUsd = c?.spentNanoUsd || "";
  $("chat-credit").textContent = c
    ? "Chat credit " + formatNanoUsd(c.remainingNanoUsd)
    : credit.address ? "Chat credit · Checking balance…" : "Chat credit · Choose how to begin";
  $("chat-credit-status").textContent = c
    ? `${c.usedTokens} tokens · ${c.spentNanoUsd} nano-USD charged${
      c.pendingInferenceId ? " · Usage pending" : ""
    }`
    : credit.address ? "Your wallet is loaded. Checking your current credit…" : "Receive $0.250000 credit for model tokens and guest seconds. No testnet ETH needed.";
}
async function claimChatCredit() {
  require(
    quote?.configured,
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
  if (guest) await guest.restore();
}
async function ensureWallet() {
  require(credit.signer, "Choose Start fresh or recover your wallet before chatting.");
  if (!credit.chatCredit) await claimChatCredit();
}
async function refreshServices() {
  $("service").textContent = "Checking the broker…";
  await startupStep("broker-identity", () => credit.checkBroker(api));
  quote = await startupStep("inference-quote", () => api("/inference/quote"));
  require(
    quote.mode === "broker-e2ee" && quote.provider === "near" &&
      typeof quote.model === "string",
    "Broker does not offer browser-encrypted NEAR chat.",
  );
  setModel();
  $("service").textContent = quote.configured
    ? "Chat ready · " + PRIVACY
    : "Private inference is not configured.";
  if (credit.signer && quote.configured) await startupStep("wallet-credit", claimChatCredit);
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
        "Provider usage pending · Checking the reported charge…";
      if (attempt === 29) {
        throw new Error(
          "USAGE_PENDING: Provider cost is still pending. Use Reconcile provider usage before another message.",
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}
function renderEvidence(e) {
  const item = document.createElement("div");
  item.className = "evidence-item";
  const p = document.createElement("p");
  p.className = "badge";
  p.textContent = `Answer ${
    $("attestations").querySelectorAll(".evidence-item").length + 1
  } · Broker verified quote · Browser checked nonce and encryption key`;
  item.append(p);
  details(item, "Model, nonce, signing addresses & TLS evidence", e);
  $("attestations").append(item);
}
function setModel() {
  if (!agent) return;
  agent.state.model = (!quote && currentSession?.model) || {
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
  $("model").textContent = agent.state.model.id === "unavailable"
    ? "NEAR TEE model · unavailable" : agent.state.model.id;
  chat?.requestUpdate();
}
async function saveCurrentChat(publish = false) {
  const session = currentSession;
  chat.dataset.saved = "false";
  $("chat-status").textContent = "Saving chat…";
  const task = saveChat(storage, session, agent);
  lastSave = task;
  try {
    const data = await task;
    if (currentSession === session) {
      $("session-title").textContent = data.title;
      $("chat-status").textContent = "Saved on this device";
      chat.dataset.saved = "true";
      continuity?.update({ hasValue: data.messages.some(m => m.role === "user") || BigInt(credit.chatCredit?.remainingNanoUsd || "0") > 0n }).catch(error);
    }
    if (publish && sync) {
      try {
        chat.dataset.synced = "false";
        await sync.push(data.id);
        if (currentSession === session) {
          chat.dataset.synced = "true";
          $("chat-status").textContent = "Encrypted and synced";
        }
      } catch (e) {
        $("chat-status").textContent = "Saved on this device · Sync pending: " + e.message;
        if ($("alert").hidden) error(e);
      }
    }
  } catch (e) {
    $("chat-status").textContent = "Chat could not be saved";
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
  $("new-chat").disabled = busy;
  $("sessions").disabled = busy;
}
async function renderPersistence() {
  const persisted = await navigator.storage?.persisted?.();
  $("storage-status").textContent = persisted
    ? "Persistent storage enabled" : "Standard browser storage";
}
async function useSession(data) {
  if (agent) await agent.waitForIdle();
  await lastSave;
  unsubscribeChat?.();
  currentSession = data || {
    id: crypto.randomUUID(), title: "New chat", createdAt: new Date().toISOString(),
    messages: [], dsmack: { evidence: [], wallet: credit.address?.toLowerCase() },
  };
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
        const saved = lastSave.catch(() => {}).then(() => saveChat(storage, record.session, record.agent));
        lastSave = saved;
        await saved;
        require(sync, "Unlock chat sync before saving your workspace.");
        await sync.push(conversationId);
      },
      changed: status => {
        const held = guests.get(conversationId);
        if (held) held.workspaceStatus = status;
        if (currentSession.id === conversationId) renderWorkspace(status);
      },
    });
    guest = new GuestSession({
      api, cfg, credit, conversationId, discover, workspace, savedLease: currentSession.dsmack.guest,
      changed: (status) => {
        const held = guests.get(conversationId);
        if (held) {
          held.statusSnapshot = status;
          if (status.lease && held.record && (status.active !== undefined || ["connecting", "released", "held", "disconnected-held"].includes(status.state))) {
            const record = held.record;
            record.session.dsmack.guest = {
              sessionId: status.lease.sessionId, conversationId,
              wallet: credit.address.toLowerCase(), active: status.active ?? !["released"].includes(status.state),
              node: status.node || held.node?.registration,
              environment: status.environment || held.environment,
              guestSeconds: status.guestSeconds || 0,
            };
            lastSave = lastSave.catch(() => {}).then(() => saveChat(storage, record.session, record.agent));
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
  const artifacts = createArtifacts();
  const artifactHost = $("artifacts-host");
  artifactHost.replaceChildren(artifacts.panel);
  artifactHost.hidden = true;
  const openArtifacts = () => { artifactHost.hidden = false; artifacts.panel.collapsed = false; };
  artifacts.panel.onOpen = openArtifacts;
  artifacts.panel.onClose = () => { artifactHost.hidden = true; };
  artifacts.panel.onArtifactsChange = () => { $("open-artifacts").hidden = !artifacts.panel.artifacts.size; };
  $("open-artifacts").onclick = openArtifacts;
  agent = new Agent({
    initialState: {
      systemPrompt: "You are the dsmack private agent. Use your tools to inspect and change the attested workspace.",
      messages: currentSession.messages,
      thinkingLevel: "off",
      tools: [...guest.tools(), artifacts.tool],
    },
    toolExecution: "sequential",
    getApiKey: () => undefined,
    streamFn: brokerStream({
      credit, api, cfg, quote: () => quote, evidence: addEvidence, usage, error,
      startedAt: currentSession.createdAt,
      systemPrompt: ({ checked, runtime }) => buildAgentPrompt({
        runtime: { preamble: "You are Dsmack Agent, a coding assistant in the Dsmack private agent page. Use the provided tools to inspect and change the attested Mac-hosted Linux workspace. Model calls remain encrypted from the browser to the NEAR model TEE.\n\n" + runtime + "\n\nThe application supplies these runtime facts. Your self-report is not proof; refer to the verified attestation shown by the page." },
        environment: guest.environment || measuredEnvironment(),
        attestation: guest.node ? { verification: "Browser verified Apple enrollment, build, measured compose and bound Noise peer", guestPeer: guest.node.registration.relay_peer, manifestHash: guest.node.registration.manifest_sha256, imageHash: guest.node.registration.os_image_hash, cdhash: guest.node.registration.cdhash } : { status: "Guest attestation will be verified before the first tool call.", cdhash: policy.cdhash },
        repository: "Initial repository snapshot; use the read tool for current workspace contents.\n" + [...repoFiles].map(([name, text]) => `${name}\n${text.length < 4096 ? text : "Read this file with the read tool."}`).join("\n"),
      }) + "\n\n" + ARTIFACT_PROMPT,
    }),
  });
  artifacts.panel.agent = agent;
  await artifacts.panel.reconstructFromMessages(currentSession.messages.filter((message) =>
    message.role !== "artifact" || /\.html$/i.test(message.filename || "")));
  $("open-artifacts").hidden = !artifacts.panel.artifacts.size;
  guest.record = { session: currentSession, agent };
  if (credit.signer) {
    try { await guest.restore(); }
    catch (e) { renderGuest({ state: guest.lease ? "disconnected-held" : "error", error: e.message }); }
  }
  setModel();
  $("attestations").replaceChildren();
  for (const e of currentSession.dsmack.evidence) renderEvidence(e);
  chat.session = agent;
  chat.dataset.sessionId = currentSession.id;
  if (!chat.isConnected) $("chat-host").append(chat);
  await chat.updateComplete;
  unsubscribeChat = agent.subscribe((event) => {
    renderToolProgress(chat, agent, event);
    // Pi's message list observes array references; the agent appends in place.
    if (event.type === "message_end") {
      agent.state.messages = [...agent.state.messages];
      chat.requestUpdate();
    }
    if (event.type === "message_end" || event.type === "agent_end") return saveCurrentChat(event.type === "agent_end");
  });
  await saveCurrentChat();
  await storage.settings.set("chat.active", currentSession.id);
}
async function initChat() {
  storage = createChatStorage();
  if (keys.bundle) sync = new ChatSync({ cfg, credit, keys: keys.bundle, storage, api });
  chat = new AgentInterface();
  chat.id = "chat";
  chat.enableAttachments = false;
  chat.enableModelSelector = false;
  chat.enableThinkingSelector = false;
  // The broker authenticates the wallet and holds the provider key in its CVM.
  chat.onApiKeyRequired = async () => true;
  chat.onBeforeSend = async () => {
    clearError();
    await credit.checkBroker(api);
    require(quote?.configured, "Private inference is not configured on this broker.");
    await ensureWallet();
    require(!credit.chatCredit.pendingInferenceId,
      "Usage is unresolved. Reconcile provider usage before sending another message.");
    require(BigInt(credit.chatCredit.remainingNanoUsd) > 0n,
      "CREDIT_EXHAUSTED: Chat credit used up.");
    if (!await storage.settings.get("chat.persistenceRequested")) {
      await storage.requestPersistence();
      await storage.settings.set("chat.persistenceRequested", true);
      await renderPersistence();
    }
  };
  const sendMessage = chat.sendMessage.bind(chat);
  chat.sendMessage = async (...args) => {
    if (chatBusy) return;
    setChatBusy(true);
    try { await sendMessage(...args); } catch (e) { error(e); }
    finally {
      setChatBusy(false);
      // The agent becomes idle after its final event listeners have settled.
      chat.requestUpdate();
    }
  };
  chat.onCostClick = () => usage().catch(error);
  const active = await storage.settings.get("chat.active") || await storage.sessions.getLatestSessionId();
  const saved = active ? await storage.sessions.get(active) : null;
  const sameWallet = credit.address && (!saved?.dsmack?.wallet || saved.dsmack.wallet === credit.address.toLowerCase());
  await useSession(sameWallet ? saved : null);
  await renderPersistence();
  action("new-chat", () => useSession());
  action("sessions", () => SessionListDialog.open(
    (id) => (async () => {
      const data = await storage.sessions.get(id);
      require(data, "This saved chat has been deleted.");
      await useSession(data);
    })().catch(error),
    (id) => { if (id === currentSession.id) useSession().catch(error); },
  ));
  action("save-storage", async () => {
    await PersistentStorageDialog.request();
    await renderPersistence();
  });
}

function loadPolicy(raw) {
  require(
    raw && typeof raw.manifest === "string" && raw.enrollment,
    "Sandbox policy needs exact manifest and Apple enrollment bytes.",
  );
  const p = {
    ...raw,
    manifest: sandbox.unhex(raw.manifest),
    enrollment: {
      attestation: sandbox.unhex(raw.enrollment.attestation),
      keyId: raw.enrollment.keyId,
      clientData: sandbox.unhex(raw.enrollment.clientData),
    },
  };
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
  label.textContent = `Directory: ${path}` + (brokerFailure ? ` · ${brokerFailure}` : "") +
    (chainFailure ? ` · Chain directory failed: ${chainFailure}` : "");
}
function directoryFailure(e) {
  return "Broker guest directory unavailable" + (e.status ? ` (HTTP ${e.status})` : "") +
    (e.message && !e.message.startsWith("Broker /nodes") ? `: ${e.message}` : ".");
}
async function discover({ peer: browserPeer, wait = false, deadline = Date.now() + (wait ? 90000 : 0), exclude = new Set(), signal, workspace, claim } = {}) {
  require(policy, "The bundled sandbox policy could not load. Refresh the page before sending a job.");
  const manifestHash = sandbox.hex(new Uint8Array(await crypto.subtle.digest("SHA-256", policy.manifest)));
  const query = workspace ? "?" + new URLSearchParams({ workspaceId: workspace.workspaceId,
    version: String(workspace.version), hash: workspace.hash }) : "";
  let lastRefusal, chainDirectory, brokerFailure;
  const mark = (stage, detail) => performance.mark("dsmack:" + stage, { detail });
  const pause = milliseconds => new Promise((resolve, reject) => {
    const aborted = () => { clearTimeout(timer); reject(signal.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", aborted); resolve(); }, milliseconds);
    if (signal?.aborted) aborted();
    else signal?.addEventListener("abort", aborted, { once: true });
  });
  for (;;) {
    signal?.throwIfAborted();
    mark("discovery:start");
    let nodes;
    try {
      nodes = await api("/nodes" + query, undefined, { signal });
      await credit.checkBroker(api);
      showDirectory("broker");
    } catch (e) {
      mark("discovery:end", { error: e.code || e.message });
      if (signal?.aborted) throw e;
      if (e.code === "FLEET_BUSY") {
        const retry = Math.max(1, Math.min(60, Number(e.retryAfterSeconds) || 15));
        showDirectory("broker");
        $("node-status").textContent = `Busy, retry in ${retry} seconds.`;
        if (!wait || Date.now() + retry * 1000 > deadline) throw e;
        await pause(retry * 1000);
        continue;
      }
      brokerFailure = directoryFailure(e);
      showDirectory("chain", brokerFailure);
      try {
        chainDirectory = await discoverChainNodes({ config: cfg, signal });
        nodes = chainDirectory.nodes;
      } catch (chainError) {
        showDirectory("chain", brokerFailure, chainError.message);
        throw new Error(`${brokerFailure} Directory: chain. Chain directory failed: ${chainError.message}`);
      }
    }
    mark("discovery:end", { candidates: nodes.length });
    // Keep the broker's order. Placement hints never replace these local pins.
    const candidates = nodes.filter(entry => entry.kind === "compute" &&
      entry.available !== false && !exclude.has(entry.relay_peer) &&
      (chainDirectory || (entry.manifest_sha256 === manifestHash && entry.cdhash === policy.cdhash &&
      Number(entry.admit_until) * 1000 >= Date.now() + 30000)));
    for (const selected of candidates) {
      signal?.throwIfAborted();
      $("node-status").textContent = "Checking the sandbox's Apple attestation, approved build and bound keys…";
      const challenge = sandbox.hex(crypto.getRandomValues(new Uint8Array(32)));
      const peer = selected.relay_peer;
      let release;
      if (claim) {
        try { release = await claim(selected); }
        catch (e) {
          if (!["GUEST_BUSY", "NODE_NOT_LIVE"].includes(e.code)) {
            const path = chainDirectory ? `${brokerFailure} Directory: chain.` : "Directory: broker.";
            throw new Error(`${path} The broker could not reserve the discovered guest` +
              (e.status ? ` (HTTP ${e.status}).` : `: ${e.message}`));
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
          mark("attestation:direct", { peer, challenge });
          direct = await fetchDirectAttestation({ peer: browserPeer, selected, challenge, policy, signal });
        }
        const registration = direct ? direct.registration : await api("/sandbox/nodes/" + encodeURIComponent(peer) +
          "/attestation?challenge=" + challenge, undefined, { signal });
        mark("attestation:response", { peer });
        require(registration.relay_peer === peer, "Guest attestation identifies a different peer.");
        if (chainDirectory) await chainDirectory.verifyRegistration(registration);
        const checked = await sandbox.verifyNode(registration, { ...policy, challenge });
        require(!registration.payments || registration.payments.challenge === challenge,
          "Node challenge mismatch. Stale attestation refused.");
        require(Number(registration.admit_until) * 1000 >= Date.now() + 30000 &&
          (!registration.payments || registration.payments.runExpires * 1000 >= Date.now() + 30000),
          "Guest is too close to drain. Trying another approved guest.");
        mark("attestation:verified", { peer });
        // The attestation endpoint omits scheduler hints; retain them for sealed
        // workspace placement without treating them as verified evidence.
        checked.placement = selected.scheduler;
        if (direct) {
          checked.chainTunnels = direct.entries;
          checked.connection = direct.connection;
          checked.directory = "chain";
        }
        node = checked;
        $("node-status").textContent = "Node verified · Apple enrollment (" +
          (checked.enrollmentMode || checked.policy.enrollmentMode || "on-chain") +
          "), approved build, compose, image, broker and bound keys";
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
      "No approved guest is available right now. Please try again shortly.");
    $("node-status").textContent = "Waiting for an approved guest; retry in 2 seconds…";
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
  const held = ["held", "connecting", "disconnected-held"].includes(status.state);
  $("end-session").disabled = !held;
  $("download").disabled = status.state !== "held";
  $("save-workspace").disabled = status.state !== "held";
  $("repo").disabled = held;
  $("sample").disabled = held;
  $("guest-seconds").textContent = `${status.guestSeconds || 0} guest seconds`;
  $("guest-status").dataset.state = status.state;
  $("guest-status").textContent = status.error || ({
    idle: "Guest starts when the agent first uses a tool.",
    verifying: "Verifying an available guest…",
    connecting: "Connecting to the verified guest…",
    held: "Guest held for this conversation: " + status.node?.relay_peer,
    "disconnected-held": "This conversation holds a disconnected guest. End the guest stay to resume its saved workspace.",
    released: status.usageUnresolved ? "Guest disconnected. Final metering receipt is unresolved." : "Guest released. The next tool call restores this conversation’s saved workspace.",
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
  const messages = { saving: "Saving workspace…", restoring: "Restoring saved workspace…", opening: "Opening workspace…" };
  $("workspace-status").textContent = messages[status.state] || (status.head
    ? `Workspace version ${status.head.version} saved · Kept for 30 days after last use`
    : "Files will be saved with this conversation.");
  $("workspace-status").dataset.version = String(status.head?.version || 0);
  $("workspace-status").dataset.state = status.state || "ready";
}
function resetSample() {
  repoFiles = new Map([["greet.txt", "Hello world.\n"]]);
  $("repository-status").textContent = "Included repository: greet.txt. Ask for changes in chat, then download the workspace patch.";
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
  require(credit.address, "Connect the original purchase wallet.");
  const p = credit.purchases.find((p) =>
    p.unit === 1 && !p.closed && p.purchaseId &&
    p.payer?.toLowerCase() === credit.address.toLowerCase()
  );
  if (!p) {
    const hash = await credit.withdraw();
    $("service").textContent = "Refund withdrawn: " + hash;
    return;
  }
  const c = await credit.contract();
  const chainPurchase = await c.getPurchase(p.purchaseId);
  if (chainPurchase.closed) {
    p.closed = true;
    await credit.save();
  } else if (
    Math.floor(Date.now() / 1000) >= Number(chainPurchase.expires) + 3600
  ) {
    const tx = await c.refund(p.purchaseId);
    p.refundHash = tx.hash;
    await credit.save();
    await tx.wait();
    p.closed = true;
    await credit.save();
  } else if (p.receipt) await credit.settle(p.receipt, p);
  else {throw new Error(
      "Unused credit can be refunded after the escrow settlement grace period, or immediately after verified final usage.",
    );}
  const hash = await credit.withdraw();
  p.refundHash = hash;
  await credit.save();
  $("service").textContent =
    "Unused testnet credit withdrawn. View the refund in your purchase card.";
}
async function checkSync() {
  if (!sync) { $("sync-status").textContent = "Choose how to begin. Chats save on this device."; return; }
  const checking = sync;
  $("sync-status").textContent = "Checking sync… Your saved chats are ready on this device.";
  try {
    await startupStep("sync-pull", () => checking.pull());
    // A recovered wallet may need to select its newest verified remote chat.
    const imported = await store("continuity.imported");
    if (!chatBusy) {
      const remoteIds = new Set(Object.keys(checking.state?.sessions || {}));
      const all = await storage.sessions.getAllMetadata();
      const latest = all.filter(m => remoteIds.has(m.id)).sort((a, b) => b.lastModified.localeCompare(a.lastModified))[0];
      const id = (imported || !agent.state.messages.some(m => m.role === "user")) && latest ? latest.id : currentSession.id;
      const data = await storage.sessions.get(id);
      if (data && (id !== currentSession.id || JSON.stringify(data.messages) !== JSON.stringify(agent.state.messages))) await useSession(data);
      if (imported && latest) await store("continuity.imported", false);
    }
    await startupStep("sync-flush", () => checking.flush());
    $("sync-status").textContent = "Chats checked and synced.";
  } catch (e) {
    $("sync-status").textContent = "Chats are saved here. Sync couldn’t finish; check your connection and try again.";
    $("sync-status").title = e.message;
  }
}
async function main() {
  require(
    !/^\/(ipfs|ipns)\//.test(window.location.pathname),
    "Open this app through a CID or IPNS subdomain gateway. Shared path gateways cannot isolate your wallet from other sites.",
  );
  const response = await startupStep("configuration", () => fetch("./config.json", { cache: "no-store" }));
  require(response.ok, "Page configuration could not load.");
  cfg = await response.json();
  for (const name of ["broker", "rpc"]) {
    require(/^https:\/\//.test(cfg[name]), `${name} must be an explicit HTTPS service address.`);
  }
  cfg.sandboxPolicy = { ...approvedSandboxPolicy, registry: cfg.registry, rpc: cfg.rpc };
  require(cfg.chainId === 84532, "This page is restricted to Base Sepolia.");
  keys = await startupStep("local-wallet", () => new DeviceKeys().init());
  $("wallet").textContent = keys.address || "Choose Start fresh or recover your wallet.";
  document.documentElement.dataset.walletLoaded = "true";
  let client = await startupStep("local-client", () => store("client"));
  if (!client) {
    client = await sandbox.createClient();
    await store("client", client);
  }
  credit = await startupStep("local-credit", () => new Credit(cfg, client, render).init());
  continuity = continuityUI({ keys, credit, cfg, api, error, beforeExport: async () => {
    require(sync, "Start fresh or recover your wallet first.");
    await sync.flush();
  } });
  render();
  await startupStep("local-chat", initChat);
  render();
  action("start-fresh", async () => {
    await keys.create();
    await credit.init();
    currentSession.dsmack.wallet = credit.address.toLowerCase();
    sync = new ChatSync({ cfg, credit, keys: keys.bundle, storage, api });
    render();
    $("welcome").hidden = true;
    $("service").textContent = "Your wallet is ready. Checking your credit…";
    refreshServices().catch(error);
    checkSync().catch(error);
  });
  $("start-fresh").disabled = false;
  $("used-before").disabled = false;
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
  action("refresh", async () => {
    for (const p of credit.purchases.filter((p) => p.status === "pending")) {
      await credit.confirm(api, p);
    }
  });
  action("reconcile", () => usage());
  action("refund", refund);
  action("discover", async () => {
    const peer = await createGuestPeer();
    try { await discover({ peer }); }
    finally { await peer.stop(); }
  });
  action("end-session", () => guest.end());
  action("save-workspace", () => guest.save());
  action("sample", resetSample);
  action("download", async () => {
    const patch = await guest.patch();
    const url = URL.createObjectURL(new Blob([patch], { type: "text/x-diff" })),
      a = document.createElement("a");
    a.href = url;
    a.download = "private-agent.patch";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $("policy").onchange = async (event) => {
    try {
      loadPolicy(JSON.parse(await event.target.files[0].text()));
    } catch (e) {
      policy = undefined;
      node = undefined;
      error(e);
    }
  };
  $("repo").onchange = async (event) => {
    try {
      repoFiles = await readRepository(event.target.files[0]);
      $("repository-status").textContent = `${repoFiles.size} repository files selected. Ask for a change in chat.`;
    } catch (e) {
      resetSample();
      error(e);
    }
  };
  loadPolicy(cfg.sandboxPolicy);
  resetSample();
  document.documentElement.dataset.ready = "true";
  // Network verification follows local rendering and never gates the wallet.
  refreshServices().catch(error);
  checkSync().catch(error);
}
main().catch((e) => {
  error(e);
  document.body.dataset.failed = "true";
});
