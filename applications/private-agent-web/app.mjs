import "@mariozechner/mini-lit/dist/MarkdownBlock.js";
import "@pi-components/components/MessageList.js";
import "@pi-components/components/Messages.js";
import "@pi-components/components/MessageEditor.js";
import "@pi-components/components/StreamingMessageContainer.js";
import { Agent } from "@mariozechner/pi-agent-core";
import {
  Credit,
  formatEther,
  formatNanoUsd,
  require,
  signed,
  store,
  walletBody,
} from "./credit.mjs";
import { brokerStream, PRIVACY } from "./inference.mjs";
import * as sandbox from "@sandbox";
import approvedSandboxPolicy from "./sandbox-policy.json";
import { applyVerifiedPatch } from "./patch.mjs";
const $ = (id) => document.getElementById(id),
  decode = new TextDecoder(),
  encode = new TextEncoder();
let cfg,
  credit,
  quote,
  policy,
  node,
  verifiedAt,
  repoTar,
  repoFiles,
  patch,
  agent,
  starterSandboxUsed = false,
  starterSandboxStatus = "available";
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
      $(id).disabled = false;
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
    const friendly = code === "starter_sandbox_used"
      ? "Your starter sandbox allowance has already been used by this wallet. Additional starter time is not available for this trial."
      : code === "diagnostic_node_not_live"
      ? "The selected sandbox retired before your job was reserved. No repository or task was sent."
      : undefined;
    const message = friendly || (typeof e === "object"
      ? [e?.code, e?.message].filter(Boolean).join(": ")
      : e) ||
      `Broker ${path}: HTTP ${response.status}`;
    throw Object.assign(new Error(message), { code, status: response.status });
  }
  return opts.stream ? response : response.json();
}
function render() {
  $("wallet").textContent = credit.address || "No wallet connected";
  $("burner").disabled = !!credit.address;
  $("connect").disabled = !!credit.address;
  $("wallet-tools").hidden = !credit.address;
  $("sandbox-credit").dataset.remainingJobs = starterSandboxUsed ? "0" : "1";
  $("sandbox-credit").dataset.status = starterSandboxStatus;
  $("sandbox-credit").textContent = {
    available:
      "Your first sandbox job includes up to 180 seconds. No testnet ETH needed.",
    running: "Your starter sandbox job is running…",
    completed: "Starter sandbox completed. Your verified result is ready.",
    stopped:
      "Your starter sandbox job stopped. The error explains what failed.",
    used: "Your starter sandbox allowance has been used.",
  }[starterSandboxStatus];
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
    : "Chat credit · Create or connect a wallet";
  $("chat-credit-status").textContent = c
    ? `${c.usedTokens} tokens · ${c.spentNanoUsd} nano-USD charged${
      c.pendingInferenceId ? " · Usage pending" : ""
    }`
    : "Receive $0.250000 chat credit and a first sandbox job. No testnet ETH needed.";
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
  const starter = await store(
    "sandbox-starter:" + credit.address.toLowerCase(),
  );
  starterSandboxUsed = !!starter;
  starterSandboxStatus = starter?.status || (starter ? "used" : "available");
  render();
}
async function setStarterSandboxStatus(status) {
  starterSandboxStatus = status;
  starterSandboxUsed = status !== "available";
  await store("sandbox-starter:" + credit.address.toLowerCase(), { status });
  render();
}
async function ensureWallet() {
  if (!credit.signer) await credit.burner();
  if (!credit.chatCredit) await claimChatCredit();
}
async function refreshServices() {
  await credit.checkBroker(api);
  quote = await api("/inference/quote");
  require(
    quote.mode === "broker-e2ee" && quote.provider === "near" &&
      typeof quote.model === "string",
    "Broker does not offer browser-encrypted NEAR chat.",
  );
  setModel();
  $("service").textContent = quote.configured
    ? "Chat ready · " + PRIVACY
    : "Private inference is not configured.";
  if (credit.signer && quote.configured) await claimChatCredit();
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
        `Provider: ${result.usedTokens} tokens · ${result.spentNanoUsd} nano-USD charged · ${
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
function addEvidence(e) {
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
  agent.state.model = {
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
  $("model").textContent = quote?.model || "NEAR TEE model · unavailable";
  const editor = document.querySelector("message-editor");
  editor.currentModel = agent.state.model;
}
function initChat() {
  const list = document.querySelector("message-list"),
    stream = document.querySelector("streaming-message-container"),
    editor = document.querySelector("message-editor");
  agent = new Agent({
    initialState: {
      systemPrompt:
        'You cannot know which model you are or where you run. Do not guess or state it. If asked, say so and point to the page\'s "Answer evidence" panel, which shows the verified model attestation. In this chat you have no tools: you cannot run commands, browse, or see network details such as IP addresses. Say so plainly instead of guessing. You are a helpful coding assistant.',
      tools: [],
    },
    getApiKey: () => undefined,
    streamFn: brokerStream({
      credit,
      api,
      cfg,
      quote: () => quote,
      evidence: addEvidence,
      usage,
      error,
    }),
  });
  setModel();
  editor.showAttachmentButton = false;
  editor.showModelSelector = false;
  editor.showThinkingSelector = false;
  editor.thinkingLevel = "off";
  editor.onSend = async (text) => {
    clearError();
    try {
      await credit.checkBroker(api);
      require(
        quote?.configured,
        "Private inference is not configured on this broker.",
      );
      await ensureWallet();
      require(
        !credit.chatCredit.pendingInferenceId,
        "Usage is unresolved. Reconcile provider usage before sending another message.",
      );
      require(
        BigInt(credit.chatCredit.remainingNanoUsd) > 0n,
        "CREDIT_EXHAUSTED: Chat credit used up.",
      );
      await agent.prompt(text);
      if (agent.state.errorMessage) error(new Error(agent.state.errorMessage));
    } catch (e) {
      error(e);
    }
  };
  editor.onAbort = () => agent.abort();
  agent.subscribe((event) => {
    const running = event.type !== "agent_end" && agent.state.isStreaming;
    editor.isStreaming = running;
    list.messages = agent.state.messages;
    list.tools = [];
    list.pendingToolCalls = new Set();
    list.isStreaming = running;
    stream.isStreaming = running;
    stream.hidden = !running;
    $("chat-empty").hidden = agent.state.messages.length > 0;
    if (event.type === "message_start" && event.message.role === "user") {
      const sent = event.message.content.filter((part) => part.type === "text")
        .map((part) => part.text).join("");
      // MessageEditor.value is its public reactive composer API. Preserve a
      // newer draft if it changed while wallet/credit checks were pending.
      if (editor.value === sent) editor.value = "";
    }
    if (event.type === "message_update") stream.setMessage(event.message);
    if (event.type === "message_end" || event.type === "agent_end") {
      stream.setMessage(null, true);
    }
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
    "Approved sandbox policy included. A node will be verified when you run.";
}
async function discover({ wait = false } = {}) {
  await credit.checkBroker(api);
  require(
    policy,
    "The bundled sandbox policy could not load. Refresh the page before sending a job.",
  );
  const manifestHash = sandbox.hex(
    new Uint8Array(await crypto.subtle.digest("SHA-256", policy.manifest)),
  );
  const deadline = Date.now() + (wait ? 90000 : 0);
  let selected;
  do {
    const nodes = await api("/nodes");
    selected = nodes.filter((entry) =>
      entry.kind === "compute" &&
      entry.manifest_sha256 === manifestHash &&
      entry.cdhash === policy.cdhash &&
      Number(entry.admit_until) * 1000 >= Date.now() + 30000
    )
      .sort((a, b) => b.admit_until - a.admit_until)[0];
    if (selected || Date.now() >= deadline) break;
    $("job-status").textContent =
      "Waiting for an approved sandbox to warm up. Your starter job has not been used…";
    await new Promise((resolve) => setTimeout(resolve, 2000));
  } while (true);
  require(
    selected,
    "No approved sandbox is available right now. Your starter job has not been used. Please try again shortly.",
  );
  $("node-status").textContent =
    "Checking the sandbox's Apple attestation, approved build and bound keys…";
  const challenge = sandbox.hex(crypto.getRandomValues(new Uint8Array(32)));
  const registration = await api(
    "/sandbox/nodes/" + encodeURIComponent(selected.relay_peer) +
      "/attestation?challenge=" + challenge,
  );
  const resolved = { ...policy, challenge };
  let checked;
  try {
    checked = await sandbox.verifyNode(registration, resolved);
  } catch (e) {
    throw new Error(
      "Node attestation refused: " + e.message +
        ". No repository or task was sent.",
    );
  }
  require(
    !registration.payments || registration.payments.challenge === challenge,
    "Node challenge mismatch. Stale attestation refused.",
  );
  node = checked;
  verifiedAt = Date.now();
  $("node-status").textContent = "Node verified · Apple enrollment (" +
    (checked.enrollmentMode || checked.policy.enrollmentMode || "on-chain") +
    "), approved build, compose, image, broker and bound keys";
  $("node-evidence").textContent = JSON.stringify(registration, null, 2);
}
async function run() {
  await ensureWallet();
  await credit.checkBroker(api);
  require(repoTar, "Choose a repository or reset the included sample.");
  require(
    $("job-prompt").value.trim(),
    "Describe the change you want the sandbox to make.",
  );
  $("job-status").textContent = "Finding and verifying an approved sandbox…";
  if (!node || Date.now() - verifiedAt >= 30000) await discover({ wait: true });
  require(
    node.policy.provider?.schema === "dsmack-broker-model/1",
    "The approved sandbox must use broker-verified TEE inference.",
  );
  const p = credit.forSpend(1);
  const jobId = sandbox.hex(crypto.getRandomValues(new Uint8Array(16)));
  let grant;
  if (p) {
    require(
      !p.uncertain && !p.receipt && BigInt(p.amount) - BigInt(p.used || 0) > 0n,
      "This paid sandbox credit is used or awaiting its usage receipt. Your saved purchase details are below.",
    );
    require(
      node.registration.payments?.escrow.toLowerCase() ===
          cfg.escrow.toLowerCase() &&
        node.registration.payments.node === p.node,
      "The available sandbox does not match this paid credit class.",
    );
    grant = await api(
      "/payments/grant",
      await signed(credit.client, {
        client_peer: credit.client.peer,
        purchaseId: p.purchaseId,
        txHash: p.txHash,
        runId: node.registration.payments.runId,
      }),
    );
  } else {
    const reserveStarter = async () =>
      api(
        "/sandbox/starter-grant",
        await walletBody(credit, "sandbox-grant", {
          client_peer: credit.client.peer,
          node_peer: node.registration.relay_peer,
          job_id: jobId,
        }),
      );
    let starter;
    try {
      starter = await reserveStarter();
    } catch (failure) {
      if (failure.code === "starter_sandbox_used") {
        if (!starterSandboxUsed) await setStarterSandboxStatus("used");
        throw failure;
      }
      if (failure.code !== "diagnostic_node_not_live") throw failure;
      $("job-status").textContent =
        "The sandbox rotated. Verifying a fresh node before reserving your job…";
      node = undefined;
      await discover({ wait: true });
      starter = await reserveStarter();
    }
    grant = starter.grant;
    await setStarterSandboxStatus("running");
  }
  const credential = await sandbox.requestCapability(cfg.broker, {
    node,
    client: credit.client,
    grant,
    jobId,
  });
  const job = await sandbox.sealJob(node, {
    grant,
    jobId,
    credential,
    repoTar,
    prompt: $("job-prompt").value,
    client: credit.client,
  });
  if (p) {
    p.uncertain = true;
    await credit.save();
  }
  $("job-status").textContent =
    "Job sealed to the verified guest. Waiting for an attested result…";
  let result;
  try {
    result = await sandbox.receive(await sandbox.submitJob(cfg.broker, job));
  } catch (failure) {
    const returned = failure.response?.payment_receipt;
    if (returned && p) {
      const envelope = { ...returned, nodeBinding: grant.nodeBinding };
      try {
        credit.checkReceipt(envelope, p);
        const binding = envelope.nodeBinding.binding;
        require(
          binding.runId === node.registration.payments.runId &&
            binding.receiptSigner.toLowerCase() ===
              node.registration.payments.receiptSigner.toLowerCase() &&
            binding.composeHash === "0x" + node.registration.manifest_sha256 &&
            binding.imageHash === "0x" + node.registration.os_image_hash &&
            BigInt(envelope.receipt.used) >= BigInt(p.used || 0),
          "Failure receipt does not match the verified node run.",
        );
        p.receipt = envelope;
        p.used = String(envelope.receipt.used);
        p.uncertain = false;
        await credit.save();
      } catch (invalid) {
        p.uncertain = true;
        await credit.save();
        throw new Error(
          failure.message + "; failure usage receipt refused: " +
            invalid.message,
        );
      }
    }
    throw failure;
  }
  require(
    result.status !== "refused",
    `Sandbox refused: ${result.error}. Discover a fresh node before submitting a new job.`,
  );
  await sandbox.verifyJobAttestation(node, result, job);
  await sandbox.verifyReceipt(node, result, job);
  const outputs = await sandbox.openOutputs(job, result);
  const receipt = result.payment_receipt;
  if (p) {
    require(receipt, "Paid sandbox result has no settlement receipt.");
    p.receipt = { ...receipt, nodeBinding: grant.nodeBinding };
    p.used = String(receipt.receipt.used);
    p.uncertain = false;
    await credit.save();
    await api("/payments/receipts", receipt);
  }
  $("job-status").textContent =
    `Verified job attestation and receipt · ${result.statement.seconds_used} seconds. Patch decrypted and hashes verified.`;
  $("job-evidence").textContent = JSON.stringify(
    {
      attestation: result.attestation,
      statement: result.statement,
      receipt: result.receipt,
      payment_receipt: receipt,
    },
    null,
    2,
  );
  patch = outputs.patch;
  const patchText = decode.decode(patch);
  renderDiff(patchText);
  $("updated-files").replaceChildren();
  if (repoFiles) {
    const applied = applyVerifiedPatch(repoFiles, patchText);
    repoFiles = applied.files;
    repoTar = sampleTar(repoFiles);
    for (const name of applied.changes) {
      const heading = document.createElement("h3"),
        contents = document.createElement("pre");
      heading.textContent = name;
      contents.textContent = repoFiles.get(name) ?? "File deleted";
      contents.dataset.file = name;
      $("updated-files").append(heading, contents);
    }
    $("job-status").textContent +=
      " Patch applied to the included repository in this browser.";
    $("job-status").dataset.patchApplied = "true";
  }
  $("transcript").textContent = decode.decode(outputs.transcript);
  $("download").disabled = false;
  if (!p) await setStarterSandboxStatus("completed");
  node = undefined;
}
function renderDiff(text) {
  $("diff").replaceChildren();
  for (const line of text.split("\n")) {
    const span = document.createElement("span");
    span.className = line.startsWith("+")
      ? "add"
      : line.startsWith("-")
      ? "del"
      : line.startsWith("@@")
      ? "hunk"
      : "";
    span.textContent = line + "\n";
    $("diff").append(span);
  }
}
function resetSample() {
  repoFiles = new Map([["greet.txt", "Hello world.\n"]]);
  repoTar = sampleTar(repoFiles);
  $("job-prompt").value =
    "Replace greet.txt with this single line, including the final period and a newline:\nHello from the private agent.\nLeave all other files unchanged.";
  $("job-status").textContent =
    "Included repository ready: greet.txt. Describe a change and run it.";
  delete $("job-status").dataset.patchApplied;
  $("updated-files").replaceChildren();
}
function sampleTar(files) {
  const chunks = [];
  for (const [name, value] of files) {
    const content = encode.encode(value), header = new Uint8Array(512);
    require(
      encode.encode(name).length <= 100,
      "Updated filename exceeds the sample archive limit.",
    );
    const put = (pos, text) => header.set(encode.encode(text), pos);
    put(0, name);
    put(100, "0000644\0");
    put(108, "0000000\0");
    put(116, "0000000\0");
    put(124, content.length.toString(8).padStart(11, "0") + "\0");
    put(136, "00000000000\0");
    put(148, "        ");
    put(156, "0");
    put(257, "ustar\0");
    put(263, "00");
    put(
      148,
      header.reduce((a, b) => a + b, 0).toString(8).padStart(6, "0") + "\0 ",
    );
    const block = new Uint8Array(Math.ceil(content.length / 512) * 512);
    block.set(content);
    chunks.push(header, block);
  }
  const tar = new Uint8Array(
    chunks.reduce((total, chunk) => total + chunk.length, 1024),
  );
  let offset = 0;
  for (const chunk of chunks) {
    tar.set(chunk, offset);
    offset += chunk.length;
  }
  return tar;
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
async function main() {
  require(
    !/^\/(ipfs|ipns)\//.test(window.location.pathname),
    "Open this app through a CID or IPNS subdomain gateway. Shared path gateways cannot isolate your wallet from other sites.",
  );
  const response = await fetch("./config.json", { cache: "no-store" });
  require(response.ok, "Page configuration could not load.");
  cfg = await response.json();
  for (const name of ["broker", "rpc"]) {
    require(/^https:\/\//.test(cfg[name]), `${name} must be an explicit HTTPS service address.`);
  }
  cfg.sandboxPolicy = { ...approvedSandboxPolicy, registry: cfg.registry, rpc: cfg.rpc };
  require(cfg.chainId === 84532, "This page is restricted to Base Sepolia.");
  let client = await store("client");
  if (!client) {
    client = await sandbox.createClient();
    await store("client", client);
  }
  credit = await new Credit(cfg, client, render).init();
  initChat();
  render();
  action("burner", async () => {
    await credit.burner();
    await claimChatCredit();
  });
  action("connect", async () => {
    await credit.connect();
    await claimChatCredit();
  });
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
  action("discover", discover);
  action("run", async () => {
    try {
      await run();
    } catch (failure) {
      if (starterSandboxStatus === "running") {
        await setStarterSandboxStatus("stopped");
      }
      throw failure;
    }
  });
  action("sample", resetSample);
  action("download", () => {
    require(patch, "No verified patch.");
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
      const file = event.target.files[0];
      require(
        file?.size <= 16 * 1024 * 1024,
        "Repository exceeds the 16 MiB input limit.",
      );
      repoTar = new Uint8Array(await file.arrayBuffer());
      repoFiles = undefined;
      $("job-status").textContent =
        "Custom snapshot selected. Your verified patch will be available for download.";
      delete $("job-status").dataset.patchApplied;
      $("updated-files").replaceChildren();
    } catch (e) {
      repoTar = undefined;
      error(e);
    }
  };
  loadPolicy(cfg.sandboxPolicy);
  resetSample();
  document.documentElement.dataset.ready = "true";
  await refreshServices();
}
main().catch((e) => {
  error(e);
  document.body.dataset.failed = "true";
});
