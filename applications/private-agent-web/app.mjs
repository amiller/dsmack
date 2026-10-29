import "@mariozechner/mini-lit/dist/MarkdownBlock.js";
import "@pi-components/components/MessageList.js";
import "@pi-components/components/Messages.js";
import "@pi-components/components/MessageEditor.js";
import "@pi-components/components/StreamingMessageContainer.js";
import { Agent } from "@mariozechner/pi-agent-core";
import {
  Credit,
  formatEther,
  inferenceBody,
  require,
  signed,
  store,
} from "./credit.mjs";
import { brokerStream, PRIVACY } from "./inference.mjs";
import * as sandbox from "@sandbox";
const $ = (id) => document.getElementById(id),
  decode = new TextDecoder(),
  encode = new TextEncoder();
let cfg,
  credit,
  quote,
  classes = [],
  policy,
  node,
  verifiedAt,
  repoTar,
  patch,
  agent;
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
    throw new Error(
      typeof e === "object"
        ? (e.code + ": " + e.message)
        : e || `Broker ${path}: HTTP ${response.status}`,
    );
  }
  return opts.stream ? response : response.json();
}
function render() {
  $("wallet").textContent = credit.address || "No wallet connected";
  $("burner").disabled = !!credit.address;
  const list = $("purchases");
  list.replaceChildren();
  if (!credit.purchases.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No purchases yet.";
    list.append(p);
  }
  for (const p of credit.purchases) {
    const div = document.createElement("div");
    div.className = "purchase";
    const title = document.createElement("strong");
    title.textContent = `${
      p.status === "confirmed" ? "Confirmed" : "Pending"
    } · ${p.amount} ${p.unit === 2 ? "tokens" : "seconds"}`;
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
  renderPrice();
}
function renderPrice() {
  const unit = Number($("unit").value),
    q = unit === 2
      ? (quote ? { price: quote.priceWei } : null)
      : classes.find((c) => Number(c.unit) === 1);
  $("price").textContent = q
    ? `${q.price} wei per ${unit === 2 ? "token" : "second"}`
    : `${
      unit === 2 ? "Private inference" : "Sandbox"
    } credit is unavailable on this broker.`;
}
async function refreshServices() {
  await credit.checkBroker(api);
  classes = await api("/payments/classes");
  try {
    quote = await api("/inference/quote");
    require(
      quote.chainId === 84532 &&
        quote.escrow.toLowerCase() === cfg.escrow.toLowerCase() &&
        quote.codeHash === cfg.codeHash,
      "Inference quote has a different escrow.",
    );
    require(
      quote.model && !quote.model.startsWith("anthropic/"),
      "Routed Anthropic models are not private TEE inference.",
    );
    $("model").textContent = quote.model;
    setModel();
    $("service").textContent = quote.configured
      ? "Broker connected · " + PRIVACY
      : "Broker connected · Private inference is not configured.";
  } catch (e) {
    quote = undefined;
    $("service").textContent = "Broker connected · " + e.message;
  }
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
async function usage(p = credit.selected(2)) {
  require(p, "No confirmed inference purchase selected.");
  const result = await api(
    "/inference/usage",
    await inferenceBody(credit.client, p, "usage"),
  );
  require(
    String(result.purchaseId) === p.purchaseId &&
      BigInt(result.usedTokens) <= BigInt(p.amount),
    "Provider usage does not match purchased credit.",
  );
  p.used = String(result.usedTokens);
  p.allocation = result;
  p.needsReconcile = false;
  await credit.save();
  $("usage").textContent =
    `Provider: ${result.usedTokens} tokens · ${result.costNanoUsd} nano-USD · ${
      BigInt(p.used) * BigInt(p.priceWei)
    } wei charged`;
  details($("usage"), "Provider usage records", result.usage);
}
function addEvidence(e) {
  const item = document.createElement("div");
  item.className = "evidence-item";
  const p = document.createElement("p");
  p.className = "badge";
  p.textContent = `Answer ${
    $("attestations").querySelectorAll(".evidence-item").length + 1
  } · Broker verified attestation · Browser matched model and freshness`;
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
    contextWindow: quote?.requestTokenCeiling || 32768,
    maxTokens: 1024,
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
      systemPrompt: "You are a helpful coding assistant.",
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
      require(
        credit.selected(2),
        "CREDIT_NOT_CONFIRMED: Buy inference credit and wait for finalized confirmation before sending.",
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
    "Trusted policy loaded. Verify a node to continue.";
}
async function discover() {
  await credit.checkBroker(api);
  require(
    policy,
    "Load the independently approved sandbox policy in Trust settings before sending a job.",
  );
  const nodes = await api("/nodes");
  require(
    nodes.length,
    "No warm sandbox node is available. Try fresh discovery when one is running.",
  );
  const challenge = sandbox.hex(crypto.getRandomValues(new Uint8Array(32)));
  const registration = await api(
    "/sandbox/nodes/" + encodeURIComponent(nodes[0].relay_peer) +
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
  const p = credit.forSpend(1);
  require(
    p,
    "CREDIT_NOT_CONFIRMED: Confirm sandbox credit before sending a job.",
  );
  require(
    !p.uncertain && !p.receipt && BigInt(p.amount) - BigInt(p.used || 0) > 0n,
    "CREDIT_EXHAUSTED: This sandbox purchase has been used or its result is unresolved.",
  );
  await credit.checkBroker(api);
  require(
    repoTar,
    "Choose a repository snapshot or use the sample repository.",
  );
  require($("job-prompt").value.trim(), "Enter a sandbox task.");
  require(
    node && Date.now() - verifiedAt < 30000,
    "Verify a fresh sandbox node before sending the task.",
  );
  require(
    node.policy.provider?.schema === "dsmack-broker-model/1",
    "The pinned sandbox must use broker-verified TEE inference.",
  );
  require(
    node.registration.payments?.escrow.toLowerCase() ===
        cfg.escrow.toLowerCase() && node.registration.payments.node === p.node,
    "Verified node belongs to another escrow or credit class.",
  );
  const jobId = sandbox.hex(crypto.getRandomValues(new Uint8Array(16)));
  const grant = await api(
    "/payments/grant",
    await signed(credit.client, {
      client_peer: credit.client.peer,
      purchaseId: p.purchaseId,
      txHash: p.txHash,
      runId: node.registration.payments.runId,
    }),
  );
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
  p.uncertain = true;
  await credit.save();
  $("job-status").textContent =
    "Job sealed to the verified guest. Waiting for an attested result…";
  let result;
  try {
    result = await sandbox.receive(await sandbox.submitJob(cfg.broker, job));
  } catch (failure) {
    const returned = failure.response?.payment_receipt;
    if (returned) {
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
  require(receipt, "Paid sandbox result has no settlement receipt.");
  p.receipt = { ...receipt, nodeBinding: grant.nodeBinding };
  p.used = String(receipt.receipt.used);
  p.uncertain = false;
  await credit.save();
  await api("/payments/receipts", receipt);
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
  renderDiff(decode.decode(patch));
  $("transcript").textContent = decode.decode(outputs.transcript);
  $("download").disabled = false;
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
function sampleTar() {
  const content = encode.encode("Hello world.\n"), header = new Uint8Array(512);
  const put = (pos, text) => header.set(encode.encode(text), pos);
  put(0, "greet.txt");
  put(100, "0000644\0");
  put(108, "0000000\0");
  put(116, "0000000\0");
  put(124, content.length.toString(8).padStart(11, "0") + "\0");
  put(136, "00000000000\0");
  put(148, "        ");
  put(156, "0");
  put(257, "ustar\0");
  put(263, "00");
  const sum = header.reduce((a, b) => a + b, 0);
  put(148, sum.toString(8).padStart(6, "0") + "\0 ");
  const tar = new Uint8Array(2048);
  tar.set(header);
  tar.set(content, 512);
  return tar;
}
async function refund() {
  require(credit.address, "Connect the original purchase wallet.");
  const p = credit.purchases.find((p) =>
    p.unit === Number($("unit").value) && !p.closed && p.purchaseId &&
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
  } else if (p.unit === 2 && p.allocation) {
    const e = await api(
      "/inference/close",
      await inferenceBody(credit.client, p, "close"),
    );
    await credit.settle(e, p);
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
  const response = await fetch("./config.json", { cache: "no-store" });
  require(response.ok, "Page configuration could not load.");
  cfg = await response.json();
  require(cfg.chainId === 84532, "This page is restricted to Base Sepolia.");
  let client = await store("client");
  if (!client) {
    client = await sandbox.createClient();
    await store("client", client);
  }
  credit = await new Credit(cfg, client, render).init();
  initChat();
  render();
  action("burner", () => credit.burner());
  action("connect", () => credit.connect());
  action("balance", async () => {
    require(credit.address, "Create or connect a wallet first.");
    $("eth").textContent =
      formatEther(await credit.rpc.getBalance(credit.address)) +
      " Base Sepolia ETH";
  });
  action("buy", async () => {
    await credit.checkBroker(api);
    const unit = Number($("unit").value),
      q = unit === 2
        ? (quote ? { ...quote, unit: 2, price: quote.priceWei } : null)
        : classes.find((c) => Number(c.unit) === 1);
    await credit.buy(q ? { ...q, unit } : null, $("amount").value);
  });
  action("refresh", async () => {
    for (const p of credit.purchases.filter((p) => p.status === "pending")) {
      await credit.confirm(api, p);
    }
  });
  action("reconcile", () => usage());
  action("refund", refund);
  action("discover", discover);
  action("run", run);
  action("sample", () => {
    repoTar = sampleTar();
    $("job-prompt").value =
      "Change greet.txt to say Hello from the private agent. Return a patch.";
    $("job-status").textContent = "Sample repository ready: greet.txt";
  });
  action("download", () => {
    require(patch, "No verified patch.");
    const url = URL.createObjectURL(new Blob([patch], { type: "text/x-diff" })),
      a = document.createElement("a");
    a.href = url;
    a.download = "private-agent.patch";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $("unit").onchange = renderPrice;
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
    } catch (e) {
      repoTar = undefined;
      error(e);
    }
  };
  if (cfg.sandboxPolicy) loadPolicy(cfg.sandboxPolicy);
  document.documentElement.dataset.ready = "true";
  await refreshServices();
}
main().catch((e) => {
  error(e);
  document.body.dataset.failed = "true";
});
