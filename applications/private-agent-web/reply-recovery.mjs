import { networkFailure } from "./network-read.mjs";
// DOMException.message is read-only; retain abort identity and the original cause.
export function referenceError(error, ref) {
  if (!ref) return error;
  return Object.assign(new Error(`${error.message || String(error)} (ref ${ref})`, { cause: error }), {
    name: error.name, code: error.code, status: error.status, retryAfterSeconds: error.retryAfterSeconds, ref,
  });
}

// Keep transport failures actionable without treating a model's partial text as
// a completed answer. This object is saved with the native Pi assistant message.
export function replyFailure(error, { partial = false, online = globalThis.navigator?.onLine } = {}) {
  const original = error?.message || String(error);
  const code = error?.code || original.match(/^([A-Z0-9_]+):/)?.[1];
  const detail = [original,
    code && !original.includes(code) ? code : "",
    error?.status ? `HTTP ${error.status}` : "",
    error?.ref && !original.includes(`ref ${error.ref}`) ? `ref ${error.ref}` : "",
  ].filter(Boolean).join(" · ");
  const interrupted = !!partial;
  let category, message, retryable = true, addCredit = false;
  if (/request.*abort|operation.*abort/i.test(original)) {
    category = "cancelled";
    message = "Reply cancelled. Send a message or Retry.";
  } else if (/PROVIDER_|NEAR_|INFERENCE_ERROR/.test(code || "")) {
    category = "provider";
    const upstream = /^PROVIDER_HTTP_(\d{3})(?:_([A-Z0-9_]+))?$/.exec(code || "");
    const reasons = { 401: "authentication failed", 403: "access denied", 402: "insufficient credit", 429: "rate limited" };
    const reason = upstream?.[2]?.toLowerCase().replaceAll("_", " ") || reasons[upstream?.[1]];
    message = upstream
      ? `NEAR AI returned ${upstream[1]}${reason ? ` (${reason})` : ""}.`
      : code === "PROVIDER_TIMEOUT" ? "NEAR AI timed out. Retry."
      : code === "PROVIDER_ABORTED" ? "NEAR AI request was aborted. Retry."
      : code === "NEAR_ATTESTATION_TRANSPORT" ? "Couldn't reach NEAR AI over the attested connection. Retry."
      : "NEAR AI couldn't finish this reply. Wait a moment, then Retry.";
    if (upstream && ["401", "402", "403"].includes(upstream[1])) retryable = false;
  } else if (code === "STARTER_BUDGET_EXHAUSTED") {
    category = "credit";
    message = "Today's free credit is used up. Try again after 00:00 UTC.";
    addCredit = true;
    retryable = false;
  } else if (/CREDIT_EXHAUSTED|(?:ARTIFACT_)?BUDGET_EXHAUSTED/.test(code || original)) {
    category = "credit";
    message = /^(?:ARTIFACT_)?BUDGET_EXHAUSTED$/.test(code || "")
      ? "This app's credit is used up. Increase its allowed model budget before trying again."
      : "You're out of credit.";
    addCredit = !/^(?:ARTIFACT_)?BUDGET_EXHAUSTED$/.test(code || "");
    retryable = false;
  } else if (code === "FLEET_BUSY" || code === "FLEET_EMPTY") {
    category = "capacity";
    const capacity = original.match(/^(?:All (?:\d+ )?slots on the Dsmack network are busy|No Macs on the Dsmack network are online right now); retrying in \d+s/)?.[0];
    message = capacity || (code === "FLEET_BUSY"
      ? `All slots on the Dsmack network are busy; retrying in ${error.retryAfterSeconds || 15}s`
      : `No Macs on the Dsmack network are online right now; retrying in ${error.retryAfterSeconds || 15}s`);
  } else if (/USAGE_PENDING|REQUEST_IN_FLIGHT|REQUEST_ALREADY_DISPATCHED|REQUEST_REPLAY|Usage is unresolved/.test(code || original)) {
    category = "credit";
    message = "The last charge is still being confirmed. Try again in a minute.";
  } else if (/CREDIT_|ARTIFACT_BUDGET/.test(code || "")) {
    category = "credit";
    message = "Couldn't use your credit. Check your wallet and available credit before trying again.";
    retryable = false;
  } else if (/attest|verif|quote|(?:broker|signing|encryption) key|code hash|deployment pin|challenge mismatch|escrow code|measured|\bTDX\b|\bNRAS\b|\bMR(?:TD|SEAM|CONFIGID)\b/i.test(original)) {
    category = "verification";
    message = /model|NEAR/i.test(original)
      ? "Couldn't verify the model, so nothing was sent. Retry, or reload the page."
      : "Couldn't verify the sandbox, so nothing was sent. Retry, or reload the page.";
  } else if (online === false) {
    category = "offline";
    message = "Your browser is offline. Reconnect to the internet, then Retry.";
  } else if (/\[api\.invalid_input\]|invalid_json/.test(original)) {
    category = "provider";
    message = "The model couldn't read this request. Retry, or reload the page.";
  } else if (error?.status) {
    category = "broker";
    message = error.status === 403
      ? "The server refused this request. Retry, or reload the page."
      : "The server couldn't complete this request. Retry, or reload the page.";
  } else if (code === "GUEST_DISCONNECTED" || /guest.*(?:closed|disconnect)|transport.*closed/i.test(original)) {
    category = "guest";
    message = "Lost the connection to the sandbox. The command may have run; check the workspace before running it again.";
  } else if (networkFailure(error) || /network|fetch|connection|disconnect|transport|terminated|partial event|stream.*(ended|closed)|load failed/i.test(original)) {
    category = "browser";
    message = interrupted
      ? "Connection lost mid-reply. The partial reply is kept. Check your connection, then Retry."
      : "Your browser lost its connection. Check your connection, then Retry.";
  } else {
    category = "request";
    message = code || /\b(?:HTTP|broker|ciphertext|nano-USD|CID)\b|\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b|\(ref /i.test(original)
      ? "Couldn't complete this request. Retry, or reload the page."
      : original;
  }
  return { category, message, retryable, interrupted, detail, ...(addCredit ? { addCredit: true } : {}) };
}

export function retryCandidate(messages) {
  const last = messages.findLast(message => message.role !== "artifact" && message.role !== "system" && message.role !== "toolResult");
  if (last?.role !== "assistant" || !["error", "aborted"].includes(last.stopReason) || !last.failure?.retryable) return;
  return last;
}

export function meteredReply(billing) {
  if (!billing?.dispatched) return "Not charged.";
  if (!billing.settled || billing.costUnknown || billing.costNanoUsd == null)
    return "The charge is still being confirmed. Retry checks it first.";
  return `This attempt cost $${(Number(billing.costNanoUsd) / 1e9).toFixed(4)}. Retrying costs again.`;
}

export function settleInterruptedReply(reply, ledger) {
  const billing = reply.billing, charge = ledger.lastModelCharge;
  if (!billing?.dispatched || billing.settled || ledger.pendingInferenceId ||
    billing.wallet !== ledger.wallet?.toLowerCase() || charge?.sessionId !== billing.sessionId) return false;
  if (!/^(0|[1-9][0-9]*)$/.test(charge.costNanoUsd) || BigInt(charge.costNanoUsd) > BigInt(billing.reservedNanoUsd))
    throw Error("USAGE_MISMATCH: The broker's charge exceeds this reply's reservation. Check provider usage before retrying.");
  Object.assign(billing, { settled: true, exactModelCost: true, costNanoUsd: charge.costNanoUsd, costUnknown: false });
  delete billing.pendingReason;
  reply.usage.cost.total = Number(charge.costNanoUsd) / 1e9;
  return true;
}

// Interrupted model turns and restored chats may contain calls core never ran.
// Pair each once so the UI and the next model request see the same failure.
export function failOrphanedTools(messages, reason) {
  const settled = new Set(messages.filter(m => m.role === "toolResult").map(m => m.toolCallId));
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i];
    if (message.role !== "assistant") continue;
    const results = message.content.filter(p => p.type === "toolCall" && !settled.has(p.id)).map(call => {
      settled.add(call.id);
      return { role: "toolResult", toolCallId: call.id, toolName: call.name, isError: true,
        content: [{ type: "text", text: reason }], details: {}, timestamp: Date.now() };
    });
    messages.splice(i + 1, 0, ...results);
    i += results.length;
  }
}
