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
  const detail = error?.message || String(error);
  const code = error?.code || detail.match(/^([A-Z_]+):/)?.[1];
  const interrupted = !!partial;
  let category, message, retryable = true;
  if (/request.*abort|operation.*abort/i.test(detail)) {
    category = "cancelled";
    message = "Reply cancelled. Send a message or Retry.";
  } else if (/CREDIT_EXHAUSTED|(?:ARTIFACT_)?BUDGET_EXHAUSTED/.test(code || detail)) {
    category = "credit";
    message = /^(?:ARTIFACT_)?BUDGET_EXHAUSTED$/.test(code || "")
      ? "ARTIFACT_BUDGET_EXHAUSTED: Artifact credit used up. Increase its allowed model budget before trying again."
      : "CREDIT_EXHAUSTED: Chat credit used up. Check your chat credit before trying again.";
    retryable = false;
  } else if (code === "FLEET_BUSY" || code === "FLEET_EMPTY") {
    category = "capacity";
    message = code === "FLEET_BUSY"
      ? `All Macs are busy, retry in ${error.retryAfterSeconds || 15} seconds.`
      : "No Macs are connected right now. Try again shortly.";
  } else if (/USAGE_PENDING|REQUEST_IN_FLIGHT|REQUEST_ALREADY_DISPATCHED|REQUEST_REPLAY|Usage is unresolved/.test(code || detail)) {
    category = "credit";
    message = `${code || "USAGE_PENDING"}: ${/REQUEST_ALREADY_DISPATCHED|REQUEST_REPLAY/.test(code || "") ? "This message was already sent. " : ""}Chat credit is waiting for NEAR AI's metered usage. Use Reconcile provider usage, then Retry; another request cannot start until it settles.`;
  } else if (/CREDIT_|ARTIFACT_BUDGET/.test(code || "")) {
    category = "credit";
    message = `Chat credit request refused (${code}). Check your wallet and available credit before trying again.`;
    retryable = false;
  } else if (online === false) {
    category = "offline";
    message = "Your browser is offline. Reconnect to the internet, then Retry.";
  } else if (/\[api\.invalid_input\]|invalid_json/.test(detail)) {
    category = "provider";
    message = `NEAR AI could not read the model request: ${detail} Send again. If it happens again, try another browser.`;
  } else if (/PROVIDER_|NEAR_|INFERENCE_ERROR/.test(code || "")) {
    category = "provider";
    message = `NEAR AI provider error${interrupted ? " interrupted this reply" : ""}. Wait a moment, then Retry.${code ? " (" + code + ")" : ""}`;
  } else if (error?.status) {
    category = "broker";
    message = `Broker returned HTTP ${error.status}${code ? " (" + code + ")" : ""}: ${detail} Retry.`;
  } else if (code === "GUEST_DISCONNECTED" || /guest.*(?:closed|disconnect)|transport.*closed/i.test(detail)) {
    category = "guest";
    message = "Mac guest disconnected. The command may have run; check the workspace before running it again.";
  } else if (networkFailure(error) || /network|fetch|connection|disconnect|transport|terminated|partial event|stream.*(ended|closed)|load failed/i.test(detail)) {
    category = "browser";
    message = interrupted
      ? "Connection lost mid-reply: your browser lost its connection, the tab was in the background, or the server restarted. The partial reply is kept. Retry"
      : "Your browser lost its connection, or the tab was in the background. Return to the tab, check your connection, then Retry.";
  } else {
    category = "request";
    message = `Model request refused: ${detail} Send again. If it happens again, try another browser.`;
  }
  const ref = error?.ref;
  if (typeof ref === "string" && /^[0-9a-f]{8}$/.test(ref) && !message.includes(`ref ${ref}`)) message += ` (ref ${ref})`;
  return { category, message, retryable, interrupted };
}

export function retryCandidate(messages) {
  const last = messages.findLast(message => message.role !== "artifact" && message.role !== "system" && message.role !== "toolResult");
  if (last?.role !== "assistant" || !["error", "aborted"].includes(last.stopReason) || !last.failure?.retryable) return;
  return last;
}

export function meteredReply(billing) {
  if (!billing?.dispatched) return "The model request was not sent; no model charge.";
  if (!billing.settled || billing.costUnknown || billing.costNanoUsd == null)
    return "The broker's model charge is not yet confirmed. Retry checks the ledger first.";
  return `Broker-metered ${billing.exactModelCost ? "model " : ""}charge: $${(Number(billing.costNanoUsd) / 1e9).toFixed(6)}. Retry is a new metered request.`;
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
