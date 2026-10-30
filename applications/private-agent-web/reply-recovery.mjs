// Keep transport failures actionable without treating a model's partial text as
// a completed answer. This object is saved with the native Pi assistant message.
export function replyFailure(error, { partial = false, online = globalThis.navigator?.onLine } = {}) {
  const detail = error?.message || String(error);
  const code = error?.code || detail.match(/^([A-Z_]+):/)?.[1];
  const interrupted = !!partial;
  let category, message, retryable = true;
  if (/CREDIT_EXHAUSTED|ARTIFACT_BUDGET_EXHAUSTED/.test(code || detail)) {
    category = "credit";
    message = code === "ARTIFACT_BUDGET_EXHAUSTED"
      ? "ARTIFACT_BUDGET_EXHAUSTED: Artifact credit used up. Increase its allowed model budget before trying again."
      : "CREDIT_EXHAUSTED: Chat credit used up. Check your chat credit before trying again.";
    retryable = false;
  } else if (/USAGE_PENDING|Usage is unresolved/.test(code || detail)) {
    category = "credit";
    message = "USAGE_PENDING: Chat credit is waiting for NEAR AI's metered usage. Use Reconcile provider usage, then Retry; another request cannot start until it settles.";
  } else if (/CREDIT_|ARTIFACT_BUDGET/.test(code || "")) {
    category = "credit";
    message = `Chat credit request refused (${code}). Check your wallet and available credit before trying again.`;
    retryable = false;
  } else if (online === false) {
    category = "offline";
    message = "You are offline. Reconnect to the internet, then Retry.";
  } else if (/PROVIDER_|NEAR_|INFERENCE_ERROR/.test(code || "")) {
    category = "provider";
    message = `NEAR AI provider error${interrupted ? " interrupted this reply" : ""}. Wait a moment, then Retry.${code ? " (" + code + ")" : ""}`;
  } else if (error?.status >= 500 || /network|fetch|connection|disconnect|transport|terminated|partial event|stream.*(ended|closed)|load failed/i.test(detail)) {
    category = "broker";
    message = interrupted
      ? "Connection lost mid-reply — the server may have restarted. Retry"
      : "Cannot reach the broker; it may be restarting. Wait a moment, then Retry.";
    if (error?.status) message += ` (Broker HTTP ${error.status}${code ? ", " + code : ""})`;
  } else {
    category = "request";
    message = `Model request refused: ${detail} Check the reported issue before trying again.`;
    retryable = false;
  }
  return { category, message, retryable, interrupted };
}

export function retryCandidate(messages) {
  const last = messages.findLast(message => message.role !== "artifact" && message.role !== "system");
  if (last?.role !== "assistant" || last.stopReason !== "error" || !last.failure?.retryable) return;
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
