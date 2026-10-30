import { AssistantMessageEventStream, getSystemMessageText } from "@earendil-works/pi-ai";
import { require, walletBody } from "./credit.mjs";
import { prepareE2eeChatRequest } from "@nearai/inference-sdk";
import { checkEvidence, PRIVACY } from "./evidence.mjs";
import { replyFailure } from "./reply-recovery.mjs";
export { checkEvidence, PRIVACY };
export async function* sse(body) {
  const reader = body.getReader(), decoder = new TextDecoder();
  let pending = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      pending += done
        ? decoder.decode()
        : decoder.decode(value, { stream: true });
      pending = pending.replace(/\r\n/g, "\n");
      let at;
      while ((at = pending.indexOf("\n\n")) >= 0) {
        const frame = pending.slice(0, at);
        pending = pending.slice(at + 2);
        let event = "message", data = [];
        for (const line of frame.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
        }
        if (data.length) yield { event, data: data.join("\n") };
      }
      if (done) {
        require(
          !pending.trim(),
          "Inference stream ended in a partial event. Reconcile usage before retrying.",
        );
        break;
      }
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}
// Main chat and artifact calls share a wallet ledger. Hold the lock until usage
// is reconciled so another caller cannot change the attribution baseline.
const walletCalls = new Map();
export function withInferenceWallet(credit, operation) {
  const key = `dsmack/inference/${credit.address?.toLowerCase() || "unconnected"}`;
  const prior = walletCalls.get(key) || Promise.resolve();
  const next = prior.catch(() => {}).then(() => globalThis.navigator?.locks
    ? navigator.locks.request(key, operation) : operation());
  walletCalls.set(key, next);
  const clear = () => { if (walletCalls.get(key) === next) walletCalls.delete(key); };
  next.then(clear, clear);
  return next;
}

export function brokerStream(
  { credit, api, cfg, quote, evidence, usage, error, startedAt, systemPrompt },
) {
  const conversationStarted = new Date(startedAt);
  return (model, context, options = {}) => {
    const stream = new AssistantMessageEventStream();
    const answer = {
      role: "assistant",
      content: [{ type: "text", text: "" }],
      api: "dsmack-inference",
      provider: "near",
      model: model.id,
      usage: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "stop",
      timestamp: Date.now(),
    };
    withInferenceWallet(credit, async () => {
      let session;
      const billing = answer.billing = { dispatched: false, settled: false, reservedNanoUsd: "0" };
      const reportError = error || (() => {});
      const reconcile = async () => {
        const charged = await usage();
        if (options.artifactId) billing.artifactBudget = charged.artifactBudgets?.[options.artifactId];
        require(!charged.pendingInferenceId, "USAGE_PENDING: Provider cost is still pending.");
        const exact = session.modelSpentNanoUsd !== undefined && charged.modelSpentNanoUsd !== undefined;
        require(!options.requireModelCost || exact, "MODEL_COST_UNAVAILABLE: Broker must report model-only cost.");
        let cost;
        if (options.artifactId) {
          const budget = billing.artifactBudget;
          require(budget && BigInt(budget.reservedNanoUsd) === 0n, "USAGE_PENDING: Artifact model cost is still pending.");
          cost = budget.lastSessionId === session.sessionId && typeof budget.lastCostNanoUsd === "string"
            ? BigInt(budget.lastCostNanoUsd) : null;
        } else if (Object.hasOwn(charged, "lastModelCharge")) {
          const charge = charged.lastModelCharge;
          cost = charge?.sessionId === session.sessionId && typeof charge.costNanoUsd === "string"
            ? BigInt(charge.costNanoUsd) : null;
        } else {
          const before = BigInt(exact ? session.modelSpentNanoUsd : session.spentNanoUsd);
          const after = BigInt(exact ? charged.modelSpentNanoUsd : charged.spentNanoUsd);
          cost = after - before;
        }
        require(cost === null || cost >= 0n && (!exact || cost <= BigInt(billing.reservedNanoUsd)),
          "USAGE_MISMATCH: Model cost differs from its reservation.");
        // Token counts belong to this encrypted stream, never a wallet-wide
        // counter that another device's inference could have advanced.
        answer.usage.cost.total = cost === null ? 0 : Number(cost) / 1e9;
        Object.assign(billing, { settled: true, exactModelCost: exact && cost !== null,
          costNanoUsd: cost === null ? null : String(cost), costUnknown: cost === null });
      };
      try {
        require(!options.signal?.aborted, "Inference request was aborted.");
        const q = quote();
        require(
          q?.configured,
          "Private inference is not configured on this broker.",
        );
        await credit.checkBroker(api);
        await options.beforePrepare?.();
        require(
          credit.signer && credit.chatCredit,
          "Create or connect a wallet to receive starter chat credit.",
        );
        require(
          !credit.chatCredit.pendingInferenceId,
          "Usage is unresolved. Reconcile provider usage before sending another message.",
        );
        require(
          BigInt(credit.chatCredit.remainingNanoUsd) > 0n,
          "CREDIT_EXHAUSTED: Chat credit used up.",
        );
        const { messages, tools } = modelTranscript(context);
        const started = Date.now();
        const attestationNonce = Array.from(
          crypto.getRandomValues(new Uint8Array(32)),
          (b) => b.toString(16).padStart(2, "0"),
        ).join("");
        session = await api(
          "/inference/prepare",
          await walletBody(credit, "prepare", { attestationNonce,
            ...(options.artifactId ? { artifactId: options.artifactId } : {}) }),
          { signal: options.signal },
        );
        const checked = checkEvidence(
          session.attestation,
          model.id,
          started,
          attestationNonce,
          session.modelPublicKey,
        );
        require(
          /^[0-9a-f]{32}$/.test(session.sessionId),
          "Provider preparation has no session ID.",
        );
        await evidence(checked);
        const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const date = new Intl.DateTimeFormat(undefined, {
          dateStyle: "full",
          timeZone,
        }).format(conversationStarted);
        const runtime = [
          `Model: ${checked.model}`,
          "Provider: NEAR AI Cloud (TEE)",
          `Conversation started: ${date} (${timeZone})`,
        ].join("\n");
        messages.unshift({
          role: "system",
          content: systemPrompt ? systemPrompt({ checked, runtime }) :
            context.messages.filter(m => m.role === "system").map(getSystemMessageText).join("\n\n") + "\n\n" + runtime,
        });
        require(!options.requireModelCost || typeof session.modelSpentNanoUsd === "string",
          "MODEL_COST_UNAVAILABLE: Broker must report model-only cost.");
        const walletRemaining = BigInt(session.remainingNanoUsd);
        const ceiling = options.maxNanoUsd === undefined ? walletRemaining : BigInt(typeof options.maxNanoUsd === "function" ? await options.maxNanoUsd() : options.maxNanoUsd);
        require(ceiling > 0n, "ARTIFACT_BUDGET_EXHAUSTED: Artifact budget used up.");
        let remaining = walletRemaining < ceiling ? walletRemaining : ceiling;
        if (options.artifactId) {
          const budget = session.artifactBudgets?.[options.artifactId];
          require(budget, "ARTIFACT_BUDGET_REQUIRED: Allow this artifact a model budget first.");
          const allowed = BigInt(budget.limitNanoUsd) - BigInt(budget.spentNanoUsd) - BigInt(budget.reservedNanoUsd);
          require(allowed > 0n, "ARTIFACT_BUDGET_EXHAUSTED: Artifact budget used up.");
          if (allowed < remaining) remaining = allowed;
        }
        const rate = BigInt(q.maxNanoUsdPerToken);
        const reservation = (body) => BigInt(
          new TextEncoder().encode(JSON.stringify(body)).length + 256 +
            64 * body.messages.length + body.max_tokens,
        ) * rate;
        if (options.maxTokens !== undefined) require(Number.isSafeInteger(options.maxTokens) && options.maxTokens >= 64,
          "INVALID_ARGS: maxTokens must be an integer of at least 64.");
        let maxTokens = Math.min(q.maxOutputTokens, options.maxTokens ?? q.maxOutputTokens), prepared, body;
        for (;;) {
          const request = new Request(
            new URL("/v1/chat/completions", window.location.origin),
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                model: checked.model,
                messages,
                ...(tools.length ? { tools, tool_choice: "auto" } : {}),
                max_tokens: maxTokens,
                stream: true,
                stream_options: { include_usage: true },
              }),
            },
          );
          prepared = await prepareE2eeChatRequest({
            request,
            modelKey: { signingAlgo: "ecdsa", publicKey: session.modelPublicKey },
          });
          body = await prepared.request.json();
          require(!q.maxRequestBytes || new TextEncoder().encode(JSON.stringify(body)).length <= q.maxRequestBytes,
            "INVALID_ARGS: Encrypted model request exceeds the broker byte limit.");
          if (reservation(body) <= remaining) break;
          // Include the serialized token limit itself in the broker's byte cost.
          // Re-encrypt the chosen limit and check the actual wire body again.
          let low = 64, high = maxTokens - 1, affordable = 0;
          while (low <= high) {
            const candidate = Math.floor((low + high) / 2);
            if (reservation({ ...body, max_tokens: candidate }) <= remaining) {
              affordable = candidate;
              low = candidate + 1;
            } else high = candidate - 1;
          }
          require(affordable >= 64, remaining < walletRemaining
            ? "ARTIFACT_BUDGET_EXHAUSTED: Artifact budget cannot cover the encrypted request."
            : "CREDIT_EXHAUSTED: Chat credit used up.");
          maxTokens = affordable;
        }
        const headers = Object.fromEntries(prepared.request.headers);
        const signed = await walletBody(credit, "chat", {
          sessionId: session.sessionId,
          body,
          headers,
        });
        Object.assign(billing, { reservedNanoUsd: String(reservation(body)),
          baselineModelSpentNanoUsd: session.modelSpentNanoUsd, wallet: credit.address.toLowerCase(),
          sessionId: session.sessionId });
        await options.onReserve?.({ ...billing });
        require(!options.signal?.aborted, "Inference request was aborted.");
        billing.dispatched = true;
        credit.chatCredit.pendingInferenceId = "awaiting-provider-response";
        const response = await api("/inference/chat", signed, {
          stream: true,
          signal: options.signal,
        });
        const decrypted = await prepared.decryptResponse(response);
        let done = false, finishReason;
        const toolCalls = new Map();
        stream.push({ type: "start", partial: answer });
        for await (const item of sse(decrypted.body)) {
          if (item.event === "error") {
            const e = JSON.parse(item.data).error;
            throw Object.assign(new Error(
              (e?.code || "INFERENCE_ERROR") + ": " +
                (e?.message || "Stream failed. Reconcile usage."),
            ), { code: e?.code || "INFERENCE_ERROR" });
          }
          if (item.data === "[DONE]") {
            done = true;
            continue;
          }
          const chunk = JSON.parse(item.data);
          require(
            !chunk.model || chunk.model === model.id,
            "Provider completion model differs from its attestation.",
          );
          if (chunk.usage) {
            answer.usage.input = chunk.usage.prompt_tokens;
            answer.usage.output = chunk.usage.completion_tokens;
            answer.usage.totalTokens = chunk.usage.total_tokens;
          }
          const choice = chunk.choices?.[0];
          if (choice?.finish_reason) finishReason = choice.finish_reason;
          const delta = choice?.delta?.content;
          if (typeof delta === "string" && delta) {
            if (!answer.content[0].text) stream.push({ type: "text_start", contentIndex: 0, partial: answer });
            answer.content[0].text += delta;
            stream.push({ type: "text_delta", contentIndex: 0, delta, partial: answer });
          }
          for (const call of choice?.delta?.tool_calls || []) {
            let current = toolCalls.get(call.index);
            if (!current) {
              current = { index: answer.content.length, json: "", block: { type: "toolCall", id: call.id || "", name: call.function?.name || "", arguments: {} } };
              toolCalls.set(call.index, current);
              answer.content.push(current.block);
              stream.push({ type: "toolcall_start", contentIndex: current.index, partial: answer });
            } else {
              if (call.id) current.block.id += call.id;
              if (call.function?.name) current.block.name += call.function.name;
            }
            const fragment = call.function?.arguments || "";
            current.json += fragment;
            stream.push({ type: "toolcall_delta", contentIndex: current.index, delta: fragment, partial: answer });
          }
        }
        require(
          done,
          "Inference transport ended before completion. Reconcile provider usage.",
        );
        if (answer.content[0].text) stream.push({ type: "text_end", contentIndex: 0, content: answer.content[0].text, partial: answer });
        for (const current of toolCalls.values()) {
          try {
            current.block.arguments = JSON.parse(current.json || "{}");
            require(current.block.arguments && !Array.isArray(current.block.arguments) && typeof current.block.arguments === "object", "Tool arguments must be a JSON object.");
          } catch (e) {
            current.block.arguments = {};
            current.block.argumentsError = "Model returned invalid tool arguments: " + current.json;
          }
          require(current.block.id && current.block.name, "Incomplete tool call from model.");
          stream.push({ type: "toolcall_end", contentIndex: current.index, toolCall: current.block, partial: answer });
        }
        answer.stopReason = toolCalls.size ? "toolUse" : finishReason === "length" ? "length" : "stop";
        try { await reconcile(); } catch (e) { billing.pendingReason = e.message; reportError(e); }
      } catch (e) {
        // Publish the interruption immediately. Ledger reconciliation can take
        // time after a broker restart, but it must not hide the partial answer.
        if (!options.signal?.aborted) {
          answer.failure = replyFailure(e, { partial: answer.content.some(part => part.type === "text" && part.text) });
          answer.stopReason = "error";
          answer.errorMessage = (answer.failure.interrupted ? "Interrupted · " : "") + answer.failure.message;
          if (answer.failure.interrupted) stream.push({ type: "text_delta", contentIndex: 0, delta: "", partial: answer });
          reportError(Object.assign(new Error(answer.failure.message), { replyFailure: answer.failure }));
        }
        if (billing.dispatched && !billing.settled) {
          try { await reconcile(); } catch (usageError) {
            billing.pendingReason = usageError.message;
          }
        }
        answer.stopReason = options.signal?.aborted ? "aborted" : "error";
        answer.errorMessage = answer.failure
          ? (answer.failure.interrupted ? "Interrupted · " : "") + answer.failure.message : e.message;
        answer.errorCode = e.code;
      }
      try { await options.onBilling?.({ ...billing }); } catch (e) {
        answer.stopReason = "error";
        answer.failure ||= replyFailure(e, { partial: answer.content.some(part => part.type === "text" && part.text) });
        answer.errorMessage = (answer.failure.interrupted ? "Interrupted · " : "") + answer.failure.message;
        answer.errorCode ||= e.code;
        reportError(Object.assign(new Error(answer.failure.message), { replyFailure: answer.failure }));
      }
    }).catch(e => {
      answer.stopReason = options.signal?.aborted ? "aborted" : "error";
      answer.failure = replyFailure(e, { partial: answer.content.some(part => part.type === "text" && part.text) });
      answer.errorMessage = (answer.failure.interrupted ? "Interrupted · " : "") + answer.failure.message;
      error?.(Object.assign(new Error(answer.failure.message), { replyFailure: answer.failure }));
    }).finally(() => {
      stream.push(answer.stopReason === "error" || answer.stopReason === "aborted"
        ? { type: "error", reason: answer.stopReason, error: answer }
        : { type: "done", reason: answer.stopReason, message: answer });
      stream.end(answer);
    });
    return stream;
  };
}

// Preserve tool requests and results in the encrypted provider transcript. Pi 1.4
// carries declarations in system messages, including changes during a session.
export function modelTranscript(context) {
  const declarations = new Map(), messages = [];
  for (const message of context.messages) {
    if (message.role === "system") {
      for (const tool of message.toolsAdded || []) declarations.set(tool.name, tool);
      for (const tool of message.toolsRemoved || []) declarations.delete(tool.name);
    } else if (message.role === "toolResult") {
      messages.push({ role: "tool", tool_call_id: message.toolCallId,
        content: contentText(message.content) });
    } else if (message.role === "assistant") {
      // Keep failed attempts in the page, but never replay a partial answer as
      // completed model output when the user retries or sends another turn.
      if (message.stopReason === "error" || message.stopReason === "aborted") continue;
      const calls = message.content.filter(c => c.type === "toolCall");
      messages.push({ role: "assistant", content: contentText(message.content) || null,
        ...(calls.length ? { tool_calls: calls.map(c => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.arguments) } })) } : {}) });
    } else if (message.role === "user") messages.push({ role: "user", content: contentText(message.content) });
  }
  return { messages, tools: [...declarations.values()].map(t => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } })) };
}
function contentText(content) {
  return typeof content === "string" ? content : content.filter(c => c.type === "text").map(c => c.text).join("\n");
}
