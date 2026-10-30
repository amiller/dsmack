import { AssistantMessageEventStream } from "@mariozechner/pi-ai";
import { require, walletBody } from "./credit.mjs";
import { prepareE2eeChatRequest } from "@nearai/inference-sdk";
import { checkEvidence, PRIVACY } from "./evidence.mjs";
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
export function brokerStream(
  { credit, api, cfg, quote, evidence, usage, error },
) {
  let conversationStarted;
  return (model, context, options = {}) => {
    conversationStarted ??= new Date();
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
    (async () => {
      let dispatched = false;
      try {
        const q = quote();
        require(
          q?.configured,
          "Private inference is not configured on this broker.",
        );
        await credit.checkBroker(api);
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
        const messages = context.messages.filter((m) =>
          m.role === "user" || m.role === "assistant"
        )
          .map((m) => ({
            role: m.role,
            content: typeof m.content === "string"
              ? m.content
              : m.content.filter((c) => c.type === "text").map((c) => c.text)
                .join("\n"),
          }));
        const started = Date.now();
        const attestationNonce = Array.from(
          crypto.getRandomValues(new Uint8Array(32)),
          (b) => b.toString(16).padStart(2, "0"),
        ).join("");
        const session = await api(
          "/inference/prepare",
          await walletBody(credit, "prepare", { attestationNonce }),
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
        evidence(checked);
        const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const date = new Intl.DateTimeFormat(undefined, {
          dateStyle: "full",
          timeZone,
        }).format(conversationStarted);
        messages.unshift({
          role: "system",
          content: context.systemPrompt + "\n\n" + [
            `Model: ${checked.model}`,
            "Provider: NEAR AI Cloud (TEE)",
            `Conversation started: ${date} (${timeZone})`,
          ].join("\n"),
        });
        const remaining = BigInt(session.remainingNanoUsd);
        const rate = BigInt(q.maxNanoUsdPerToken);
        const reservation = (body) => BigInt(
          new TextEncoder().encode(JSON.stringify(body)).length + 256 +
            64 * body.messages.length + body.max_tokens,
        ) * rate;
        let maxTokens = q.maxOutputTokens, prepared, body;
        for (;;) {
          const request = new Request(
            new URL("/v1/chat/completions", window.location.origin),
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                model: checked.model,
                messages,
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
          require(affordable >= 64, "CREDIT_EXHAUSTED: Chat credit used up.");
          maxTokens = affordable;
        }
        const headers = Object.fromEntries(prepared.request.headers);
        const signed = await walletBody(credit, "chat", {
          sessionId: session.sessionId,
          body,
          headers,
        });
        dispatched = true;
        credit.chatCredit.pendingInferenceId = "awaiting-provider-response";
        const response = await api("/inference/chat", signed, {
          stream: true,
          signal: options.signal,
        });
        const decrypted = await prepared.decryptResponse(response);
        let done = false;
        stream.push({ type: "start", partial: answer });
        for await (const item of sse(decrypted.body)) {
          if (item.event === "error") {
            const e = JSON.parse(item.data).error;
            throw new Error(
              (e?.code || "INFERENCE_ERROR") + ": " +
                (e?.message || "Stream failed. Reconcile usage."),
            );
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
          const delta = chunk.choices?.[0]?.delta?.content;
          if (typeof delta === "string" && delta) {
            if (!answer.content[0].text) {
              stream.push({
                type: "text_start",
                contentIndex: 0,
                partial: answer,
              });
            }
            answer.content[0].text += delta;
            stream.push({
              type: "text_delta",
              contentIndex: 0,
              delta,
              partial: answer,
            });
          }
        }
        require(
          done,
          "Inference transport ended before completion. Reconcile provider usage.",
        );
        stream.push({
          type: "text_end",
          contentIndex: 0,
          content: answer.content[0].text,
          partial: answer,
        });
        try {
          await usage();
        } catch (e) {
          error(e);
        }
        stream.push({ type: "done", reason: "stop", message: answer });
        stream.end(answer);
      } catch (e) {
        if (dispatched) {
          try {
            await usage();
          } catch (usageError) {
            error(usageError);
          }
        }
        answer.stopReason = options.signal?.aborted ? "aborted" : "error";
        answer.errorMessage = e.message;
        error(e);
        stream.push({
          type: "error",
          reason: answer.stopReason,
          error: answer,
        });
        stream.end(answer);
      }
    })();
    return stream;
  };
}
