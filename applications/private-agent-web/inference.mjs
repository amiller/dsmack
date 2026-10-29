import { AssistantMessageEventStream } from "@mariozechner/pi-ai";
import { inferenceBody, require } from "./credit.mjs";
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
    (async () => {
      let purchase;
      try {
        const q = quote();
        require(
          q?.configured,
          "Private inference is not configured on this broker.",
        );
        await credit.checkBroker(api);
        purchase = credit.forSpend(2, q.requestTokenCeiling);
        require(
          purchase,
          "CREDIT_NOT_CONFIRMED: Buy inference credit and wait for finalized confirmation before sending.",
        );
        require(
          !purchase.needsReconcile,
          "Usage is unresolved. Reconcile provider usage before sending another message.",
        );
        const remaining = BigInt(purchase.amount) - BigInt(purchase.used || 0);
        require(
          remaining >= BigInt(q.requestTokenCeiling),
          "CREDIT_EXHAUSTED: Confirmed credit cannot cover the request reservation. Refund or top up.",
        );
        if (!purchase.allocation) {
          purchase.allocation = "minting";
          await credit.save();
          const minted = await api(
            "/inference/mint",
            await inferenceBody(credit.client, purchase, "mint"),
          );
          purchase.allocation = minted;
          await credit.save();
        }
        require(
          purchase.allocation !== "minting",
          "MINT_AMBIGUOUS: Key allocation is unresolved; reconcile before retrying.",
        );
        const messages = context.messages.filter((m) =>
          m.role === "user" || m.role === "assistant"
        ).map((m) => ({
          role: m.role,
          content: typeof m.content === "string"
            ? m.content
            : m.content.filter((c) => c.type === "text").map((c) => c.text)
              .join("\n"),
        }));
        if (context.systemPrompt) {
          messages.unshift({ role: "system", content: context.systemPrompt });
        }
        const started = Date.now();
        purchase.needsReconcile = true;
        await credit.save();
        const request = await inferenceBody(credit.client, purchase, "chat", {
          messages,
          max_tokens: 1024,
        });
        const nonceBytes = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(
            "dsmack-near-attestation/1:" + purchase.purchaseId + ":" +
              purchase.txHash + ":" + request.nonce,
          ),
        );
        const expectedNonce = Array.from(
          new Uint8Array(nonceBytes),
          (b) => b.toString(16).padStart(2, "0"),
        ).join("");
        const response = await api("/inference/chat", request, {
          stream: true,
          signal: options.signal,
        });
        let attested = false, done = false;
        stream.push({ type: "start", partial: answer });
        for await (const item of sse(response.body)) {
          if (item.event === "error") {
            const e = JSON.parse(item.data).error;
            throw new Error(
              (e?.code || "INFERENCE_ERROR") + ": " +
                (e?.message || "Stream failed. Reconcile usage."),
            );
          }
          if (item.event === "attestation") {
            require(!attested, "Repeated provider attestation in one stream.");
            evidence(
              checkEvidence(
                JSON.parse(item.data),
                model.id,
                started,
                expectedNonce,
              ),
            );
            attested = true;
            continue;
          }
          require(
            attested,
            "Provider sent answer data before verified model attestation.",
          );
          if (item.data === "[DONE]") {
            done = true;
            break;
          }
          const chunk = JSON.parse(item.data);
          require(
            !chunk.model || chunk.model === model.id,
            "Provider completion model differs from its attestation.",
          );
          const delta = chunk.choices?.[0]?.delta?.content;
          if (typeof delta === "string") {
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
          attested && done,
          "Inference transport ended before completion. Reconcile provider usage.",
        );
        stream.push({
          type: "text_end",
          contentIndex: 0,
          content: answer.content[0].text,
          partial: answer,
        });
        stream.push({ type: "done", reason: "stop", message: answer });
        stream.end(answer);
        try {
          await usage(purchase);
        } catch (e) {
          error(e);
        }
      } catch (e) {
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
