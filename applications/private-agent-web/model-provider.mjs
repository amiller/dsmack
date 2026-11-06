import { getCurrentTools } from "@earendil-works/pi-ai";
import { lazyStream } from "@earendil-works/pi-ai/api/lazy";
import { anthropicMessagesApi } from "@earendil-works/pi-ai/api/anthropic-messages.lazy";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { ANTHROPIC_MODELS } from "@earendil-works/pi-ai/providers/anthropic.models";
import { replyFailure } from "./reply-recovery.mjs";

const apis = { "anthropic-messages": anthropicMessagesApi(), "openai-completions": openAICompletionsApi() };
export const defaultAnthropicModel = Object.keys(ANTHROPIC_MODELS).find(id => id.startsWith("claude-sonnet-4-6"));
const selectedKey = "chat.provider";

export function providerLabel(model) {
  return model.provider === "anthropic" ? "Anthropic" : new URL(model.baseUrl).host;
}
export function modelPrivacy(model) {
  return model.provider === "near"
    ? "Model calls remain encrypted from the browser to the NEAR model TEE."
    : `Model calls go directly from this browser to ${providerLabel(model)}, which sees the conversation. Model tokens use your provider key; guest seconds use chat credit.`;
}
export function modelBadge(model) {
  return model.provider === "near" ? model.id === "unavailable" ? "NEAR TEE model · unavailable" : model.id
    : `${model.id} · ${providerLabel(model)} sees the conversation`;
}
export function directModel(provider, id, baseUrl) {
  if (!id.trim()) throw Error("Enter a model ID.");
  if (provider === "anthropic") {
    const model = ANTHROPIC_MODELS[id];
    if (!model) throw Error("Choose an Anthropic model from the list.");
    return { ...model, provider: "anthropic", baseUrl: "https://api.anthropic.com" };
  }
  const url = new URL(baseUrl);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash)
    throw Error("Use an HTTPS API base URL without credentials, query or fragment.");
  baseUrl = url.href.replace(/\/$/, "");
  return { id: id.trim(), name: id.trim(), provider: "openai-compatible:" + baseUrl,
    api: "openai-completions", baseUrl, reasoning: false, input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 128000, maxTokens: 4096,
    compat: { supportsDeveloperRole: false, maxTokensField: "max_tokens" },
  };
}
export const anthropicModels = Object.keys(ANTHROPIC_MODELS);
export async function loadProvider(storage) {
  const id = await storage.settings.get(selectedKey);
  return id ? (await storage.customProviders.get(id)).models[0] : undefined;
}
export async function saveProvider(storage, model, key) {
  if (model) {
    await storage.providerKeys.set(model.provider, key);
    await storage.customProviders.set({ id: model.provider, name: providerLabel(model), type: model.api,
      baseUrl: model.baseUrl, models: [model] });
    await storage.settings.set(selectedKey, model.provider);
  } else await storage.settings.delete(selectedKey);
}
// A real, tiny Pi request checks the browser's CORS path and authentication
// before enabling an endpoint. Only the connection-test prompt is sent.
export async function checkProvider(model, apiKey) {
  if (!apiKey.trim()) throw Error("Paste your provider API key.");
  const result = await apis[model.api].streamSimple(model, { messages: [
    { role: "user", content: "Reply OK.", timestamp: Date.now() },
  ] }, { apiKey, maxTokens: 16, signal: AbortSignal.timeout(30000) }).result();
  if (["error", "aborted"].includes(result.stopReason))
    throw Error("Browser connection failed. Check the key, model and endpoint CORS: " + result.errorMessage);
}
export function providerStream({ near, preflight, systemPrompt, startedAt }) {
  return (model, context, options) => {
    if (model.provider === "near") return near(model, context, options);
    return lazyStream(model, async () => {
      await preflight(context, options.signal);
      const runtime = `Model: ${model.id}\nProvider: ${providerLabel(model)}\nConversation started: ${startedAt}`;
      return apis[model.api].streamSimple(model, { messages: [
        { role: "system", content: systemPrompt({ model, runtime }), toolsAdded: getCurrentTools(context.messages), timestamp: 0 },
        ...context.messages.filter(message => message.role !== "system"),
      ] }, options);
    }, { onResult: answer => {
      if (["error", "aborted"].includes(answer.stopReason)) answer.failure = replyFailure(
        answer.stopReason === "aborted" ? new DOMException("Request aborted", "AbortError") : Error(answer.errorMessage),
        { partial: answer.content.some(part => part.type === "text" && part.text) });
    } });
  };
}
