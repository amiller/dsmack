import "@mariozechner/mini-lit/dist/CodeBlock.js";
import "@pi-components/components/ConsoleBlock.js";
import { html } from "lit";
import { SquareTerminal } from "lucide";
import { registerToolRenderer } from "@pi-components/tools/index.js";
import { renderHeader } from "@pi-components/tools/renderer-registry.js";

// Pi's native bash renderer uses "Running command..." for every state. Keep
// its inline console presentation and distinguish settled results explicitly.
registerToolRenderer("bash", {
  render(params, result) {
    const completed = result && !result.isPartial;
    const state = completed ? (result.isError ? "error" : "complete") : "inprogress";
    const output = result?.content?.filter(c => c.type === "text").map(c => c.text).join("\n") || "";
    const command = params?.command;
    const label = completed ? (result.isError ? "bash · failed" : "bash · completed") : "bash · running";
    return { isCustom: false, content: html`<div class="space-y-3">
      ${renderHeader(state, SquareTerminal, label)}
      ${command || output ? html`<console-block .content=${[command ? `> ${command}` : "", output].filter(Boolean).join("\n\n")} .variant=${result?.isError ? "error" : "default"}></console-block>` : ""}
    </div>` };
  },
});

// AgentInterface 0.75 observes assistant deltas, but does not yet observe the
// 1.4 tool execution events. Feed genuine progress into its native streaming
// message component; the transcript remains owned by the Agent.
export function renderToolProgress(chat, agent, event) {
  if (!event.type.startsWith("tool_execution_")) return;
  const container = chat.querySelector("streaming-message-container");
  const assistant = agent.state.messages.findLast(message => message.role === "assistant" &&
    message.content.some(part => part.type === "toolCall" && part.id === event.toolCallId));
  if (!container || !assistant) return;
  const result = event.type === "tool_execution_update" ? event.partialResult :
    event.type === "tool_execution_end" ? event.result : undefined;
  container.toolResultsById = new Map(result ? [[event.toolCallId, { ...result, isError: !!event.isError, isPartial: event.type === "tool_execution_update" }]] : []);
  container.isStreaming = true;
  container.setMessage({ ...assistant, content: assistant.content.filter(part => part.type === "toolCall" && part.id === event.toolCallId) }, true);
}
