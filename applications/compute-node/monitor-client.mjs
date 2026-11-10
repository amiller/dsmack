export const MONITOR_CODES = Object.freeze(["PG2_PROMPT_ATTACK", "MONITOR_CONTEXT_REQUIRED", "MONITOR_UNAVAILABLE"]);
export function failedMonitorResult(code) {
  if (!MONITOR_CODES.includes(code)) throw new Error("Monitor code outside enum");
  return { isError: true, content: [{ type: "text", text: JSON.stringify({ code }) }] };
}

export class MonitorSession {
  constructor({ enabled = JSON.parse(process.env.DSMACK_MONITOR_POLICY || '{"name":"none"}').name === "baseline-pg2", check = gatewayCheck } = {}) {
    this.enabled = enabled;
    this.check = check;
  }
  async preflight(prompt) {
    if (!this.enabled || this.started) return;
    if (typeof prompt !== "string") throw new Error("First user prompt required");
    this.pending = await this.check(prompt);
    this.started = true;
  }
  async tool(name, args, response) {
    if (!this.enabled) return;
    // Repository import precedes inference. Scan its actual tool arguments too.
    if (this.started && typeof response !== "string") return "MONITOR_CONTEXT_REQUIRED";
    const first = this.pending;
    this.pending = undefined;
    if (first) return first;
    return this.check(JSON.stringify({ response: response ?? "", tool: { name, arguments: args } }));
  }
}

async function gatewayCheck(text) {
  const response = await fetch("http://127.0.0.1:18080/_dsmack/monitor", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }), signal: AbortSignal.timeout(125000),
  });
  if (!response.ok) throw new Error("MONITOR_UNAVAILABLE");
  const { code } = await response.json();
  if (code !== "" && !MONITOR_CODES.includes(code)) throw new Error("Monitor code outside enum");
  return code || undefined;
}
