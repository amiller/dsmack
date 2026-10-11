// Only a separately validated public copy of the controller's three fields.
const states = new Set(["ready", "unavailable", "unknown", "maintenance", "reconciliation-required", "approval-renewal-required"]);
export function view(value, now = Math.floor(Date.now() / 1000)) {
  const unknown = { claiming: "unknown", observation: "No fresh operator observation." };
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(",") !== "claiming_available,observed_at_unix,state"
      || !states.has(value.state) || typeof value.claiming_available !== "boolean"
      || !Number.isSafeInteger(value.observed_at_unix) || value.observed_at_unix < 0
      || !Number.isSafeInteger(now) || value.observed_at_unix > now + 30
      || now - value.observed_at_unix > 90
      || (value.claiming_available && value.state !== "ready")) return unknown;
  return { claiming: value.claiming_available ? "available" : "unavailable",
    observation: `Operator reports ${value.state} · observed ${new Date(value.observed_at_unix * 1000).toISOString()}.` };
}

export async function readFeed(fetcher = fetch) {
  const response = await fetcher(new URL("health.json", import.meta.url), {
    credentials: "omit", cache: "no-store", redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error("Status unavailable");
  const reader = response.body.getReader();
  const chunks = []; let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      bytes += value.byteLength;
      if (bytes > 4096) throw new Error("Status unavailable");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const joined = new Uint8Array(bytes); let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(joined));
}

if (typeof document !== "undefined") {
  let observation = null;
  const draw = () => {
    const current = view(observation);
    document.getElementById("claiming").textContent = `Claim readiness: ${current.claiming}`;
    document.getElementById("observation").textContent = current.observation;
  };
  const poll = async () => {
    try { observation = await readFeed(); } catch { observation = null; }
    draw();
  };
  draw(); void poll(); setInterval(poll, 30000); setInterval(draw, 1000);
}
