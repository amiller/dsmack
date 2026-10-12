// Relay budget observation, not a reservation or proof this device is eligible.
export const capacityEndpoint = "https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft/status";
const registry = "0xd4b33c83576a6049d29c6b849ec73491e52781a0";
const unknown = () => ({status: "unknown", message: "No fresh public joining capacity observation. Check the joining instructions before opening the app.", deadline: "Unknown"});
const stamp = v => typeof v === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(v) ? Date.parse(v) / 1000 : NaN;
export function capacityView(value, now = Date.now() / 1000) {
  if (!value || value.chainId !== 84532 || typeof value.registry !== "string" || value.registry.toLowerCase() !== registry
      || value.protocolVersion !== 2 || typeof value.sponsorWritesPaused !== "boolean" || !Number.isFinite(now)) return unknown();
  const observed = stamp(value.generatedAt), b = value.sponsorBudget;
  if (!Number.isFinite(observed) || observed > now + 15 || now - observed > 90 || !b
      || !["qualification", "public-pilot"].includes(b.mode) || typeof b.expired !== "boolean"
      || ![0, 1].includes(b.additionalPublicEnrollmentCapacity)) return unknown();
  const expiry = stamp(b.expiresAt);
  if (!Number.isFinite(expiry) || (b.mode === "qualification" && b.additionalPublicEnrollmentCapacity !== 0)
      || (b.mode === "public-pilot" && typeof b.exhausted !== "boolean")
      || ((b.expired || b.exhausted) && b.additionalPublicEnrollmentCapacity !== 0)) return unknown();
  const deadline = new Date(expiry * 1000).toISOString();
  if (value.sponsorWritesPaused) return {status: "unavailable", message: "Joining sponsorship is paused.", deadline};
  if (b.expired || now >= expiry) return {status: "unavailable", message: "The public joining sponsorship window has expired.", deadline};
  if (b.mode !== "public-pilot" || b.exhausted || b.additionalPublicEnrollmentCapacity === 0)
    return {status: "unavailable", message: "No additional public enrollment slot is advertised. Existing participants may have a separate remaining allowance.", deadline};
  return {status: "bounded slot advertised", message: "The relay advertises at most one additional public enrollment. It is first-come, not reserved for your invitation. Admission, current fees and network readiness can still prevent joining.", deadline};
}
export async function readCapacity(fetcher = fetch) {
  const response = await fetcher(capacityEndpoint, {credentials: "omit", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(5000)});
  if (!response.ok) throw Error("Capacity unavailable");
  const reader = response.body.getReader(), chunks = []; let length = 0;
  try { for (;;) {const {done, value} = await reader.read(); if (done) break; length += value.byteLength;
    if (length > 32768) throw Error("Capacity too large"); chunks.push(value);} }
  finally {await reader.cancel();}
  const data = new Uint8Array(length); let offset = 0; for (const chunk of chunks) {data.set(chunk, offset); offset += chunk.length;}
  return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(data));
}
export function drawCapacity(value, doc = document, now = Date.now() / 1000) {
  const view = capacityView(value, now);
  for (const [id, text] of [["capacity-state", view.status], ["capacity-message", view.message], ["capacity-deadline", view.deadline]]) doc.getElementById(id).textContent = text;
}
