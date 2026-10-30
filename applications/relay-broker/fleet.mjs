import { verifyMessage } from "../payments/schema.mjs";

export const canonicalFleet = value => JSON.stringify(value, (_, v) =>
  v && typeof v === "object" && !Array.isArray(v)
    ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);
const address = v => typeof v === "string" && /^0x[0-9a-f]{40}$/.test(v);
const need = (ok, message) => { if (!ok) throw Error(message); };
const memory = {};
let pending = Promise.resolve();

export function fleet(req, publishers = {}, path, now = () => Math.floor(Date.now() / 1000)) {
  const result = pending.then(() => handle(req, publishers, path, now));
  pending = result.then(() => {}, () => {});
  return result;
}

export async function readFleet(path, now = Math.floor(Date.now() / 1000)) {
  const state = await readState(path);
  return Object.values(state).map(mac => {
    const online = now - mac.received_at < 60 && now - mac.updated_at < 60;
    return { ...mac, online, status: online ? "online" : "offline" };
  });
}

async function readState(path) {
  if (!path) return memory;
  try { return JSON.parse(await Deno.readTextFile(path)); }
  catch (error) { if (!(error instanceof Deno.errors.NotFound)) throw error; return {}; }
}

async function handle(req, publishers, path, now) {
  const headers = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type", "cache-control": "no-store", "content-type": "application/json" };
  const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers });
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
  if (!["GET", "POST"].includes(req.method)) return reply({ error: "method" }, 405);
  const state = await readState(path);
  const visible = mac => ({ ...mac,
    online: now() - mac.received_at < 60 && now() - mac.updated_at < 60,
    status: now() - mac.received_at < 60 && now() - mac.updated_at < 60 ? "online" : "offline" });
  if (req.method === "GET") {
    const payout = new URL(req.url).searchParams.get("payout")?.toLowerCase();
    if (payout && !address(payout)) return reply({ error: "payout address" }, 400);
    return reply(Object.values(state).filter(mac => !payout || mac.payout === payout).map(visible));
  }
  try {
    const chunks = []; let size = 0;
    for await (const bytes of req.body ?? []) {
      size += bytes.length;
      if (size > 256 * 1024) return reply({ error: "body limit" }, 413);
      chunks.push(bytes);
    }
    const raw = new Uint8Array(size); let at = 0;
    for (const bytes of chunks) { raw.set(bytes, at); at += bytes.length; }
    const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    need(body && typeof body === "object" && !Array.isArray(body), "heartbeat object");
    const { signature, ...unsigned } = body;
    need(address(body.publisher) && address(body.payout), "publisher/payout address");
    const payout = publishers[body.publisher]?.toLowerCase();
    if (!payout || payout !== body.payout) return reply({ error: "publisher/payout not configured" }, 403);
    need(verifyMessage("dsmack-fleet/1\n" + canonicalFleet(unsigned), signature).toLowerCase() === body.publisher, "publisher signature");
    need(Number.isSafeInteger(body.updated_at) && Math.abs(now() - body.updated_at) <= 30, "heartbeat timestamp");
    need(body.config && Number.isSafeInteger(body.config.max_guests) && body.config.max_guests > 0,
      "capacity config");
    need(body.hardware && typeof body.hardware.name === "string" && body.hardware.name.length <= 256, "Mac hardware");
    need(typeof body.version === "string" && body.version.length <= 128, "pool version");
    need(Array.isArray(body.slots) && body.slots.length <= 64, "at most 64 guest states");
    for (const slot of body.slots) {
      need(Number.isSafeInteger(slot.slot_id) && slot.slot_id >= 0 && slot.slot_id < body.config.max_guests,
        "slot id");
      need(["launching", "attesting", "ready", "busy", "draining", "failed"].includes(slot.state), "slot state");
    }
    need(Array.isArray(body.errors) && body.errors.length <= 10, "at most ten errors");
    need(Array.isArray(body.classes) && body.classes.length <= 64 && body.classes.every(v => /^0x[0-9a-fA-F]{64}$/.test(v)), "node classes");
    const prior = state[body.publisher];
    need(!prior || body.updated_at > prior.updated_at ||
      (body.updated_at === prior.updated_at && signature === prior.signature), "stale heartbeat");
    if (prior?.signature === signature) return reply(visible(prior));
    const next = { ...body, received_at: now() };
    const saved = { ...state, [body.publisher]: next };
    if (path) {
      await Deno.writeTextFile(path + ".tmp", JSON.stringify(saved), { mode: 0o600 });
      await Deno.rename(path + ".tmp", path);
    } else Object.assign(memory, saved);
    return reply(visible(next));
  } catch (error) { return reply({ error: error.message }, 400); }
}
