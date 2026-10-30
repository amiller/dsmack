import { applyOwnership, ownershipDomain, ownershipState, ownershipView } from "./ownership.mjs";
import { verifyMessage } from "../payments/schema.mjs";

export const canonicalFleet = value => JSON.stringify(value, (_, v) =>
  v && typeof v === "object" && !Array.isArray(v)
    ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);
const address = v => typeof v === "string" && /^0x[0-9a-f]{40}$/.test(v);
const need = (ok, message) => { if (!ok) throw Error(message); };
let memory = ownershipState();
let pending = Promise.resolve();

export function fleet(req, escrow, path, now = () => Math.floor(Date.now() / 1000)) {
  const result = pending.then(() => handle(req, escrow, path, now));
  pending = result.then(() => {}, () => {});
  return result;
}

async function readState(path) {
  if (!path) return memory;
  try { return ownershipState(JSON.parse(await Deno.readTextFile(path))); }
  catch (error) { if (!(error instanceof Deno.errors.NotFound)) throw error; return ownershipState(); }
}

export async function readFleet(path, now = Math.floor(Date.now() / 1000)) {
  const state = await readState(path);
  return Object.values(state.heartbeats).filter(mac => state.links[mac.publisher])
    .map(mac => visibleMac(state, mac, now));
}

function visibleMac(state, mac, at) {
    const online = at - mac.received_at < 60 && at - mac.updated_at < 60;
    const link = state.links[mac.publisher];
    const { payout: _legacyPayout, operator: _legacyOperator, ...heartbeat } = mac;
    return { ...heartbeat, operator: link.link.operator, kid: link.link.kid, link, capacity: "reported", online, status: online ? "online" : "offline" };
}

async function handle(req, escrow, path, now) {
  const headers = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type", "cache-control": "no-store", "content-type": "application/json" };
  const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers });
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
  if (!["GET", "POST"].includes(req.method)) return reply({ error: "method" }, 405);
  const state = await readState(path);
  const domain = ownershipDomain(escrow);
  const save = async () => {
    if (path) {
      await Deno.writeTextFile(path + ".tmp", JSON.stringify(state), { mode: 0o600 });
      using file = await Deno.open(path + ".tmp", { write: true }); await file.sync();
      await Deno.rename(path + ".tmp", path);
    } else memory = state;
  };
  const visible = mac => visibleMac(state, mac, now());
  const url = new URL(req.url), action = url.pathname.split("/").at(-1);
  if (req.method === "GET") {
    if (action === "ownership") return reply(ownershipView(state, domain, url));
    const operator = url.searchParams.get("operator")?.toLowerCase();
    if (operator && !address(operator)) return reply({ error: "operator address" }, 400);
    return reply(Object.values(state.heartbeats).filter(mac => state.links[mac.publisher] &&
      (!operator || state.links[mac.publisher].link.operator === operator)).map(visible));
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
    if (["link", "unlink", "revoke-provisioner"].includes(action)) {
      const result = applyOwnership(state, domain, action, body);
      await save();
      return reply(result);
    }
    const { signature, ...unsigned } = body;
    need(address(body.publisher), "publisher address");
    need(!("payout" in body) && !("operator" in body), "heartbeat cannot claim payout or operator");
    if (!state.links[body.publisher]) return reply({ error: "Mac ownership link required" }, 403);
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
    const prior = state.heartbeats[body.publisher];
    need(!prior || body.updated_at > prior.updated_at ||
      (body.updated_at === prior.updated_at && signature === prior.signature), "stale heartbeat");
    if (prior?.signature === signature) return reply(visible(prior));
    const next = { ...body, received_at: now() };
    state.heartbeats[body.publisher] = next;
    await save();
    return reply(visible(next));
  } catch (error) { return reply({ error: error.message }, 400); }
}
