import { readFleet } from "./fleet.mjs";

const headers = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, OPTIONS",
  "cache-control": "no-store", "content-type": "application/json" };

// Select public capacity fields: hostname, errors, run IDs and full ownership
// envelopes belong to the operator fleet view, not the network map.
export function networkSnapshot(fleet, now) {
  const macs = fleet.map(mac => {
    const busy = new Set(mac.slots.filter(slot => slot.state === "busy").map(slot => slot.slot_id));
    const ready = new Set(mac.slots.filter(slot => slot.state === "ready" && !busy.has(slot.slot_id)).map(slot => slot.slot_id));
    return { publisher: mac.publisher, operator: mac.operator, region: mac.region ?? null,
      chip: typeof mac.hardware.chip === "string" ? mac.hardware.chip : "Unknown",
      ram_bytes: Number.isSafeInteger(mac.hardware.mem_bytes) ? mac.hardware.mem_bytes : null,
      slots: mac.config.max_guests, ready: ready.size, busy: busy.size,
      last_heartbeat: mac.updated_at, received_at: mac.received_at, online: mac.online, status: mac.status };
  });
  const totals = { macs_online: 0, total_slots: 0, ready_slots: 0, busy_slots: 0, utilization: 0 };
  for (const mac of macs.filter(mac => mac.online)) {
    totals.macs_online++; totals.total_slots += mac.slots;
    totals.ready_slots += mac.ready; totals.busy_slots += mac.busy;
  }
  totals.utilization = totals.total_slots ? totals.busy_slots / totals.total_slots : 0;
  return { updated_at: now, capacity: "reported", macs, totals };
}

export class Network {
  constructor({ read, now = () => Math.floor(Date.now() / 1000) }) {
    this.read = read; this.now = now; this.started_at = now(); this.samples = [];
  }
  async current() { const at = this.now(); return networkSnapshot(await this.read(at), at); }
  async sample() {
    const current = await this.current(), timestamp = Math.floor(current.updated_at / 60) * 60;
    const { ready_slots, busy_slots, macs_online, total_slots } = current.totals;
    const sample = { timestamp, ready_slots, busy_slots, macs_online, total_slots };
    this.samples = this.samples.filter(value => value.timestamp > timestamp - 86400 && value.timestamp !== timestamp);
    this.samples.push(sample);
  }
  async start() {
    await this.sample();
    // Sampling is independent of dashboard traffic. Unref allows normal runtime
    // shutdown; the broker owns this timer and never creates a host service.
    this.timer = setInterval(() => this.sample().catch(() => console.error("network history sample failed")), 60000);
    if (typeof Deno !== "undefined") Deno.unrefTimer(this.timer);
    else this.timer.unref?.();
    return this;
  }
  stop() { clearInterval(this.timer); }
  history() {
    const cutoff = this.now() - 86400;
    return { started_at: this.started_at, interval_seconds: 60, retention_seconds: 86400,
      lost_on_restart: true, samples: this.samples.filter(sample => sample.timestamp > cutoff) };
  }
  async response(req) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (req.method !== "GET") return new Response(JSON.stringify({ error: "method" }), { status: 405, headers });
    const value = new URL(req.url).pathname.endsWith("/history") ? this.history() : await this.current();
    return new Response(JSON.stringify(value), { headers });
  }
}

const monitors = new Map();
export function networkMonitor(path) {
  if (!monitors.has(path)) monitors.set(path, new Network({ read: at => readFleet(path, at) }).start().catch(error => {
    monitors.delete(path); throw error;
  }));
  return monitors.get(path);
}
