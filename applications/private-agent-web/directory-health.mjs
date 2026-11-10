#!/usr/bin/env -S deno run --allow-net --allow-read --allow-write --allow-run --allow-env
// Run the page's directory checks and notify only when outage state changes.
import { discoverChainNodes } from "./chain-directory.mjs";

async function readState(path) {
  try { return JSON.parse(await Deno.readTextFile(path)); }
  catch (error) { if (!(error instanceof Deno.errors.NotFound)) throw error; return null; }
}

async function saveState(path, value) {
  await Deno.writeTextFile(path + ".tmp", JSON.stringify(value) + "\n", { mode: 0o600 });
  await Deno.rename(path + ".tmp", path);
}

export async function pingHeartbeat(url, fetcher = fetch) {
  const response = await fetcher(url, { method: "POST", redirect: "error", signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw Error(`Heartbeat HTTP ${response.status}`);
}

export async function checkDirectory(url, { fetcher = fetch } = {}) {
  const response = await fetcher(url, { redirect: "error", signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw Error(`config.json HTTP ${response.status}`);
  const config = await response.json();
  const directory = await discoverChainNodes({ config, fetcher });
  if (!directory.nodes.length) throw Error("No signed guest entries");
  return { nodes: directory.nodes.length, blockNumber: directory.blockNumber, blockHash: directory.blockHash };
}

export async function monitor({ target, url, state, notify, check = checkDirectory, heartbeat }) {
  const prior = await readState(state);
  let result;
  try { result = { ok: true, ...await check(url) }; }
  catch (error) { result = { ok: false, error: error.message }; }
  if ((!result.ok && prior?.ok !== false) || (result.ok && prior?.ok === false)) {
    const message = `Dsmack ${target} directory ${result.ok ? "RECOVERED" : "FAILED"}: ${url}\n${result.ok ? `${result.nodes} signed guest(s), block ${result.blockNumber}` : result.error}`;
    await notify(message);
    result.notification = result.ok ? "recovery" : "failure";
  }
  await saveState(state, { ...result, checkedAt: new Date().toISOString() });
  if (heartbeat) await pingHeartbeat(heartbeat);
  console.log(JSON.stringify({ target, url, ...result }));
  return result;
}

export async function checkCapacity(url, { fetcher = fetch } = {}) {
  const response = await fetcher(url, { redirect: "error", signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw Error(`/network HTTP ${response.status}`);
  const { totals } = await response.json();
  if (![totals?.ready_slots, totals?.macs_online].every(n => Number.isSafeInteger(n) && n >= 0)) {
    throw Error("/network has invalid ready_slots or macs_online");
  }
  return { readySlots: totals.ready_slots, macsOnline: totals.macs_online };
}

export async function monitorCapacity({ target, url, state, notify, check = checkCapacity,
  now = () => Math.floor(Date.now() / 1000), heartbeat }) {
  const prior = await readState(state), at = now();
  let result;
  try {
    const counts = await check(url);
    result = { ok: counts.readySlots > 0 && counts.macsOnline > 0, ...counts };
  } catch (error) { result = { ok: false, error: error.message }; }
  // Missing a minute breaks the observed streak; two isolated zero readings
  // must not be mistaken for three minutes of continuously empty capacity.
  const contiguous = prior && at >= prior.lastSampleAt && at - prior.lastSampleAt <= 90;
  result.badSince = result.ok ? null : contiguous && prior.badSince !== null ? prior.badSince : at;
  result.alerted = prior?.alerted ?? false;
  const failing = !result.ok && at - result.badSince >= 180;
  // Preserve this observation even if delivery fails, so the next scheduled
  // retry keeps the observed outage rather than restarting its three minutes.
  await saveState(state, { ...result, lastSampleAt: at });
  if ((failing && !result.alerted) || (result.ok && result.alerted)) {
    await notify(`Dsmack ${target} capacity ${result.ok ? "RECOVERED" : "FAILED"}: ${url}\n` +
      (result.error || `ready_slots=${result.readySlots}, macs_online=${result.macsOnline}`) +
      (result.ok ? "" : "; unavailable for at least 3 consecutive minutes"));
    result.alerted = !result.ok;
    result.notification = result.ok ? "recovery" : "failure";
  }
  await saveState(state, { ...result, lastSampleAt: at });
  // A completed observation and notification is a live monitor, including a
  // correctly reported target outage. Exceptions above do not send a heartbeat.
  if (heartbeat) await pingHeartbeat(heartbeat);
  console.log(JSON.stringify({ target, url, ...result }));
  return result;
}

if (import.meta.main) {
  const [kind, target, url, state, notifier, heartbeat] = Deno.args;
  if (!heartbeat || !["directory", "capacity"].includes(kind)) throw Error("usage: directory-health.mjs directory|capacity TARGET URL STATE_FILE NOTIFY_SCRIPT HEARTBEAT_URL");
  const run = kind === "directory" ? monitor : monitorCapacity;
  const result = await run({ target, url, state, heartbeat, notify: async message => {
    const child = new Deno.Command(notifier, { args: [message], stdout: "null", stderr: "inherit" }).spawn();
    const status = await child.status;
    if (!status.success) throw Error(`Notification failed with exit ${status.code}; outage state retained`);
  } });
  if (!result.ok) Deno.exit(1);
}
