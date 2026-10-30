import { formatEther, getAddress } from "../payments/schema.mjs";
import { Earnings } from "./chain.mjs";
import { summarize } from "./model.mjs";

const $ = id => document.getElementById(id);
const el = (tag, text, cls) => { const node = document.createElement(tag); if (text != null) node.textContent = text; if (cls) node.className = cls; return node; };
const json = value => JSON.stringify(value, (_, v) => typeof v === "bigint" ? v.toString() : v, 2);
const short = value => value ? `${value.slice(0, 10)}…${value.slice(-6)}` : "—";
const eth = value => formatEther(value);
const when = seconds => seconds ? new Date(seconds * 1000).toLocaleString() : "—";
const uptime = seconds => { const elapsed = Math.max(0, Math.floor(Date.now() / 1000 - seconds)); return elapsed >= 3600 ? `${Math.floor(elapsed / 3600)}h ${Math.floor(elapsed % 3600 / 60)}m` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`; };
let config, earnings, operator, macs = [], events = [], snapshot, selected, chainAt = 0, refreshing = false;
let downloads = [];
function error(message) { $("error").hidden = !message; $("error").textContent = message || ""; }
function download(value, label, filename) {
  const a = el("a", label); a.href = URL.createObjectURL(new Blob([json(value)], { type: "application/json" })); a.download = filename; downloads.push(a.href); return a;
}
function external(url, label) { const a = el("a", label); a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; return a; }
function status(mac) { return mac.online && Date.now() / 1000 - mac.updated_at < 60 ? mac.status : "offline"; }
function redraw() {
  if (!operator) return;
  snapshot = summarize(events, macs, operator);
  $("earned-all").textContent = chainAt ? eth(snapshot.all) : "—";
  $("earned-week").textContent = chainAt ? eth(snapshot.week) : "—";
  $("guests").textContent = `${snapshot.macs.reduce((sum, m) => sum + (status(m) === "offline" ? 0 : m.running), 0)} / ${snapshot.macs.reduce((sum, m) => sum + m.config.max_guests, 0)}`;
  $("mac-count").textContent = `${snapshot.macs.length} Mac${snapshot.macs.length === 1 ? "" : "s"} · ${snapshot.macs.filter(m => status(m) !== "offline").length} online`;
  $("chart").replaceChildren();
  const max = snapshot.daily.reduce((sum, d) => d.earned > sum ? d.earned : sum, 1n);
  for (const day of snapshot.daily) {
    const column = el("div", null, "day"), bar = el("div", null, "bar");
    bar.style.height = `${Number(day.earned * 10000n / max) / 100 * 1.05}px`;
    column.append(el("span", chainAt ? eth(day.earned) : "—", "value"), bar, el("span", new Date(day.day * 86400000).toLocaleDateString(undefined, { weekday: "short", timeZone: "UTC" })));
    $("chart").append(column);
  }
  const search = $("search").value.toLowerCase();
  const visible = snapshot.macs.filter(m => (!$("online").checked || status(m) !== "offline") && [m.hardware.name, m.hardware.model, m.hardware.chip, m.publisher].join(" ").toLowerCase().includes(search));
  $("macs").replaceChildren();
  for (const mac of visible) {
    const row = el("tr"), name = el("td"), button = el("button", mac.hardware.name, "mac-name");
    button.dataset.publisher = mac.publisher;
    button.onclick = () => { selected = mac.publisher; showDetail(); $("detail").scrollIntoView({ behavior: "smooth", block: "start" }); };
    name.append(button, el("span", mac.hardware.model, "sub"));
    const chip = el("td", `${mac.hardware.chip} · reported`); chip.append(el("span", `${Math.round(mac.hardware.mem_bytes / 2 ** 30)} GiB · ${mac.hardware.cores} cores`, "sub"));
    const state = el("td"); state.append(el("span", status(mac), `pill ${status(mac)}`));
    const lastError = [...mac.errors].reverse()[0]?.error || mac.slots.find(s => s.last_error)?.last_error || "—";
    const last = el("td", lastError, "last-error"); last.title = lastError;
    row.append(name, chip, el("td", `${status(mac) === "offline" ? 0 : mac.running} / ${mac.config.max_guests}`), state, el("td", chainAt ? mac.chain.jobs24h : "—"), el("td", chainAt ? `${eth(mac.chain.week)} ETH` : "—"), last);
    $("macs").append(row);
  }
  if (!visible.length) { const row = el("tr"), cell = el("td", snapshot.macs.length ? "No Macs match your filters." : "No Macs are linked to this operator.", "muted"); cell.colSpan = 7; row.append(cell); $("macs").append(row); }
  showDetail();
}
function showDetail() {
  downloads.forEach(url => URL.revokeObjectURL(url)); downloads = [];
  const mac = snapshot?.macs.find(m => m.publisher === selected);
  $("detail").hidden = !mac; if (!mac) return;
  const head = el("div", null, "panel-head"), title = el("div"), close = el("button", "Close", "secondary");
  title.append(el("h2", mac.hardware.name), el("p", `${mac.hardware.chip} · ${status(mac)}`, "muted"));
  close.onclick = () => { selected = null; showDetail(); };
  head.append(title, close);
  const body = el("div", null, "detail-body"), meta = el("div", null, "detail-meta");
  meta.append(el("span", `Last heartbeat ${when(mac.updated_at)}`), el("span", `Pool ${short(mac.version)}`), el("span", `Publisher ${short(mac.publisher)}`), el("span", `Operator ${short(mac.operator)}`), el("span", `Link nonce ${mac.link?.link?.nonce ?? "—"}`), el("span", "Capacity reported by the Mac"));
  body.append(meta, el("h3", "Guest slots", "section-title"));
  const slots = el("div", null, "slot-grid");
  for (const slot of mac.slots) {
    const card = el("article", null, "slot"), top = el("div", null, "row");
    top.append(el("strong", `Slot ${slot.slot_id}`), el("span", slot.state, `pill ${slot.state}`));
    card.append(top, el("p", slot.started_at ? `Uptime ${uptime(slot.started_at)} · ${slot.jobs_served} jobs served` : "Waiting to launch"));
    if (slot.run_id) card.append(el("p", `Run ${slot.run_id}`, "mono"));
    if (slot.relay_peer) card.append(el("p", `Peer ${slot.relay_peer}`, "mono"));
    if (slot.attestation) card.append(download(slot.attestation, "View attestation ↗", `attestation-slot-${slot.slot_id}-${slot.run_id || "waiting"}.json`));
    if (slot.last_error) card.append(el("p", slot.last_error, "error"));
    slots.append(card);
  }
  body.append(slots, el("h3", "Recent settled jobs", "section-title"));
  if (!chainAt) body.append(el("p", "Reading escrow settlements…", "muted"));
  else if (!mac.chain.jobs.length) body.append(el("p", "No settled jobs for this Mac’s node classes.", "muted"));
  else {
    const table = el("table"), thead = el("thead"), tr = el("tr");
    ["Purchase", "Settled", "Guest seconds", "Receipt"].forEach(t => tr.append(el("th", t))); thead.append(tr); table.append(thead);
    const tbody = el("tbody");
    for (const job of mac.chain.jobs.slice(0, 20)) {
      const row = el("tr"), purchase = el("td"), receipt = el("td");
      purchase.append(external(`https://sepolia.basescan.org/tx/${job.transactionHash}`, `#${job.purchaseId} ↗`));
      receipt.append(download({ ...job.envelope, transactionHash: job.transactionHash, blockNumber: job.blockNumber }, "Signed receipt ↗", `receipt-${job.purchaseId}.json`));
      row.append(purchase, el("td", when(job.timestamp)), el("td", `${job.used}${job.finalReceipt ? " · final" : ""}`), receipt); tbody.append(row);
    }
    table.append(tbody); const wrap = el("div", null, "table-wrap"); wrap.append(table); body.append(wrap);
  }
  body.append(el("h3", "Last ten errors", "section-title"));
  if (!mac.errors.length) body.append(el("p", "No errors reported.", "muted"));
  for (const item of mac.errors.slice(-10).reverse()) {
    const div = el("article", null, "error-item"); div.append(el("small", `${when(item.at)} · slot ${item.slot_id}`), el("pre", json(item))); body.append(div);
  }
  body.append(el("h3", "Operator config", "section-title"), el("pre", json(mac.config)));
  $("detail").replaceChildren(head, body);
}
async function refresh(force = false) {
  if (!operator || refreshing) return;
  refreshing = true;
  try {
    error(null);
    const response = await fetch(`${config.broker}/fleet?operator=${encodeURIComponent(operator)}`, { cache: "no-store" });
    if (!response.ok) throw Error(`Fleet heartbeat request failed (${response.status})`);
    const fleet = await response.json();
    if (!Array.isArray(fleet)) throw Error("Broker returned an invalid fleet response");
    macs = fleet.map(mac => ({ ...mac, classes: [...mac.classes, ...(config.classesByPublisher?.[mac.publisher.toLowerCase()] || [])] }));
    redraw();
    if (force || Date.now() - chainAt > 60000) {
      events = await earnings.read(text => $("status").textContent = text);
      chainAt = Date.now(); redraw();
    }
    $("status").textContent = `Updated ${new Date().toLocaleTimeString()} · earnings through finalized block ${earnings.finalizedBlock?.toLocaleString() || "pending"}`;
    document.documentElement.dataset.loaded = "true";
  } catch (e) { error(e.message); $("status").textContent = "Refresh failed. Retrying in 15 seconds."; }
  finally { refreshing = false; }
}
async function choose(address) {
  operator = getAddress(address); const url = new URL(location.href); url.searchParams.set("operator", operator); history.replaceState(null, "", url); $("wallet").textContent = operator; $("address").value = operator;
  selected = null; document.documentElement.dataset.loaded = "false";
  await refresh(true);
}
$("connect").onclick = async () => {
  try {
    if (!window.ethereum?.request) throw Error("Open this page in your wallet’s browser, or use View an operator address.");
    const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
    if (!accounts[0]) throw Error("The wallet returned no operator address");
    await choose(accounts[0]);
  } catch (e) { error(e.message); }
};
$("address-form").onsubmit = async event => { event.preventDefault(); try { await choose($("address").value.trim()); } catch (e) { error(e.message); } };
$("search").oninput = redraw; $("online").onchange = redraw;
window.ethereum?.on?.("accountsChanged", accounts => { if (accounts[0]) choose(accounts[0]).catch(e => error(e.message)); else { operator = null; location.reload(); } });
try {
  if (/^\/ip[fn]s\//.test(location.pathname)) throw Error("Open the page on its IPFS subdomain gateway URL.");
  const response = await fetch("./config.json"); if (!response.ok) throw Error("Unable to read published fleet configuration");
  config = await response.json(); earnings = new Earnings(config);
  $("escrow").href = `https://sepolia.basescan.org/address/${config.escrow}`;
  document.documentElement.dataset.ready = "true";
  setInterval(() => refresh(), 15000);
  const initial = new URL(location.href).searchParams.get("operator");
  if (initial) await choose(initial);
} catch (e) { error(e.message); $("connect").disabled = true; }
