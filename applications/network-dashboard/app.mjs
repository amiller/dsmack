import { NetworkChain } from "./chain.mjs";

const $ = id => document.getElementById(id);
const node = (tag, text, cls) => { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; };
const svg = (tag, attrs = {}, text) => { const n = document.createElementNS("http://www.w3.org/2000/svg", tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); if (text != null) n.textContent = text; return n; };
const format = value => Number(value).toLocaleString();
const stat = (name, value) => document.querySelector(`[data-stat="${name}"]`).textContent = value;
const project = ([lon, lat]) => [(lon + 180) * 1000 / 360, (85 - lat) * 490 / 170];
const point = p => project(p).map(n => n.toFixed(1)).join(",");
// Coarse, hand-drawn continental silhouettes; location markers use only opted-in coordinates.
const land = [
  [[-168,71],[-155,71],[-150,68],[-138,69],[-128,70],[-120,75],[-105,78],[-93,76],[-84,72],[-80,69],[-90,65],[-78,61],[-65,61],[-56,54],[-60,47],[-68,44],[-76,40],[-80,33],[-81,25],[-86,29],[-91,29],[-97,25],[-99,20],[-91,18],[-85,15],[-83,9],[-78,9],[-80,7],[-86,11],[-94,16],[-103,20],[-109,24],[-114,30],[-117,33],[-124,42],[-129,51],[-139,59],[-149,60],[-158,57],[-165,61],[-168,64]],
  [[-81,12],[-72,12],[-61,8],[-53,4],[-48,-3],[-35,-6],[-40,-18],[-47,-25],[-53,-33],[-61,-40],[-67,-55],[-73,-52],[-75,-40],[-71,-29],[-73,-18],[-80,-5],[-78,3]],
  [[-53,60],[-43,59],[-29,67],[-22,76],[-36,83],[-48,83],[-61,77],[-64,69]],
  [[-10,36],[-9,43],[-1,44],[-5,49],[5,54],[8,58],[5,62],[14,70],[27,71],[32,66],[41,67],[49,70],[59,69],[69,73],[89,76],[108,76],[119,73],[128,72],[139,72],[150,70],[165,65],[179,66],[179,58],[166,60],[157,57],[161,51],[155,50],[146,55],[139,49],[141,43],[134,35],[123,39],[119,31],[121,24],[115,23],[109,19],[105,9],[100,4],[97,7],[98,17],[92,22],[88,22],[80,7],[73,19],[67,25],[59,25],[56,18],[49,12],[43,13],[42,20],[35,28],[34,32],[30,36],[27,40],[20,40],[18,44],[13,45],[16,40],[13,37],[7,43],[3,42],[0,39]],
  [[-17,34],[-7,36],[10,37],[20,33],[31,31],[34,25],[39,16],[44,12],[51,12],[49,6],[43,-1],[41,-11],[35,-18],[32,-28],[26,-34],[18,-35],[13,-25],[12,-14],[9,-4],[5,5],[-3,5],[-8,4],[-15,11],[-17,21]],
  [[113,-22],[115,-15],[125,-14],[131,-11],[136,-12],[138,-16],[143,-11],[147,-19],[153,-26],[150,-35],[140,-39],[132,-33],[124,-33],[115,-35]],
  [[47,-13],[51,-16],[49,-25],[45,-26],[44,-19]], [[130,31],[134,34],[139,36],[141,40],[143,44],[146,44],[144,39],[141,35],[136,33]],
  [[-8,50],[-5,51],[-4,56],[-6,58],[-3,59],[0,53]], [[-10,51],[-6,52],[-7,55],[-10,55]], [[-24,64],[-14,64],[-13,67],[-22,67]],
  [[95,5],[104,-1],[106,-6],[102,-5]], [[106,-6],[115,-8],[119,-8],[116,-6]], [[109,7],[118,7],[119,-4],[113,-4]], [[120,19],[124,18],[126,8],[122,5],[120,12]], [[131,-2],[140,-2],[151,-6],[146,-10],[137,-8]],
  [[173,-34],[178,-39],[176,-42],[171,-45],[166,-46],[170,-40]], [[-84,23],[-75,21],[-74,19],[-82,21]], [[-73,20],[-66,18],[-71,18]]
];
for (const polygon of land) $("continents").append(svg("polygon", { points: polygon.map(point).join(" "), class: "continent" }));

let config, chain, refreshing = false, chainRefreshing = false, network, history, chainResult, chainReadAt = 0;
window.__networkDashboard = Object.freeze({ network: null, history: null, chain: null });
function snapshot() { window.__networkDashboard = Object.freeze({ network, history, chain: chainResult }); }
function callout(mac) {
  const box = $("map-callout"); box.replaceChildren();
  box.append(node("b", mac.region.name), node("span", `${mac.online ? "Online" : "Offline"} · ${mac.slots} guest slots · ${mac.busy} busy${mac.online ? ` · ${mac.ready} ready` : ""}`));
}
function drawNetwork() {
  if (!network) return;
  const total = network.totals;
  stat("macsOnline", format(total.macs_online)); stat("slots", format(total.total_slots)); stat("busy", format(total.busy_slots));
  stat("utilization", `${total.total_slots ? Math.round(total.busy_slots / total.total_slots * 100) : 0}%`);
  $("ready").textContent = format(total.ready_slots);
  $("mac-summary").textContent = `${network.macs.length} reported · ${total.macs_online} online`;
  $("regions").replaceChildren();
  const regions = network.macs.filter(mac => mac.region);
  for (const mac of regions) {
    const [cx, cy] = project([mac.region.lon, mac.region.lat]), r = Math.min(24, 5 + Math.sqrt(mac.slots) * 3), busy = mac.slots ? mac.busy / mac.slots : 0;
    const cls = !mac.online ? "offline" : busy >= 1 ? "full" : busy > 0 ? "working" : "available";
    const marker = svg("a", { href: `${config.fleet}?operator=${encodeURIComponent(mac.operator)}`, class: "region-marker", "aria-label": `${mac.region.name}: ${mac.slots} slots, ${mac.busy} busy. View operator fleet.` });
    marker.append(svg("title", {}, `${mac.region.name} · ${mac.chip} · ${mac.slots} slots · ${mac.busy} busy`));
    marker.append(svg("circle", { cx, cy, r: r + 10, class: "region-halo" }), svg("circle", { cx, cy, r, class: `region-dot ${cls}` }));
    marker.addEventListener("pointerenter", () => callout(mac)); marker.addEventListener("focus", () => callout(mac));
    $("regions").append(marker);
  }
  if (regions.length) callout(regions.find(mac => mac.online) || regions[0]);
  else $("map-callout").textContent = "No Macs have opted in to sharing a region yet.";
  $("world-description").textContent = `${regions.length} Macs with opted-in regions. ${network.macs.length - regions.length} Macs have no shared region. Dot size represents guest slots; color represents utilization.`;
  $("macs").replaceChildren();
  for (const mac of [...network.macs].sort((a, b) => Number(b.online) - Number(a.online))) {
    const row = node("tr"), region = node("td"), link = node("a", mac.region?.name || "Region not shared");
    link.href = `${config.fleet}?operator=${encodeURIComponent(mac.operator)}`; link.title = `View operator ${mac.operator}`;
    region.append(link, node("span", `${mac.operator.slice(0, 8)}…${mac.operator.slice(-6)} ↗`, "sub"));
    const hardware = node("td", mac.chip || "Not reported"); hardware.append(node("span", mac.ram_bytes ? `${Math.round(mac.ram_bytes / 2 ** 30)} GiB RAM` : "Memory not reported", "sub"));
    const status = node("td"); status.append(node("span", mac.online ? "Online" : "Offline", `pill${mac.online ? "" : " offline"}`));
    const elapsed = Math.max(0, Math.floor(Date.now() / 1000 - mac.last_heartbeat)), last = node("td", elapsed < 60 ? `${elapsed}s ago` : elapsed < 3600 ? `${Math.floor(elapsed / 60)}m ago` : `${Math.floor(elapsed / 3600)}h ago`);
    last.title = new Date(mac.last_heartbeat * 1000).toLocaleString();
    row.append(region, hardware, node("td", mac.slots), node("td", mac.busy), status, last); $("macs").append(row);
  }
  if (!network.macs.length) { const row = node("tr"), cell = node("td", "No Macs have reported a signed heartbeat yet.", "empty"); cell.colSpan = 6; row.append(cell); $("macs").append(row); }
  $("updated").textContent = `Updated ${new Date(network.updated_at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })} · refreshes every 15s`;
}
function drawHistory() {
  if (!history) return;
  const chart = $("history-chart"), now = Math.floor(Date.now() / 1000), start = now - 86400, x = t => 55 + (t - start) / 86400 * 720, y = p => 175 - p * 145;
  chart.replaceChildren();
  for (const p of [0, .5, 1]) chart.append(svg("line", { x1: 55, x2: 775, y1: y(p), y2: y(p), class: "chart-grid" }), svg("text", { x: 42, y: y(p) + 4, "text-anchor": "end", class: "chart-label" }, `${p * 100}%`));
  for (const hours of [24, 18, 12, 6, 0]) chart.append(svg("text", { x: x(now - hours * 3600), y: 205, "text-anchor": hours === 24 ? "start" : hours === 0 ? "end" : "middle", class: "chart-label" }, hours ? `${hours}h ago` : "Now"));
  const samples = history.samples.filter(s => s.timestamp >= start && s.timestamp <= now), groups = [];
  for (const s of samples) {
    const previous = groups.at(-1)?.at(-1);
    if (!previous || s.timestamp - previous.timestamp > 90) groups.push([]);
    groups.at(-1).push(s);
  }
  for (const group of groups) {
    const points = group.map(s => [x(s.timestamp), y(s.total_slots ? s.busy_slots / s.total_slots : 0)]);
    if (points.length > 1) {
      chart.append(svg("polygon", { points: [[points[0][0], 175], ...points, [points.at(-1)[0], 175]].map(p => p.join(",")).join(" "), class: "chart-fill" }));
      chart.append(svg("polyline", { points: points.map(p => p.join(",")).join(" "), class: "chart-line" }));
    }
    group.forEach((s, i) => { const dot = svg("circle", { cx: points[i][0], cy: points[i][1], r: group.length === 1 ? 4 : 2, class: "chart-dot" }); dot.append(svg("title", {}, `${new Date(s.timestamp * 1000).toLocaleString()} · ${s.busy_slots}/${s.total_slots} busy · ${s.ready_slots} ready · ${s.macs_online} Macs online`)); chart.append(dot); });
  }
  if (!samples.length) chart.append(svg("text", { x: 420, y: 110, "text-anchor": "middle", class: "chart-empty" }, "Waiting for the first minute of history"));
  const since = new Date(history.started_at * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  $("history-status").textContent = `Per-minute network totals · ${samples.length.toLocaleString()} observations since ${since}. History is held in memory for 24h and lost on broker restart. Gaps have no observations.`;
}
function chainStats(result) {
  const windows = result?.windows;
  for (const [i, suffix] of [[0, "24h"], [1, "7d"]]) { stat(`guestSeconds${suffix}`, windows ? BigInt(windows[i].guestSeconds).toLocaleString() : "—"); stat(`jobs${suffix}`, windows ? format(windows[i].jobs) : "—"); }
}
async function readChain() {
  if (!chain || chainRefreshing) return;
  chainRefreshing = true;
  try {
    $("chain-status").classList.remove("error");
    chainResult = await chain.read(text => $("chain-status").textContent = text);
    chainReadAt = Date.now(); chainStats(chainResult);
    $("chain-status").textContent = `Two public RPCs agree · finalized block ${chainResult.block.toLocaleString()} · ${new Date(chainResult.finalizedAt * 1000).toLocaleTimeString()}. ${config.rpcs.map(url => new URL(url).hostname).join(" + ")}.`;
    document.documentElement.dataset.chainLoaded = "true";
  } catch (error) {
    chainResult = null; chainStats(null); document.documentElement.dataset.chainLoaded = "false";
    $("chain-status").textContent = `${error.message} Retrying in one minute.`; $("chain-status").classList.add("error"); chainReadAt = Date.now();
  } finally { chainRefreshing = false; snapshot(); }
}
async function refresh() {
  if (!config || refreshing) return;
  refreshing = true;
  try {
    const responses = await Promise.all(["/network", "/network/history"].map(async path => { const response = await fetch(config.broker + path, { cache: "no-store", signal: AbortSignal.timeout(15000) }); if (!response.ok) throw Error(`Network data returned HTTP ${response.status}`); return response.json(); }));
    [network, history] = responses; drawNetwork(); drawHistory(); snapshot();
    $("capacity-error").hidden = true; document.documentElement.dataset.loaded = "true";
  } catch (error) {
    $("capacity-error").textContent = `${error.message}. ${network ? "Showing the last received snapshot; it may be stale." : "Capacity is unavailable."} Retrying in 15 seconds.`;
    $("capacity-error").hidden = false; $("updated").textContent = "Network refresh unavailable";
  } finally { refreshing = false; }
}
const themes = ["system", "light", "dark"];
let theme = "system";
$("theme").onclick = () => { theme = themes[(themes.indexOf(theme) + 1) % themes.length]; if (theme === "system") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme; $("theme").textContent = `Theme: ${theme}`; };
$("refresh").onclick = () => { refresh(); readChain(); };
try {
  const response = await fetch("./config.json"); if (!response.ok) throw Error("Cannot read the dashboard configuration"); config = await response.json();
  chain = new NetworkChain(config); $("agent-link").href = config.agent; $("network-data").href = config.broker + "/network";
  $("escrow").href = `https://sepolia.basescan.org/address/${config.escrow}`;
  document.documentElement.dataset.ready = "true";
  await refresh(); readChain();
  setInterval(() => { refresh(); if (Date.now() - chainReadAt >= 60000) readChain(); }, 15000);
} catch (error) { $("capacity-error").textContent = error.message; $("capacity-error").hidden = false; }
