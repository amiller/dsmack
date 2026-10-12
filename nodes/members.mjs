// Registry members on Base Sepolia merged with the relay's opt-in directory.
import {directoryView, readDirectory} from "./directory.mjs";
export const REGISTRY = "0xd4B33C83576a6049d29c6B849ec73491e52781a0";
export const CD_REGISTRY = "0x9e513E19fCE48563c89E91C4ca571b1B089484a4";
// Members of the measured category are admitted while MeasurementRegistry has an open window for their M.
export const MEASURED = {category: "0xfea7ca3e37ca38760ee1b6b754c54abec93064e5513ffe5e15d955087a4014cb",
  adapter: "0xBD78416237c18874BBbD55ccc9A38Fdd85945982", registry: "0x976C2F9DF2bab0616f25D07CEC77cab7C5272203"};
export const LEGACY = {category: "0xbbbb9ea44ff8fbd35e60f06bdf52445c102d8d1ffa10f5df51582dbd45cda9b6", adapter: "0x46b425674d361a5E2A0ec5F486A6c1FA5aE012BB"};
export const RPC = "https://sepolia.base.org";
export const EXPLORER = "https://base-sepolia.blockscout.com";
const ZERO = "0x" + "0".repeat(64);
const TOPIC = {
  checked: "0xd0d18ff6d30fa07f2ffb5fe7b133cc9a2910cfa7299b56c9e79706ed27d66d63",
  receipt: "0x2c08c07b29879c8c258b3e3cf23077378c7df242f33a1c5407af302f05c799bd",
  epoch: "0x143519224fe404fde2f926e45a8cd8de4da43c648680d13caadff828449c7ad0",
  bootstrap: "0xe792a62ade48ed6a195383dfa274422269b9dd73b74d85a26846cfdd8434f282",
  revoked: "0xe5af7daed5ab2a2dc5f98d53619f05089c0c14d11a6621f6b906a2366c9a7ab3",
  asserted: "0x8baa3ce13e072df0e9c6811d3a5ca383f3db280949f547aaca24ac161ad21c69",
};
const SELECTOR = {keyEpochs: "0xd71779d9", isAdmitted: "0xc216e459", isAdmittedAt: "0xfc9e2bfe",
  assertionEvidence: "0x80fb5bc4", measurementOf: "0x2bbfe646"};
const ADAPTER = {[MEASURED.category]: MEASURED.adapter, [LEGACY.category]: LEGACY.adapter};

// sepolia.base.org caps eth_getLogs at 200 blocks and Blockscout's log index for this contract is incomplete,
// so Blockscout lists the registry's transactions and the RPC returns their receipts.
// The RPC allows 25 requests per second, counting each batch entry.
let lastBatch = 0;
async function batched(fetcher, requests) {
  const out = [];
  for (let i = 0; i < requests.length; i += 20) {
    await new Promise(ok => setTimeout(ok, Math.max(0, lastBatch + 1100 - Date.now())));
    lastBatch = Date.now();
    const chunk = requests.slice(i, i + 20);
    const r = await fetcher(RPC, {method: "POST", headers: {"content-type": "application/json"}, signal: AbortSignal.timeout(15000),
      body: JSON.stringify(chunk.map(([method, params], id) => ({jsonrpc: "2.0", id, method, params})))});
    if (!r.ok) throw new Error(`RPC ${r.status}`);
    for (const {id, result, error} of (await r.json()).sort((x, y) => x.id - y.id)) {
      if (error || result == null) throw new Error(`${chunk[id][0]}: ${error?.message ?? "no result"}`);
      out.push(result);
    }
  }
  return out;
}
const call = (to, selector, arg) => ["eth_call", [{to, data: selector + arg.slice(2)}, "latest"]];

const receipts = new Map();
async function logs(fetcher) {
  const txs = []; let query = "";
  for (;;) {
    const r = await fetcher(`${EXPLORER}/api/v2/addresses/${REGISTRY}/transactions${query}`, {signal: AbortSignal.timeout(15000)});
    if (!r.ok) throw new Error(`Blockscout transactions ${r.status}`);
    const page = await r.json(); txs.push(...page.items.filter(t => t.status === "ok"));
    if (!page.next_page_params) break;
    query = "?" + new URLSearchParams(page.next_page_params);
  }
  const missing = txs.filter(t => !receipts.has(t.hash));
  (await batched(fetcher, missing.map(t => ["eth_getTransactionReceipt", [t.hash]]))).forEach((r, i) => receipts.set(missing[i].hash, r));
  // An execute's adapter Asserted log names the App Attest key the registry's Checked log refers to.
  const adapters = Object.values(ADAPTER).map(a => a.toLowerCase());
  return txs.flatMap(t => {
    const all = receipts.get(t.hash).logs, keyId = all.find(l => adapters.includes(l.address.toLowerCase()) && l.topics[0] === TOPIC.asserted)?.topics[1] ?? null;
    return all.filter(l => l.address.toLowerCase() === REGISTRY.toLowerCase())
      .map(l => ({...l, keyId, block: Number(l.blockNumber), index: Number(l.logIndex), at: Date.parse(t.timestamp) / 1000}));
  })
    .sort((a, b) => a.block - b.block || a.index - b.index);
}

export async function loadMembers(fetcher = fetch, now = Date.now() / 1000) {
  const [events, directory] = await Promise.all([logs(fetcher),
    readDirectory(fetcher).then(directoryView, e => ({status: "unknown", message: `Relay directory unavailable (${e.message}).`, nodes: []}))]);
  const epochs = [], members = new Map();
  const member = id => members.get(id) ?? members.set(id, {member: id, category: null, keyId: null, joinedAt: null, lastTx: null, lastEventAt: null, receiptBlock: null, revoked: false}).get(id);
  for (const l of events) {
    const [t0, t1, t2] = l.topics;
    if (t0 === TOPIC.epoch && t1 === ZERO) { epochs.push({block: l.block, epoch: BigInt(l.data)}); continue; }
    const id = t0 === TOPIC.checked || t0 === TOPIC.revoked ? t1 : (t0 === TOPIC.receipt || t0 === TOPIC.bootstrap) && t1 === ZERO ? t2 : null;
    if (!id) continue;
    const m = member(id);
    if (t0 === TOPIC.checked) { m.joinedAt ??= l.at; m.category = t2; m.keyId = l.keyId ?? m.keyId; }
    if (t0 === TOPIC.receipt || t0 === TOPIC.bootstrap) m.receiptBlock = l.block;
    if (t0 === TOPIC.revoked) m.revoked = true;
    m.lastTx = l.transactionHash; m.lastEventAt = l.at;
  }
  const byMember = new Map(directory.nodes.map(n => [n.member, n]));
  for (const n of directory.nodes) member(n.member);
  const list = [...members.values()], keyed = list.filter(m => m.keyId && ADAPTER[m.category]);
  const [blockHex, epochWord, ...words] = await batched(fetcher, [["eth_blockNumber", []], call(REGISTRY, SELECTOR.keyEpochs, ZERO),
    ...keyed.map(m => call(ADAPTER[m.category], SELECTOR.assertionEvidence, m.keyId))]);
  // assertionEvidence(keyId) = (context, cdhash, rp, checkedAt, counter): the CDHash of the member's last assertion.
  keyed.forEach((m, i) => { m.cdhash = "0x" + words[i].slice(66, 130); });
  const measured = keyed.filter(m => m.category === MEASURED.category), legacy = keyed.filter(m => m.category === LEGACY.category);
  const ms = await batched(fetcher, [...measured.map(m => call(MEASURED.registry, SELECTOR.measurementOf, m.cdhash)),
    ...legacy.map(m => call(CD_REGISTRY, SELECTOR.isAdmitted, m.cdhash))]);
  measured.forEach((m, i) => { m.measurement = ms[i]; });
  legacy.forEach((m, i) => { m.admitted = BigInt(ms[measured.length + i]) === 1n; });
  const windows = await batched(fetcher, measured.map(m => call(MEASURED.registry, SELECTOR.isAdmittedAt, m.measurement + BigInt(blockHex).toString(16).padStart(64, "0"))));
  measured.forEach((m, i) => { m.admitted = BigInt(windows[i]) === 1n; });
  const currentEpoch = BigInt(epochWord), epochAt = block => epochs.filter(e => e.block <= block).at(-1)?.epoch ?? 0n;
  const short = h => `${h.slice(0, 10)}…`;
  const rows = list.map(m => {
    const node = byMember.get(m.member);
    const epoch = m.receiptBlock === null ? null : epochAt(m.receiptBlock);
    const checkIn = node ? Date.parse(node.checkIn.lastVerifiedAt) / 1000 : null;
    const lastSeen = Math.max(checkIn ?? 0, m.lastEventAt ?? 0) || null;
    return {
      member: m.member, name: node?.label || `${m.member.slice(0, 8)}…${m.member.slice(-6)}`, revoked: m.revoked,
      version: node ? `${node.version.selfReported} (build ${node.version.buildNumber})` : null,
      admitted: m.admitted === undefined ? (m.category === null ? "no join on chain" : "no assertion found") : m.admitted ? "admitted" : "not admitted",
      admittedNote: m.admitted === undefined ? "" : m.measurement ? `measured · M ${short(m.measurement)}` : `legacy build ${short(m.cdhash)}`,
      checkIn, registryAt: m.lastEventAt, lastSeen, recent: lastSeen !== null && now - lastSeen <= 7 * 86400,
      presence: node ? (node.fresh && now - checkIn <= 90 ? "online" : "stale") : directory.status === "unknown" ? "unknown" : "no check-in",
      epoch: epoch === null ? "no receipt" : `${epoch}${epoch === currentEpoch ? " (current)" : ` (stale; current ${currentEpoch})`}`,
      lastTx: m.lastTx,
    };
  });
  const rank = {online: 0, stale: 1};
  rows.sort((a, b) => (rank[a.presence] ?? 2) - (rank[b.presence] ?? 2) || (b.lastSeen ?? 0) - (a.lastSeen ?? 0));
  return {rows, currentEpoch, directory, events: events.length};
}

export function ago(seconds, now = Date.now() / 1000) {
  if (seconds === null) return "never";
  const d = Math.max(0, Math.round(now - seconds));
  return d < 90 ? `${d} s ago` : d < 5400 ? `${Math.round(d / 60)} min ago` : d < 129600 ? `${Math.round(d / 3600)} h ago` : `${Math.round(d / 86400)} d ago`;
}

const SHOW_ALL = "dsmack-nodes-show-all";
let showAll = false, lastView = null;
try { showAll = localStorage.getItem(SHOW_ALL) === "1"; } catch {}
export function toggleAll(doc = document) {
  showAll = !showAll;
  try { localStorage.setItem(SHOW_ALL, showAll ? "1" : "0"); } catch {}
  if (lastView) draw(lastView, doc);
}

export function draw(view, doc = document) {
  lastView = view;
  const text = (id, v) => { doc.getElementById(id).textContent = v; };
  const el = (tag, v, cls) => { const e = doc.createElement(tag); e.textContent = v; if (cls) e.className = cls; return e; };
  const recent = view.rows.filter(r => r.recent);
  text("chain-state", "observed"); text("directory-state", view.directory.status); text("directory-message", view.directory.message);
  text("summary", `${view.rows.filter(r => r.presence === "online").length} online · ${recent.length} recent · ${view.rows.length} ever registered · shared key epoch ${view.currentEpoch}`);
  text("toggle-all", showAll ? `Show only the ${recent.length} recent members` : `Show all ${view.rows.length} members`);
  const body = doc.getElementById("member-rows"); body.replaceChildren();
  for (const r of showAll ? view.rows : recent) {
    const row = doc.createElement("tr");
    const cell = (...parts) => { const td = doc.createElement("td"); td.append(...parts); row.append(td); };
    const name = el("strong", r.name); name.title = r.member;
    const link = doc.createElement("a"); link.rel = "noreferrer";
    if (r.lastTx) { link.href = `${EXPLORER}/tx/${r.lastTx}`; link.textContent = `${r.lastTx.slice(0, 10)}…`; } else link.textContent = "none";
    cell(name, el("small", r.version ?? ""));
    cell(el("span", r.revoked ? "revoked" : r.presence, `presence ${r.revoked ? "revoked" : r.presence.replace(" ", "-")}`));
    cell(r.admitted, el("small", r.admittedNote));
    cell(ago(r.lastSeen), el("small", r.registryAt === null ? "no registry event" : `registry ${ago(r.registryAt)}`));
    cell(r.epoch); cell(link);
    body.append(row);
  }
}
