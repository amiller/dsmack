// Registry members on Base Sepolia merged with the relay's opt-in directory.
import {directoryView, readDirectory} from "./directory.mjs";
export const REGISTRY = "0xd4B33C83576a6049d29c6B849ec73491e52781a0";
export const CD_REGISTRY = "0x9e513E19fCE48563c89E91C4ca571b1B089484a4";
export const RPC = "https://sepolia.base.org";
export const EXPLORER = "https://base-sepolia.blockscout.com";
const ZERO = "0x" + "0".repeat(64);
const TOPIC = {
  checked: "0xd0d18ff6d30fa07f2ffb5fe7b133cc9a2910cfa7299b56c9e79706ed27d66d63",
  receipt: "0x2c08c07b29879c8c258b3e3cf23077378c7df242f33a1c5407af302f05c799bd",
  epoch: "0x143519224fe404fde2f926e45a8cd8de4da43c648680d13caadff828449c7ad0",
  bootstrap: "0xe792a62ade48ed6a195383dfa274422269b9dd73b74d85a26846cfdd8434f282",
  revoked: "0xe5af7daed5ab2a2dc5f98d53619f05089c0c14d11a6621f6b906a2366c9a7ab3",
};
const SELECTOR = {isActive: "0x5c36901c", keyEpochs: "0xd71779d9", isAdmitted: "0xc216e459"};

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
  return txs.flatMap(t => receipts.get(t.hash).logs.filter(l => l.address.toLowerCase() === REGISTRY.toLowerCase())
    .map(l => ({...l, block: Number(l.blockNumber), index: Number(l.logIndex), at: Date.parse(t.timestamp) / 1000})))
    .sort((a, b) => a.block - b.block || a.index - b.index);
}

export async function loadMembers(fetcher = fetch, now = Date.now() / 1000) {
  const [events, directory] = await Promise.all([logs(fetcher),
    readDirectory(fetcher).then(directoryView, e => ({status: "unknown", message: `Relay directory unavailable (${e.message}).`, nodes: []}))]);
  const epochs = [], members = new Map();
  const member = id => members.get(id) ?? members.set(id, {member: id, joinedAt: null, lastTx: null, lastEventAt: null, receiptBlock: null, revoked: false}).get(id);
  for (const l of events) {
    const [t0, t1, t2] = l.topics;
    if (t0 === TOPIC.epoch && t1 === ZERO) { epochs.push({block: l.block, epoch: BigInt(l.data)}); continue; }
    const id = t0 === TOPIC.checked || t0 === TOPIC.revoked ? t1 : (t0 === TOPIC.receipt || t0 === TOPIC.bootstrap) && t1 === ZERO ? t2 : null;
    if (!id) continue;
    const m = member(id);
    if (t0 === TOPIC.checked) m.joinedAt ??= l.at;
    if (t0 === TOPIC.receipt || t0 === TOPIC.bootstrap) m.receiptBlock = l.block;
    if (t0 === TOPIC.revoked) m.revoked = true;
    m.lastTx = l.transactionHash; m.lastEventAt = l.at;
  }
  const byMember = new Map(directory.nodes.map(n => [n.member, n]));
  for (const n of directory.nodes) member(n.member);
  const list = [...members.values()], checked = list.filter(m => byMember.has(m.member));
  const [epochWord, ...words] = await batched(fetcher, [call(REGISTRY, SELECTOR.keyEpochs, ZERO),
    ...list.map(m => call(REGISTRY, SELECTOR.isActive, m.member)),
    ...checked.map(m => call(CD_REGISTRY, SELECTOR.isAdmitted, byMember.get(m.member).version.admittedCodeHash))]);
  const currentEpoch = BigInt(epochWord), epochAt = block => epochs.filter(e => e.block <= block).at(-1)?.epoch ?? 0n;
  const rows = list.map((m, i) => {
    const node = byMember.get(m.member), admitted = node ? BigInt(words[list.length + checked.indexOf(m)]) === 1n : null;
    const epoch = m.receiptBlock === null ? null : epochAt(m.receiptBlock);
    const checkIn = node ? Date.parse(node.checkIn.lastVerifiedAt) / 1000 : null;
    return {
      member: m.member, name: `${m.member.slice(0, 8)}…${m.member.slice(-6)}`,
      active: BigInt(words[i]) === 1n, revoked: m.revoked,
      version: node ? `${node.version.selfReported} (build ${node.version.buildNumber})` : directory.status === "unknown" ? "unknown" : "no check-in",
      lastSeen: checkIn ?? m.lastEventAt, lastSeenSource: node ? "check-in" : "registry event",
      presence: node ? (node.fresh && now - checkIn <= 90 ? "online" : "stale") : directory.status === "unknown" ? "unknown" : "no check-in",
      attestation: [m.joinedAt === null ? "no join on chain" : "App Attest at join",
        admitted === null ? "build unknown" : admitted ? "build admitted" : "build no longer admitted"].join(" · "),
      epoch: epoch === null ? "no receipt" : `${epoch}${epoch === currentEpoch ? " (current)" : ` (stale; current ${currentEpoch})`}`,
      lastTx: m.lastTx,
    };
  });
  rows.sort((a, b) => (b.active - a.active) || (b.lastSeen ?? 0) - (a.lastSeen ?? 0));
  return {rows, currentEpoch, directory, events: events.length};
}

export function ago(seconds, now = Date.now() / 1000) {
  if (seconds === null) return "never";
  const d = Math.max(0, Math.round(now - seconds));
  return d < 90 ? `${d} s ago` : d < 5400 ? `${Math.round(d / 60)} min ago` : d < 129600 ? `${Math.round(d / 3600)} h ago` : `${Math.round(d / 86400)} d ago`;
}

export function draw(view, doc = document) {
  const text = (id, v) => { doc.getElementById(id).textContent = v; };
  text("chain-state", "observed"); text("directory-state", view.directory.status); text("directory-message", view.directory.message);
  text("summary", `${view.rows.filter(r => r.active).length} active of ${view.rows.length} registry members · ${view.events} registry events · shared key epoch ${view.currentEpoch}`);
  const body = doc.getElementById("member-rows"); body.replaceChildren();
  for (const r of view.rows) {
    const row = doc.createElement("tr");
    const cell = v => { const td = doc.createElement("td"); typeof v === "string" ? td.textContent = v : td.append(v); row.append(td); };
    const id = doc.createElement("code"); id.textContent = r.name; id.title = r.member;
    const link = doc.createElement("a"); link.rel = "noreferrer";
    if (r.lastTx) { link.href = `${EXPLORER}/tx/${r.lastTx}`; link.textContent = `${r.lastTx.slice(0, 10)}…`; } else link.textContent = "none";
    cell(id); cell(r.revoked ? "revoked" : r.active ? "active" : "inactive"); cell(r.version);
    cell(`${r.presence} · ${ago(r.lastSeen)} (${r.lastSeenSource})`); cell(r.attestation); cell(r.epoch); cell(link);
    body.append(row);
  }
}
