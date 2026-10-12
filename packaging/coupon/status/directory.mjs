// Browser display of relay-verified public opt-ins, not a browser attestation verifier.
export const directoryEndpoint = "https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft/directory";
const registry = "0xd4b33c83576a6049d29c6b849ec73491e52781a0";
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join() === keys.slice().sort().join();
const hex = (v, n) => typeof v === "string" && new RegExp(`^0x[0-9a-f]{${n}}$`).test(v);
const stamp = v => {
  if (typeof v !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(v)) return NaN;
  const time = Date.parse(v);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === v.slice(0, 19) ? time / 1000 : NaN;
};
const uint = (v, max) => typeof v === "string" && /^(0|[1-9][0-9]{0,77})$/.test(v) && BigInt(v) <= max;
const unknown = () => ({status: "unknown", message: "No valid node directory observation. This does not mean no peers are running.", nodes: []});

export function directoryView(value, now = Date.now() / 1000) {
  if (!Number.isFinite(now) || now < 0 || !exact(value, ["schema", "type", "generatedAt", "network", "coverage", "status", "error", "freshness", "nodes"])
      || value.schema !== 1 || value.type !== "dsmack-native-directory" || value.coverage !== "explicit-opt-in"
      || !exact(value.network, ["chainId", "registry"]) || value.network.chainId !== 84532 || value.network.registry !== registry
      || !exact(value.freshness, ["heartbeatTtlSeconds", "staleRetentionSeconds", "receiptFreshnessSeconds"])
      || value.freshness.heartbeatTtlSeconds !== 90 || value.freshness.staleRetentionSeconds !== 300 || value.freshness.receiptFreshnessSeconds !== 120
      || !Array.isArray(value.nodes) || value.nodes.length > 64) return unknown();
  const generated = stamp(value.generatedAt);
  if (!Number.isFinite(generated) || generated > now + 30) return unknown();
  if (value.status !== "available") {
    if (!["unavailable", "not-configured"].includes(value.status) || value.nodes.length
        || !exact(value.error, ["code"]) || value.error.code !== (value.status === "unavailable" ? "RPC_UNAVAILABLE" : "DIRECTORY_DISABLED")) return unknown();
    return {status: value.status, message: value.status === "not-configured" ? "Public node sharing is not enabled on this relay." : "The relay could not verify the directory. Node availability is unknown.", nodes: []};
  }
  if (value.error !== null) return unknown();
  const ids = new Set(), members = new Set(), rows = [];
  for (const n of value.nodes) {
    // label and version.measurement come from v2 check-ins; v1 records omit them.
    const v2 = "label" in n;
    if (!exact(n, ["id", "member", "account", "version", "checkIn", "sync", ...(v2 ? ["label"] : [])]) || !hex(n.id, 64) || !hex(n.member, 64)
        || (v2 && !(n.label === null || (typeof n.label === "string" && /^[A-Za-z0-9 ._-]{0,32}$/.test(n.label))))
        || ids.has(n.id) || members.has(n.member)
        || !exact(n.account, ["status", "address", "participantToken"])
        || !["verified", "unavailable"].includes(n.account.status)
        || (n.account.status === "verified" ? !hex(n.account.address, 40) : n.account.address !== null || n.account.participantToken !== null)
        || !(n.account.participantToken === null || (uint(n.account.participantToken, (1n << 256n) - 1n) && BigInt(n.account.participantToken) > 0n))
        || !exact(n.version, ["selfReported", "buildNumber", "admittedCodeHash", ...(v2 ? ["measurement"] : [])])
        || (v2 && !(n.version.measurement === null || hex(n.version.measurement, 64)))
        || typeof n.version.selfReported !== "string" || !/^[0-9][A-Za-z0-9._-]{0,63}$/.test(n.version.selfReported)
        || !uint(n.version.buildNumber, 2147483647n) || !hex(n.version.admittedCodeHash, 64)
        || !exact(n.checkIn, ["lastVerifiedAt", "expiresAt", "status"]) || !["fresh", "stale"].includes(n.checkIn.status)
        || !exact(n.sync, ["scope", "keyEpoch", "groupPublicFingerprint", "status", "receiptTransaction", "receiptCheckedAt", "receiptBlockTime"])
        || n.sync.scope !== "0x" + "0".repeat(64) || !uint(n.sync.keyEpoch, (1n << 64n) - 1n)
        || !["receipt-verified-current-epoch", "stale", "unverified"].includes(n.sync.status)
        || !(n.sync.groupPublicFingerprint === null || (typeof n.sync.groupPublicFingerprint === "string" && /^sha256:[0-9a-f]{64}$/.test(n.sync.groupPublicFingerprint)))
        || !(n.sync.receiptTransaction === null || hex(n.sync.receiptTransaction, 64))) return unknown();
    const checked = stamp(n.checkIn.lastVerifiedAt), expires = stamp(n.checkIn.expiresAt);
    if (!Number.isFinite(checked) || expires !== checked + 90 || checked > generated + 1 || checked > now + 30) return unknown();
    const receiptCheck = n.sync.receiptCheckedAt === null ? null : stamp(n.sync.receiptCheckedAt);
    const receiptBlock = n.sync.receiptBlockTime === null ? null : stamp(n.sync.receiptBlockTime);
    if ((receiptCheck !== null && (!Number.isFinite(receiptCheck) || receiptCheck > generated + 1 || receiptCheck > now + 30))
        || (receiptBlock !== null && (!Number.isFinite(receiptBlock) || receiptCheck === null || receiptBlock > receiptCheck + 15))) return unknown();
    if (n.sync.status === "unverified" && [n.sync.receiptTransaction, n.sync.receiptCheckedAt, n.sync.receiptBlockTime, n.sync.groupPublicFingerprint].some(v => v !== null)) return unknown();
    if (n.sync.status !== "unverified" && (receiptBlock === null || receiptCheck === null || n.sync.receiptTransaction === null || n.sync.groupPublicFingerprint === null)) return unknown();
    ids.add(n.id); members.add(n.member);
    const stale = now - generated > 90 || now >= expires || n.checkIn.status === "stale";
    const sync = !stale && n.sync.status === "receipt-verified-current-epoch" && receiptBlock !== null && now - receiptBlock <= 120
      ? "Recent verified exchange" : n.sync.status === "unverified" ? "Exchange unverified" : "Historical exchange";
    rows.push({...n, fresh: !stale, syncLabel: sync, expiredRetention: now - checked > 300});
  }
  const stale = now - generated > 90;
  return {status: stale ? "stale" : "available", generatedAt: value.generatedAt,
    message: stale ? `Directory observation is stale (${value.generatedAt}). Displayed records are historical.`
      : rows.length ? `Explicit public opt-ins · relay observation ${value.generatedAt}.` : "No retained public opt-ins. This is not a census of all peers.",
    nodes: stale ? rows : rows.filter(n => !n.expiredRetention)};
}

export async function readDirectory(fetcher = fetch) {
  const response = await fetcher(directoryEndpoint, {credentials: "omit", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(5000)});
  if (!response.ok) throw new Error("Directory unavailable");
  const reader = response.body.getReader(), chunks = []; let length = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read(); if (done) break;
      length += value.byteLength; if (length > 131072) throw new Error("Directory too large"); chunks.push(value);
    }
  } finally {await reader.cancel();}
  const data = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) {data.set(chunk, offset); offset += chunk.byteLength;}
  return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(data));
}

const rendered = new WeakMap();
export function drawDirectory(value, doc = document) {
  const view = directoryView(value), text = (id, value) => {doc.getElementById(id).textContent = value;};
  text("directory-state", view.status); text("directory-message", view.message);
  const query = doc.getElementById("find-node").value.trim().toLowerCase();
  const nodes = view.nodes.filter(n => !query || [n.id, n.member, n.account.address].some(id => id && id.toLowerCase().includes(query)));
  text("directory-match", query ? `${nodes.length} matching public records. Search stays in this browser.` : "Copy your public node or account ID from the app to find your entry.");
  const list = doc.getElementById("directory-nodes"), renderKey = JSON.stringify(nodes);
  if (rendered.get(list) === renderKey) return;
  const expanded = new Set([...list.querySelectorAll(".node-card")].filter(card => card.querySelector("details")?.open).map(card => card.dataset.nodeId));
  list.replaceChildren();
  for (const node of nodes) {
    const card = doc.createElement("article"); card.className = "node-card"; card.dataset.nodeId = node.id;
    const identity = node.account.status === "verified" ? node.account.address : node.member;
    const heading = doc.createElement("h3"); heading.textContent = `${node.label ? node.label + " · " : ""}${node.account.status === "verified" ? "Account" : "Member"} ${identity.slice(0, 10)}…${identity.slice(-8)}`; card.append(heading);
    const fields = [
      ["Participant receipt", node.account.participantToken === null ? "Not available" : `#${node.account.participantToken}`],
      ["Check-in", `${node.fresh ? "Fresh verified check-in" : "Stale check-in"} · ${node.checkIn.lastVerifiedAt}`],
      ["App version (signed self-report)", `${node.version.selfReported} · build ${node.version.buildNumber}`],
      ["Key exchange", `${node.syncLabel} · epoch ${node.sync.keyEpoch}`],
    ];
    const evidence = [
      ["Account address", node.account.address ?? "No verified account binding"],
      ["Admitted build (relay-verified)", node.version.admittedCodeHash],
      ["Code measurement (registry-verified)", node.version.measurement ?? "Not measured"],
      ["Receipt block time", node.sync.receiptBlockTime ?? "Unknown"],
      ["Public-key fingerprint", node.sync.groupPublicFingerprint ?? "Unknown"],
      ["Receipt transaction", node.sync.receiptTransaction ?? "Unknown"],
      ["Public node ID", node.id], ["Membership ID", node.member],
    ];
    const description = fields => {
      const dl = doc.createElement("dl");
      for (const [label, value] of fields) {const dt = doc.createElement("dt"), dd = doc.createElement("dd"); dt.textContent = label; dd.textContent = value; dl.append(dt, dd);}
      return dl;
    };
    card.append(description(fields));
    const details = doc.createElement("details"), summary = doc.createElement("summary"); summary.textContent = "View public IDs and exchange evidence";
    details.open = expanded.has(node.id); details.append(summary, description(evidence)); card.append(details); list.append(card);
  }
  rendered.set(list, renderKey);
}
