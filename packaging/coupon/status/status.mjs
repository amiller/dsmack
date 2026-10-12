import { drawParticipation } from "./participation.mjs";
import { drawDirectory, readDirectory } from "./directory.mjs";
// Two independent operator observations. Neither authorizes a coupon claim.
const states = new Set(["ready", "unavailable", "unknown", "maintenance", "reconciliation-required", "approval-renewal-required"]);
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(",") === keys.slice().sort().join(",");
const time = value => Number.isSafeInteger(value) && value >= 0 && value <= 253402300799;
const date = value => new Date(value * 1000).toISOString();
const freshness = (observed, now, maxAge) => !time(now) || observed > now + 30 ? "unknown"
  : now - observed > maxAge ? "stale" : "fresh";

export function view(value, now = Math.floor(Date.now() / 1000)) {
  const unknown = { claiming: "unknown", freshness: "unknown", observation: "No valid operator observation." };
  if (!exact(value, ["claiming_available", "observed_at_unix", "state"])
      || !states.has(value.state) || typeof value.claiming_available !== "boolean"
      || !time(value.observed_at_unix)
      || (value.claiming_available && value.state !== "ready")) return unknown;
  const age = freshness(value.observed_at_unix, now, 90);
  if (age === "unknown") return unknown;
  return { claiming: age === "stale" || value.state === "unknown" ? "unknown" : value.claiming_available ? "available" : "unavailable",
    freshness: age, observation: `${age === "stale" ? "Stale observation" : "Operator reports " + value.state} · observed ${date(value.observed_at_unix)}.` };
}

const issuerKeys = ["identity_profile", "schema", "network", "observed_at_unix", "issuer_status", "peer", "source_revision", "trust_profile", "bundle_url", "bundle_sha256", "approval_expires_at_unix", "claim_window_ends_at_unix"];
function publicURL(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try { const url = new URL(value); return url.protocol === "https:" && url.hostname
    && !url.username && !url.password && !url.search && !url.hash && (!url.port || url.port === "443"); }
  catch { return false; }
}
export function issuerView(value, now = Math.floor(Date.now() / 1000)) {
  const unknown = { status: "unknown", freshness: "unknown", observation: "No valid issuer observation.", details: null };
  if (!exact(value, issuerKeys) || value.schema !== "dsmack-issuer-observation-v1"
      || typeof value.network !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value.network)
      || value.trust_profile !== "operator-readable-debug"
      || !["legacy-intel-tdx-identity", "mac-appattest-coupon-v1"].includes(value.identity_profile)
      || !["issuer-reachable", "refused", "expired", "stale"].includes(value.issuer_status)
      || typeof value.peer !== "string" || !/^\/dns4\/[A-Za-z0-9.-]+\/tcp\/443\/wss\/p2p\/[A-Za-z0-9]{16,128}$/.test(value.peer)
      || typeof value.source_revision !== "string" || !/^[0-9a-f]{40}$/.test(value.source_revision)
      || typeof value.bundle_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(value.bundle_sha256)
      || !publicURL(value.bundle_url)
      || ![value.observed_at_unix, value.approval_expires_at_unix, value.claim_window_ends_at_unix].every(time)
      || value.claim_window_ends_at_unix > value.approval_expires_at_unix) return unknown;
  const age = freshness(value.observed_at_unix, now, 300);
  if (age === "unknown") return unknown;
  const status = age === "stale" || value.issuer_status === "stale" ? "stale"
    : now >= value.approval_expires_at_unix ? "expired" : value.issuer_status;
  return { status, freshness: status === "stale" ? "stale" : age,
    observation: `Operator probe observed ${date(value.observed_at_unix)}. Expires locally after 5 minutes.`,
    details: { ...value, approvalDeadline: date(value.approval_expires_at_unix),
      claimDeadline: date(value.claim_window_ends_at_unix),
      claimWindow: now >= value.claim_window_ends_at_unix ? "expired" : "advertised window open" } };
}

export async function readFeed(fetcher = fetch, filename = "health.json") {
  if (!["health.json", "issuer.json", "participation.json"].includes(filename)) throw new Error("Unknown feed");
  const response = await fetcher(new URL(filename, import.meta.url), {
    credentials: "omit", cache: "no-store", redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error("Status unavailable");
  const reader = response.body.getReader();
  const chunks = []; let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      bytes += value.byteLength;
      if (bytes > (filename === "participation.json" ? 65536 : 4096)) throw new Error("Status unavailable");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const joined = new Uint8Array(bytes); let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(joined));
}

if (typeof document !== "undefined") {
  let health = null, issuer = null, participation = null, directory = null;
  const text = (id, value) => { document.getElementById(id).textContent = value; };
  const draw = () => {
    drawParticipation(participation);
    drawDirectory(directory);
    const current = view(health), peer = issuerView(issuer);
    text("claiming", current.claiming);
    text("observation", current.observation);
    text("claim-freshness", current.freshness);
    text("issuer", peer.status);
    text("issuer-observation", peer.observation);
    text("issuer-freshness", peer.freshness);
    const details = peer.details;
    document.getElementById("issuer-details").hidden = !details;
    document.getElementById("no-issuer").hidden = !!details;
    if (details) {
      text("network", details.network); text("peer", details.peer);
      text("identity-profile", details.identity_profile); text("revision", details.source_revision); text("profile", details.trust_profile);
      text("approval-deadline", details.approvalDeadline);
      text("claim-deadline", `${details.claimDeadline} (${details.claimWindow})`);
      text("bundle-hash", details.bundle_sha256);
      const link = document.getElementById("bundle"); link.href = details.bundle_url; link.textContent = details.bundle_url;
    } else document.getElementById("bundle").removeAttribute("href");
  };
  const poll = async () => {
    await Promise.all([
      readFeed().then(value => { health = value; }, () => { health = null; }),
      readFeed(fetch, "issuer.json").then(value => { issuer = value; }, () => { issuer = null; }),
      readFeed(fetch, "participation.json").then(value => { participation = value; }, () => { participation = null; }),
      readDirectory().then(value => { directory = value; }, () => { directory = null; }),
    ]);
    draw();
  };
  document.getElementById("find-node").addEventListener("input", () => drawDirectory(directory));
  draw(); void poll(); setInterval(poll, 30000); setInterval(draw, 1000);
}
