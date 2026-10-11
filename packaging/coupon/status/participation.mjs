// Registry observations for an explicitly reviewed public opt-in roster, never a peer census.
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(",") === keys.slice().sort().join(",");
const integer = value => Number.isSafeInteger(value) && value >= 0;
const time = value => integer(value) && value <= 253402300799;
const hex = (value, length) => typeof value === "string" && new RegExp(`^0x[0-9a-fA-F]{${length}}$`).test(value);
const common = ["version", "state", "observed_at", "max_age", "observation_source", "members", "independent_operator_count", "independent_device_count", "liveness"];
export function participationView(value, now = Math.floor(Date.now() / 1000)) {
  const unknown = { status: "unknown", observation: "No valid participation observation.", details: null };
  if (!value || !["observed", "unknown"].includes(value.state)) return unknown;
  const keys = value.state === "unknown" ? [...common, "reason"] : [...common, "chain_id", "registry", "protocol_version", "block", "coverage", "network_paused", "relay", "shared_key"];
  if (!exact(value, keys) || value.version !== 1 || value.max_age !== 90
      || value.observation_source !== "operator-rpc-relay"
      || value.independent_operator_count !== null || value.independent_device_count !== null
      || value.liveness !== "unknown" || !Array.isArray(value.members) || value.members.length > 64
      || typeof value.observed_at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(value.observed_at)) return unknown;
  const observed = Date.parse(value.observed_at) / 1000;
  if (!Number.isFinite(observed) || observed < 0
      || new Date(observed * 1000).toISOString().slice(0, 19) !== value.observed_at.slice(0, 19)
      || !time(now) || observed > now + 30) return unknown;
  if (value.state === "unknown") return value.reason === "observation-unavailable" && !value.members.length
    ? { ...unknown, observation: `Operator could not obtain a participation observation at ${value.observed_at}.` } : unknown;
  const { block, coverage, relay, shared_key: key } = value;
  if (value.chain_id !== 84532 || value.protocol_version !== 2 || !hex(value.registry, 40)
      || typeof value.network_paused !== "boolean"
      || !exact(block, ["number", "hash", "timestamp"]) || !integer(block.number) || !hex(block.hash, 64) || !time(block.timestamp)
      || observed - block.timestamp < -15 || observed - block.timestamp > 120
      || !exact(coverage, ["from_block", "to_block", "opt_in_identities", "complete_census", "selection"])
      || ![coverage.from_block, coverage.to_block, coverage.opt_in_identities].every(integer)
      || coverage.from_block !== coverage.to_block || coverage.to_block !== block.number
      || coverage.opt_in_identities > 64 || coverage.opt_in_identities !== value.members.length || coverage.complete_census !== false
      || coverage.selection !== "operator-supplied-public-opt-in-roster"
      || !exact(relay, ["state", "sponsor_writes_paused"]) || relay.state !== "observed" || typeof relay.sponsor_writes_paused !== "boolean"
      || !exact(key, ["scope", "epoch", "committed", "public_key_sha256"]) || !hex(key.scope, 64)
      || key.scope !== "0x" + "0".repeat(64)
      || typeof key.epoch !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(key.epoch)
      || BigInt(key.epoch) > 18446744073709551615n
      || typeof key.committed !== "boolean"
      || !(key.public_key_sha256 === null || (typeof key.public_key_sha256 === "string" && /^[0-9a-f]{64}$/.test(key.public_key_sha256)))
      || key.committed !== (key.public_key_sha256 !== null)) return unknown;
  const ids = new Set();
  for (const member of value.members) {
    if (!exact(member, ["member_id", "category", "registered", "last_checked", "revoked", "liveness", "source"])
        || !hex(member.member_id, 64) || !hex(member.category, 64)
        || typeof member.registered !== "boolean" || typeof member.revoked !== "boolean"
        || !(member.last_checked === null || time(member.last_checked)) || member.liveness !== "unknown"
        || (member.registered ? member.last_checked === null || member.last_checked > block.timestamp
          : member.last_checked !== null || member.revoked || member.category !== "0x" + "0".repeat(64))
        || member.source !== "operator-opt-in"
        || ids.has(member.member_id.toLowerCase())) return unknown;
    ids.add(member.member_id.toLowerCase());
  }
  const status = now - observed > 90 ? "stale" : "observed";
  return { status, observation: `${status === "stale" ? "Stale operator observation" : "Operator RPC and relay observation"} · ${value.observed_at}. Expires locally after 90 seconds.`, details: value };
}

export function drawParticipation(value, doc = document) {
  const current = participationView(value);
  doc.getElementById("participation-state").textContent = current.status;
  doc.getElementById("participation-observation").textContent = current.observation;
  const details = current.details;
  doc.getElementById("participation-details").hidden = !details;
  const rows = doc.getElementById("member-rows"); rows.replaceChildren();
  if (!details) return;
  const text = (id, value) => { doc.getElementById(id).textContent = value; };
  text("participation-chain", `Base Sepolia (${details.chain_id}) · protocol ${details.protocol_version}`);
  text("registry", details.registry);
  text("participation-block", `${details.block.number} · ${new Date(details.block.timestamp * 1000).toISOString()}`);
  text("coverage", `Block ${details.coverage.to_block}; ${details.coverage.opt_in_identities} identities from an operator-supplied public opt-in roster. This is not a complete census or an authenticated self-published directory.`);
  text("native-pause", `Registry paused: ${details.network_paused ? "yes" : "no"}; sponsor writes paused: ${details.relay.sponsor_writes_paused ? "yes" : "no"}. These flags do not prove fresh admission.`);
  text("shared-key", `Epoch ${details.shared_key.epoch} · commitment ${details.shared_key.committed ? "present" : "absent"}. A commitment does not establish that nodes hold or synchronized a key.`);
  text("shared-key-hash", details.shared_key.public_key_sha256 ?? "No committed public key");
  for (const member of details.members) {
    const row = doc.createElement("tr");
    for (const value of [member.member_id, `${member.registered ? "registered" : "not registered"}${member.revoked ? " / revoked" : ""}`,
      member.last_checked === null ? "unknown" : new Date(member.last_checked * 1000).toISOString(), member.source, "unknown"]) {
      const cell = doc.createElement("td"); cell.textContent = value; row.append(cell);
    }
    rows.append(row);
  }
}
