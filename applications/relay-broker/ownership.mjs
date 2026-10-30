import { verifyTypedData } from "../payments/schema.mjs";

const binding = [
  { name: "kid", type: "bytes32" },
  { name: "publisher", type: "address" },
  { name: "operator", type: "address" },
  { name: "nonce", type: "uint64" },
];
const delegation = [
  { name: "operator", type: "address" },
  { name: "provisioner", type: "address" },
  { name: "nonce", type: "uint64" },
];
export const ownershipTypes = {
  MacLink: binding, MacUnlink: binding,
  ProvisioningAuthorization: delegation, ProvisionerRevocation: delegation,
};
export const ownershipDomain = escrow => ({
  name: "DsmackMacOwnership", version: "1", chainId: 84532, verifyingContract: escrow,
});
const need = (ok, message) => { if (!ok) throw Error(message); };
const canonical = value => JSON.stringify(value, (_, v) =>
  v && typeof v === "object" && !Array.isArray(v)
    ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);
const address = value => typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
const uint64 = value => typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) < 2n ** 64n;
function message(type, value) {
  need(value && typeof value === "object" && !Array.isArray(value), type + " object");
  const fields = ownershipTypes[type];
  need(Object.keys(value).length === fields.length && fields.every(({ name }) => name in value), type + " fields");
  for (const { name, type: kind } of fields) {
    need(kind === "address" ? address(value[name]) : kind === "bytes32"
      ? typeof value[name] === "string" && /^0x[0-9a-fA-F]{64}$/.test(value[name]) : uint64(value[name]), type + " " + name);
  }
  return Object.fromEntries(fields.map(({ name }) => [name, name === "nonce" ? value[name] : value[name].toLowerCase()]));
}
function signed(domain, type, value, signature, signer) {
  need(verifyTypedData(domain, { [type]: ownershipTypes[type] }, value, signature).toLowerCase() === signer,
    type + " signature");
}
export function ownershipState(raw = {}) {
  if (raw.heartbeats) return raw;
  return { heartbeats: raw, links: {}, kids: {}, nonces: { publishers: {}, kids: {} }, revocations: {} };
}
export function ownershipView(state, domain, url) {
  const publisher = url.searchParams.get("publisher")?.toLowerCase();
  const kid = url.searchParams.get("kid")?.toLowerCase();
  const operator = url.searchParams.get("operator")?.toLowerCase();
  return { domain,
    links: Object.values(state.links).filter(r => (!publisher || r.link.publisher === publisher) && (!kid || r.link.kid === kid) && (!operator || r.link.operator === operator)),
    revocations: Object.values(state.revocations).filter(r => !operator || r.revocation.operator === operator),
    nonces: {
      publishers: Object.fromEntries(Object.entries(state.nonces.publishers).filter(([p]) => !publisher || p === publisher)),
      kids: Object.fromEntries(Object.entries(state.nonces.kids).filter(([k, publishers]) => (!kid || k === kid) && (!publisher || publisher in publishers))
        .map(([k, publishers]) => [k, publisher ? publishers[publisher] : publishers])),
    },
  };
}
export function applyOwnership(state, domain, action, body) {
  need(domain.verifyingContract && address(domain.verifyingContract), "ownership escrow not configured");
  if (action === "revoke-provisioner") {
    const revocation = message("ProvisionerRevocation", body.revocation);
    signed(domain, "ProvisionerRevocation", revocation, body.signature, revocation.operator);
    const key = revocation.operator + ":" + revocation.provisioner;
    const previous = state.revocations[key];
    const record = { revocation, signature: body.signature };
    if (previous && canonical(previous) === canonical(record)) return previous;
    need(!previous || BigInt(revocation.nonce) > BigInt(previous.revocation.nonce), "stale provisioner revocation");
    state.revocations[key] = record;
    return record;
  }
  need(action === "link" || action === "unlink", "ownership action");
  const type = action === "link" ? "MacLink" : "MacUnlink";
  const value = message(type, body[action === "link" ? "link" : "unlink"]);
  signed(domain, type, value, body.publisherSignature, value.publisher);
  let record;
  if (action === "link") {
    need(!(body.operatorSignature && body.authorization), "choose operator or provisioner signature");
    record = { link: value, publisherSignature: body.publisherSignature, linkage_scope: "publisher_operator" };
    if (body.operatorSignature) {
      signed(domain, type, value, body.operatorSignature, value.operator);
      record.operatorSignature = body.operatorSignature;
    } else {
      need(body.authorization, "operator authorization required");
      const authorization = message("ProvisioningAuthorization", body.authorization.authorization);
      need(authorization.operator === value.operator, "authorization operator");
      signed(domain, "ProvisioningAuthorization", authorization, body.authorization.signature, value.operator);
      const revoked = state.revocations[authorization.operator + ":" + authorization.provisioner];
      need(!revoked, "provisioner revoked");
      signed(domain, type, value, body.provisionerSignature, authorization.provisioner);
      record.authorization = { authorization, signature: body.authorization.signature };
      record.provisionerSignature = body.provisionerSignature;
    }
    const prior = state.links[value.publisher];
    if (prior && canonical(prior) === canonical(record)) return prior;
  } else {
    record = { unlink: value, publisherSignature: body.publisherSignature };
    if (!state.links[value.publisher] && state.unlinks?.[value.publisher] && canonical(state.unlinks[value.publisher]) === canonical(record)) return record;
    const prior = state.links[value.publisher];
    need(prior && prior.link.kid === value.kid && prior.link.operator === value.operator, "active Mac link required");
  }
  for (const previous of [state.nonces.publishers[value.publisher], state.nonces.kids[value.kid]?.[value.publisher]]) {
    need(previous === undefined || BigInt(value.nonce) > BigInt(previous), "stale Mac nonce");
  }
  const displaced = [state.links[value.publisher]].filter(Boolean);
  for (const prior of displaced) {
    delete state.links[prior.link.publisher];
    delete state.kids[prior.link.kid][prior.link.publisher];
    if (!Object.keys(state.kids[prior.link.kid]).length) delete state.kids[prior.link.kid];
  }
  state.nonces.publishers[value.publisher] = value.nonce;
  state.nonces.kids[value.kid] ??= {};
  state.nonces.kids[value.kid][value.publisher] = value.nonce;
  if (action === "link") {
    state.links[value.publisher] = record;
    state.kids[value.kid] ??= {};
    state.kids[value.kid][value.publisher] = true;
  } else {
    state.unlinks ??= {};
    state.unlinks[value.publisher] = record;
  }
  return record;
}
