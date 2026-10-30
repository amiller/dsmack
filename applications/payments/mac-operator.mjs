import { applyOwnership, ownershipDomain, ownershipState } from "../relay-broker/ownership.mjs";

// Verify the signatures before letting a broker response select an escrow payee.
export function linkedOperator(response, escrow, publisher, kid) {
  const domain = ownershipDomain(escrow);
  if (JSON.stringify(response.domain) !== JSON.stringify(domain)) throw Error("Mac ownership domain differs");
  const record = response.links.find(r => r.link.publisher.toLowerCase() === publisher.toLowerCase() &&
    r.link.kid.toLowerCase() === kid.toLowerCase());
  if (!record) throw Error("active Mac ownership link required");
  return applyOwnership(ownershipState(), domain, "link", record).link.operator;
}
