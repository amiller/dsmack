import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "../../payments/schema.mjs";
import { applyOwnership, ownershipState, ownershipTypes, ownershipView, ownershipDomain as brokerDomain } from "../../relay-broker/ownership.mjs";
import { brokerOwners } from "./owners.mjs";

test("brokerOwners verifies each MacLink the broker serves and drops revoked provisioners", async () => {
  const escrow = "0x835A61a88Cc8D750b5a971219aa8f9813B2067e6", domain = brokerDomain(escrow), state = ownershipState();
  const operator = Wallet.createRandom(), provisioner = Wallet.createRandom(), mac = Wallet.createRandom();
  const kid = "0x" + "e3".repeat(32), authorization = { operator: operator.address, provisioner: provisioner.address, nonce: "1" };
  const link = { kid, publisher: mac.address, operator: operator.address, nonce: "2" };
  applyOwnership(state, domain, "link", { link,
    authorization: { authorization, signature: await operator.signTypedData(domain, { ProvisioningAuthorization: ownershipTypes.ProvisioningAuthorization }, authorization) },
    publisherSignature: await mac.signTypedData(domain, { MacLink: ownershipTypes.MacLink }, link),
    provisionerSignature: await provisioner.signTypedData(domain, { MacLink: ownershipTypes.MacLink }, link) });
  const serve = () => globalThis.fetch = async (url) => new Response(JSON.stringify(ownershipView(state, domain, new URL(url))));
  const owners = brokerOwners("https://broker.invalid/fleet/ownership", escrow);
  serve();
  assert.deepEqual(await owners(kid), [operator.address.toLowerCase()]);
  assert.deepEqual(await owners("0x" + "00".repeat(32)), []);
  await assert.rejects(brokerOwners("https://broker.invalid/fleet/ownership", "0x" + "12".repeat(20))(kid), /domain differs/);

  const forged = structuredClone(state);
  Object.values(forged.links)[0].link.operator = Wallet.createRandom().address.toLowerCase();
  globalThis.fetch = async (url) => new Response(JSON.stringify(ownershipView(forged, domain, new URL(url))));
  await assert.rejects(owners(kid), /signature|authorization/);

  const revocation = { operator: operator.address, provisioner: provisioner.address, nonce: "1" };
  applyOwnership(state, domain, "revoke-provisioner", { revocation,
    signature: await operator.signTypedData(domain, { ProvisionerRevocation: ownershipTypes.ProvisionerRevocation }, revocation) });
  serve();
  assert.deepEqual(await owners(kid), []);
});
