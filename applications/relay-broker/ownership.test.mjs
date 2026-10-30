import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "../payments/schema.mjs";
import { applyOwnership, ownershipDomain, ownershipState, ownershipTypes } from "./ownership.mjs";

const domain = ownershipDomain("0x" + "17".repeat(20));
const kid = "0x" + "42".repeat(32);
const sign = (wallet, type, value) => wallet.signTypedData(domain, { [type]: ownershipTypes[type] }, value);
async function delegated(operator, provisioner, publisher, nonce, authorizationNonce = "0", key = kid) {
  const authorization = { operator: operator.address, provisioner: provisioner.address, nonce: authorizationNonce };
  const link = { kid: key, publisher: publisher.address, operator: operator.address, nonce };
  return { link, authorization: { authorization, signature: await sign(operator, "ProvisioningAuthorization", authorization) },
    provisionerSignature: await sign(provisioner, "MacLink", link), publisherSignature: await sign(publisher, "MacLink", link) };
}

test("a Mac needs both operator authorization and its own countersignature", async () => {
  const state = ownershipState(), operator = Wallet.createRandom(), provisioner = Wallet.createRandom(), publisher = Wallet.createRandom();
  const body = await delegated(operator, provisioner, publisher, "0");
  assert.throws(() => applyOwnership(state, domain, "link", { ...body, authorization: undefined }), /authorization required/);
  assert.throws(() => applyOwnership(state, domain, "link", { ...body, publisherSignature: body.provisionerSignature }), /MacLink signature/);
  const impostor = Wallet.createRandom();
  const forged = { ...body, authorization: { ...body.authorization, signature: await sign(impostor, "ProvisioningAuthorization", body.authorization.authorization) } };
  assert.throws(() => applyOwnership(state, domain, "link", forged), /ProvisioningAuthorization signature/);
  const linked = applyOwnership(state, domain, "link", body);
  assert.equal(linked.link.operator, operator.address.toLowerCase());
  assert.equal(linked.linkage_scope, "publisher_operator");
  assert.deepEqual(applyOwnership(state, domain, "link", body), linked);
  assert.throws(() => applyOwnership(ownershipState(), ownershipDomain("0x" + "18".repeat(20)), "link", body), /signature/);
});

test("higher Mac nonce transfers an identity; unlink tombstones prevent old owner resurrection", async () => {
  const state = ownershipState(), first = Wallet.createRandom(), second = Wallet.createRandom(), provisioner = Wallet.createRandom(), publisher = Wallet.createRandom();
  const original = await delegated(first, provisioner, publisher, "0");
  applyOwnership(state, domain, "link", original);
  const transferred = await delegated(second, provisioner, publisher, "1");
  applyOwnership(state, domain, "link", transferred);
  assert.equal(state.links[publisher.address.toLowerCase()].link.operator, second.address.toLowerCase());
  assert.throws(() => applyOwnership(state, domain, "link", original), /stale Mac nonce/);
  const unlink = { ...transferred.link, nonce: "2" };
  const body = { unlink, publisherSignature: await sign(publisher, "MacUnlink", unlink) };
  applyOwnership(state, domain, "unlink", body);
  assert.deepEqual(applyOwnership(state, domain, "unlink", body), { ...body, unlink: { ...unlink, publisher: publisher.address.toLowerCase(), operator: second.address.toLowerCase() } });
  assert.deepEqual(state.links, {});
  assert.throws(() => applyOwnership(state, domain, "link", transferred), /stale Mac nonce/);
  const direct = { ...transferred.link, nonce: "3" };
  const result = applyOwnership(state, domain, "link", { link: direct, operatorSignature: await sign(second, "MacLink", direct), publisherSignature: await sign(publisher, "MacLink", direct) });
  assert.equal(result.link.nonce, "3");
});

test("revoked provisioners stay retired; existing links survive and a fresh key can add Macs", async () => {
  const state = ownershipState(), operator = Wallet.createRandom(), provisioner = Wallet.createRandom(), publisher = Wallet.createRandom();
  applyOwnership(state, domain, "link", await delegated(operator, provisioner, publisher, "0"));
  const revocation = { operator: operator.address, provisioner: provisioner.address, nonce: "0" };
  const body = { revocation, signature: await sign(operator, "ProvisionerRevocation", revocation) };
  const record = applyOwnership(state, domain, "revoke-provisioner", body);
  assert.deepEqual(applyOwnership(state, domain, "revoke-provisioner", body), record);
  assert(state.links[publisher.address.toLowerCase()]);
  const refused = await delegated(operator, provisioner, Wallet.createRandom(), "0");
  assert.throws(() => applyOwnership(state, domain, "link", refused), /provisioner revoked/);
  const newer = await delegated(operator, provisioner, publisher, "1", "1");
  assert.throws(() => applyOwnership(state, domain, "link", newer), /provisioner revoked/);
  applyOwnership(state, domain, "link", await delegated(operator, Wallet.createRandom(), publisher, "1"));
  assert.equal(state.links[publisher.address.toLowerCase()].link.nonce, "1");
});

test("an unproven kid cannot displace another publisher's Mac", async () => {
  const state = ownershipState(), operator = Wallet.createRandom(), provisioner = Wallet.createRandom(), first = Wallet.createRandom(), second = Wallet.createRandom();
  applyOwnership(state, domain, "link", await delegated(operator, provisioner, first, "4"));
  const attacker = Wallet.createRandom();
  applyOwnership(state, domain, "link", await delegated(attacker, provisioner, second, "5"));
  assert.equal(Object.keys(state.links).length, 2);
  assert.equal(state.links[first.address.toLowerCase()].link.operator, operator.address.toLowerCase());
  assert.equal(state.links[second.address.toLowerCase()].link.operator, attacker.address.toLowerCase());
  const differentKid = "0x" + "43".repeat(32);
  const stale = await delegated(operator, provisioner, first, "3", "0", differentKid);
  assert.throws(() => applyOwnership(state, domain, "link", stale), /stale Mac nonce/);
  assert.throws(() => applyOwnership(state, domain, "link", { ...stale, link: { ...stale.link, nonce: "18446744073709551616" } }), /nonce/);
  applyOwnership(state, domain, "link", await delegated(operator, provisioner, first, "6", "0", differentKid));
  assert.equal(state.nonces.kids[kid][first.address.toLowerCase()], "4");
  assert.equal(state.links[second.address.toLowerCase()].link.nonce, "5");
});
