import { Wallet } from "ethers";
import { store, require, walletBody } from "./credit.mjs";

export const RP_ID = "private-agent.dstack.soc1024.com";
const utf8 = new TextEncoder();
export const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
export const unb64 = (text) => Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
const random = (size = 32) => crypto.getRandomValues(new Uint8Array(size));
const prfInput = utf8.encode("dsmack private agent key wrapping v1");

export async function seal(key, value, context) {
  const iv = random(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv,
    additionalData: utf8.encode(context) }, key, utf8.encode(JSON.stringify(value)));
  return { v: 1, iv: b64(iv), ciphertext: b64(ciphertext) };
}
export async function open(key, envelope, context) {
  require(envelope?.v === 1, "Unsupported key wrap.");
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(envelope.iv),
    additionalData: utf8.encode(context) }, key, unb64(envelope.ciphertext));
  return JSON.parse(new TextDecoder().decode(plain));
}
async function kek(result) {
  require(result?.byteLength === 32,
    "This passkey does not support PRF. Link this device using the QR code from your other device.");
  const material = await crypto.subtle.importKey("raw", result, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256",
    salt: utf8.encode(RP_ID), info: utf8.encode("dsmack/passkey-wrap/v1") },
  material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
function checkOrigin() {
  require(location.hostname === RP_ID && location.protocol === "https:",
    "Open https://" + RP_ID + " to use a passkey. You can link keys from this origin.");
}
async function evaluate(credentialId) {
  const credential = await navigator.credentials.get({ publicKey: {
    challenge: random(), rpId: RP_ID, userVerification: "required", timeout: 60000,
    ...(credentialId ? { allowCredentials: [{ type: "public-key", id: unb64(credentialId) }] } : {}),
    extensions: { prf: { eval: { first: prfInput } } },
  } });
  require(credential, "No passkey was selected.");
  return { credentialId: b64(credential.rawId),
    key: await kek(credential.getClientExtensionResults().prf?.results?.first) };
}

export class DeviceKeys {
  async init() {
    const bundle = await store("continuity.keys");
    const legacy = !bundle && await store("burner");
    if (bundle || legacy) await this.import(bundle || { v: 1, dk: b64(random()), walletKey: legacy });
    return this;
  }
  async create() {
    if (!this.bundle) await this.import({ v: 1, dk: b64(random()), walletKey: Wallet.createRandom().privateKey });
    return this.bundle;
  }
  async import(bundle) {
    require(bundle?.v === 1 && unb64(bundle.dk).length === 32,
      "Invalid device key bundle.");
    const wallet = new Wallet(bundle.walletKey);
    const previous = await store("continuity.keys");
    const previousKey = previous?.walletKey || await store("burner");
    if (previousKey !== wallet.privateKey) {
      await store("purchases", []);
      await store("continuity.passkey", null);
      await store("continuity.email", null);
      await store("continuity.imported", !!previousKey);
    }
    this.address = wallet.address;
    this.bundle = { v: 1, dk: bundle.dk, walletKey: wallet.privateKey };
    await store("continuity.keys", this.bundle);
    await store("burner", wallet.privateKey);
    return this.bundle;
  }
  async addPasskey({ credit, api }) {
    require(this.bundle, "Choose Start fresh or recover your wallet before adding a passkey.");
    checkOrigin();
    const credential = await navigator.credentials.create({ publicKey: {
      challenge: random(), rp: { id: RP_ID, name: "Dsmack private agent" },
      user: { id: random(), name: credit.address, displayName: "Private agent" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none", timeout: 60000, extensions: { prf: { eval: { first: prfInput } } },
    } });
    require(credential, "No passkey was created.");
    const credentialId = b64(credential.rawId);
    const extension = credential.getClientExtensionResults().prf;
    require(extension?.enabled || extension?.results,
      "This passkey does not support PRF. Link this device using the QR code from your other device.");
    // Some authenticators evaluate only on get(), after creating the credential.
    const key = extension.results?.first ? await kek(extension.results.first)
      : (await evaluate(credentialId)).key;
    const envelope = await seal(key, this.bundle, "dsmack/passkey/" + credentialId);
    await api("/sync/wrap/put", await walletBody(credit, "sync-wrap-put", { credentialId, envelope }));
    await store("continuity.passkey", credentialId);
    return credentialId;
  }
  async recoverPasskey({ api }) {
    checkOrigin();
    const { credentialId, key } = await evaluate();
    const record = await api("/sync/wrap/get", { credentialId });
    await this.import(await open(key, record.envelope, "dsmack/passkey/" + credentialId));
    await store("continuity.passkey", credentialId);
    return this.bundle;
  }
}
