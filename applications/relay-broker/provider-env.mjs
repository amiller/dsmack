import { verifyMessage, Wallet } from "../payments/schema.mjs";
import { canonical } from "./grants.mjs";

const enc = new TextEncoder();
const context = { purpose: "dsmack-near-env/1", project: "relay-broker" };
const aad = enc.encode(canonical(context));
const fields = new Set([
  "NEAR_API_KEY",
]);
const pubkey = (v) => typeof v === "string" && /^0x04[0-9a-fA-F]{128}$/.test(v);
const hex = (v) =>
  Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
const bytes = (v) => Uint8Array.from(v.match(/../g), (b) => parseInt(b, 16));
const need = (ok) => {
  if (!ok) throw new Error("provider environment refused");
};

function payload(value) {
  need(value && typeof value === "object" && !Array.isArray(value));
  const names = Object.keys(value);
  need(
    names.length > 0 && names.every((name) =>
      fields.has(name) &&
      typeof value[name] === "string" && value[name].length > 0
    ),
  );
  const raw = enc.encode(JSON.stringify(value));
  need(raw.length <= 65536);
  return raw;
}

async function aes(wallet, otherPublicKey) {
  need(pubkey(otherPublicKey));
  // ethers returns an uncompressed ECDH point. Use its 32-byte X coordinate,
  // matching conventional secp256k1 ECDH implementations.
  const shared = bytes(
    wallet.signingKey.computeSharedSecret(otherPublicKey).slice(2),
  ).slice(1, 33);
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: await crypto.subtle.digest("SHA-256", aad),
      info: aad,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function info(encryptionWallet, paymentWallet) {
  try {
    const publicKey = encryptionWallet.signingKey.publicKey;
    need(pubkey(publicKey));
    const signature = await paymentWallet.signMessage(
      canonical({ ...context, publicKey }),
    );
    return { publicKey, signature, signer: paymentWallet.address };
  } catch {
    throw new Error("provider environment key unavailable");
  }
}

export async function encryptEnvelope(
  publicInfo,
  secrets,
  expectedPaymentSigner,
) {
  try {
    need(
      publicInfo && pubkey(publicInfo.publicKey) &&
        /^0x[0-9a-fA-F]{40}$/.test(expectedPaymentSigner),
    );
    const signer = verifyMessage(
      canonical({ ...context, publicKey: publicInfo.publicKey }),
      publicInfo.signature,
    );
    need(
      signer.toLowerCase() === expectedPaymentSigner.toLowerCase() &&
        publicInfo.signer?.toLowerCase() ===
          expectedPaymentSigner.toLowerCase(),
    );
    const raw = payload(secrets), ephemeral = Wallet.createRandom();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await aes(ephemeral, publicInfo.publicKey);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      raw,
    );
    return {
      v: 1,
      ephemeralPublicKey: ephemeral.signingKey.publicKey,
      iv: hex(iv),
      ciphertext: hex(new Uint8Array(encrypted)),
    };
  } catch {
    throw new Error("provider environment encryption refused");
  }
}

export async function decryptEnvelope(envelope, encryptionWallet) {
  try {
    need(
      envelope && typeof envelope === "object" && envelope.v === 1 &&
        pubkey(envelope.ephemeralPublicKey) &&
        /^[0-9a-f]{24}$/.test(envelope.iv) &&
        typeof envelope.ciphertext === "string" &&
        envelope.ciphertext.length >= 32 &&
        envelope.ciphertext.length <= 131104 &&
        /^(?:[0-9a-f]{2})+$/.test(envelope.ciphertext),
    );
    const key = await aes(encryptionWallet, envelope.ephemeralPublicKey);
    const raw = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes(envelope.iv), additionalData: aad },
      key,
      bytes(envelope.ciphertext),
    );
    const secrets = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(raw),
    );
    payload(secrets);
    return secrets;
  } catch {
    throw new Error("provider environment decryption refused");
  }
}
