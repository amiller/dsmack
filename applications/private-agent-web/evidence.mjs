import { computeAddress } from "ethers";
const usedNonces = new Set();
const require = (ok, message) => {
  if (!ok) throw new Error(message);
};
export const PRIVACY =
  "Messages encrypted in browser to the NEAR model TEE; broker meters ciphertext.";
export function checkEvidence(
  e,
  model,
  started,
  expectedNonce,
  modelPublicKey,
) {
  require(
    e && e.provider === "near" && e.model === model &&
      e.verification === "verified" &&
      e.mode === "broker-e2ee",
    "Provider attestation is invalid or names another model.",
  );
  require(
    /^[0-9a-f]{64}$/.test(expectedNonce) && e.nonce === expectedNonce &&
      !usedNonces.has(e.nonce),
    "Provider attestation has a stale or reused nonce.",
  );
  require(
    Number.isSafeInteger(e.verifiedAt) &&
      e.verifiedAt * 1000 >= started - 30000 &&
      e.verifiedAt * 1000 <= Date.now() + 30000,
    "Provider attestation is stale. No prompt sent.",
  );
  const verified = e.models?.find((m) => m.model === model && m.signingAddress);
  require(
    e.verifier && e.gateway?.signingAddress && e.gateway?.tlsFingerprint &&
      verified,
    "Provider attestation is missing gateway or per-model evidence.",
  );
  require(
    e.tls?.checkedBy === "broker" && e.tls.browserObservable === false &&
      e.tls.binding === "spki",
    "Provider TLS channel was not pinned by the broker.",
  );
  require(
    typeof modelPublicKey === "string" &&
      /^(0x)?[0-9a-fA-F]+$/.test(modelPublicKey),
    "Attested model encryption key is missing.",
  );
  let raw = modelPublicKey.replace(/^0x/, "");
  if (raw.length === 128) raw = "04" + raw;
  let address;
  try {
    address = computeAddress("0x" + raw);
  } catch {
    throw new Error("Model encryption key is invalid. No prompt sent.");
  }
  require(
    address.toLowerCase() === verified.signingAddress.toLowerCase(),
    "Model encryption key differs from the attested signing address. No prompt sent.",
  );
  usedNonces.add(e.nonce);
  return {
    ...e,
    browser: {
      nonceMatched: true,
      modelKeyMatched: true,
      fullQuoteVerifiedBy: "broker",
      promptEncryptedIn: "browser",
      responseDecryptedIn: "browser",
    },
  };
}
