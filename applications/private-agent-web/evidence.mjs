const usedNonces = new Set();
const require = (ok, message) => {
  if (!ok) throw new Error(message);
};
export const PRIVACY =
  "NEAR TEE model via broker CVM; broker handles plaintext";
export function checkEvidence(e, model, started, expectedNonce) {
  require(
    !model.startsWith("anthropic/"),
    "This routed model is not a private TEE model.",
  );
  require(
    e && e.mode === "broker-proxy" && e.provider === "near" &&
      e.model === model && e.verification === "verified",
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
    "Provider attestation is stale. No answer accepted.",
  );
  require(
    e.verifier && e.gateway?.signingAddress && e.gateway?.tlsFingerprint &&
      e.models?.some((m) => m.model === model && m.signingAddress),
    "Provider attestation is missing gateway or per-model evidence.",
  );
  require(
    e.tls?.checkedBy === "broker" && e.tls.browserObservable === false &&
      e.tls.binding === "spki",
    "Provider TLS channel was not pinned by the broker.",
  );
  usedNonces.add(e.nonce);
  return e;
}
