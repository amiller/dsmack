import { computeAddress } from "ethers";
import { verifyGatewayAttestation, verifyDirectModelAttestation } from "@nearai/inference-sdk";
import { getCollateral, verify } from "@phala/dcap-qvl";
import { nearVerifiers } from "../relay-broker/near-policy.mjs";
const require = (ok, message) => { if (!ok) throw new Error(message); };
export const PRIVACY = "Messages encrypted in browser to the NEAR model TEE; broker meters ciphertext.";

// NEAR format: https://docs.near.ai/cloud/verification/cloud-api/model-attestations
function normalized(raw) {
  require(raw?.signing_algo === "ecdsa", "NEAR requires an ECDSA signing identity.");
  const tcb = typeof raw.info?.tcb_info === "string" ? JSON.parse(raw.info.tcb_info) : raw.info?.tcb_info;
  require(typeof tcb?.app_compose === "string", "NEAR measured deployment is missing.");
  return { nonce: raw.request_nonce, signer: { signingAlgo: raw.signing_algo, signingAddress: raw.signing_address },
    intelQuote: raw.intel_quote, eventLog: tcb.event_log ?? raw.event_log, appCompose: tcb.app_compose,
    ...(raw.report_data ? { reportedQuoteData: raw.report_data } : {}) };
}
async function tdxQuote(quote) {
  require(/^(?:[0-9a-f]{2})+$/i.test(quote), "Invalid NEAR quote encoding.");
  const bytes = Uint8Array.from(quote.match(/../g), b => parseInt(b, 16));
  const collateral = await getCollateral("https://cloud.near.ai/api/proxy/pccs", bytes);
  const result = verify(bytes, collateral, Math.floor(Date.now() / 1000));
  const td = result.report.asTd10() || result.report.asTd15()?.base;
  require(td, "NEAR requires a TDX quote.");
  return { tcbStatus: result.status, advisoryIds: result.advisory_ids, debugEnabled: !!(td.tdAttributes[0] & 1),
    reportData: td.reportData, mrConfigId: td.mrConfigId, rtMr3: td.rtMr3 };
}
const summary = v => ({ signingAddress: v.signer.signingAddress, tcbStatus: v.tcbStatus,
  advisoryIds: v.advisoryIds, composeHash: v.deployment.runtimeMeasurements.composeHash });

export async function checkEvidence(e, model, started, expectedNonce, modelPublicKey) {
  require(e?.provider === "near" && e.model === model && e.mode === "broker-e2ee", "Provider attestation is invalid or names another model.");
  require(/^[0-9a-f]{64}$/.test(expectedNonce), "Provider attestation needs a 32-byte client challenge.");
  const report = e.report, rawGateway = report?.gateway_attestation;
  require(/^[0-9a-f]{64}$/.test(rawGateway?.tls_cert_fingerprint), "NEAR gateway TLS key binding is missing.");
  const gateway = await verifyGatewayAttestation({
    attestation: { ...normalized(rawGateway), spkiFingerprint: rawGateway.tls_cert_fingerprint },
    // This compares the quoted fingerprint binding only. Browser Fetch cannot
    // observe the live peer SPKI (NEAR's /cloud/verification/cloud-api/tls).
    clientBinding: { nonce: expectedNonce, spkiFingerprint: rawGateway.tls_cert_fingerprint },
    policy: { acceptedTcbStatuses: ["UpToDate"] },
    verifiers: nearVerifiers("gateway", rawGateway.intel_quote, tdxQuote),
  });
  require(report.model_attestations?.length > 0, "NEAR model quotes are missing.");
  const models = await Promise.all(report.model_attestations.map(async raw => {
    require(raw.model_name === model, "NEAR quote names another model.");
    const manager = raw.compose_manager_attestation;
    // include_tls_fingerprint=true also binds SPKI in current model reports.
    // The SDK's direct-report primitive handles that encoding and verifies the
    // same model CPU, deployment, compose-manager, key and GPU properties.
    const v = await verifyDirectModelAttestation({
      attestation: { ...normalized(raw), modelName: raw.model_name,
        ...(raw.tls_cert_fingerprint ? { spkiFingerprint: raw.tls_cert_fingerprint } : {}), signingPublicKey: raw.signing_public_key, nvidiaPayload: raw.nvidia_payload,
        ...(manager ? { composeManagerAttestation: { actions: manager.actions, actionsHash: manager.actions_hash,
          nonce: manager.nonce, intelQuote: manager.quote, eventLog: manager.event_log, reportedQuoteData: manager.report_data } } : {}) },
      clientBinding: { nonce: expectedNonce },
      policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" },
      verifiers: nearVerifiers("model", raw.intel_quote, tdxQuote),
    });
    require(v.signingPublicKey, "NEAR model encryption key is missing.");
    let key = modelPublicKey?.replace(/^0x/, "");
    require(/^[0-9a-f]+$/i.test(key), "Model encryption key is missing.");
    if (key.length === 128) key = "04" + key;
    require(computeAddress("0x" + key).toLowerCase() === v.signer.signingAddress.toLowerCase(),
      "Model encryption key differs from the attested signing address. No prompt sent.");
    return { ...summary(v), model, gpuEvidence: v.gpuEvidence };
  }));
  require(Date.now() - started < 60000, "NEAR attestation took too long. No prompt sent.");
  return { provider: "near", model, nonce: expectedNonce, mode: "broker-e2ee", verifiedAt: Math.floor(Date.now() / 1000),
    verification: "verified", verifier: "browser: @phala/dcap-qvl + @nearai/inference-sdk",
    gateway: { ...summary(gateway), tlsFingerprint: rawGateway.tls_cert_fingerprint }, models,
    tls: { quotedSpkiBinding: "verified-in-browser", livePeerSpki: "not-observable-in-browser" },
    browser: { nonceMatched: true, modelKeyMatched: true, fullQuoteVerifiedBy: "browser",
      gpuEvidence: "NVIDIA NRAS ES384 signature, issuer, expiry, nonce and overall result verified in browser",
      promptEncryptedIn: "browser", responseDecryptedIn: "browser" } };
}
