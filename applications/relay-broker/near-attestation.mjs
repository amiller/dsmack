// NEAR's verifier authenticates Intel TDX, MRCONFIGID/RTMR3, signer and nonce,
// and NVIDIA GPU evidence. Its Node transport checks the TLS peer before sending
// request bytes. Keep plaintext prompt fields inside this broker and the model.
import {
  createPinnedTlsFetch,
  prepareE2eeChatRequest,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from "npm:@nearai/inference-sdk@0.2.0/node";

const need = (ok) => {
  if (!ok) throw new Error("NEAR attestation rejected");
};
function normalized(raw) {
  need(raw && raw.signing_algo === "ecdsa");
  const tcb = typeof raw.info?.tcb_info === "string"
    ? JSON.parse(raw.info.tcb_info)
    : raw.info?.tcb_info;
  need(tcb && typeof tcb.app_compose === "string");
  return {
    nonce: raw.request_nonce,
    signer: {
      signingAlgo: raw.signing_algo,
      signingAddress: raw.signing_address,
    },
    intelQuote: raw.intel_quote,
    eventLog: tcb.event_log ?? raw.event_log,
    appCompose: tcb.app_compose,
    ...(raw.report_data ? { reportedQuoteData: raw.report_data } : {}),
  };
}
function deploymentPolicy(allowed) {
  return (deployment) => {
    need(
      Array.isArray(allowed) && allowed.length > 0 &&
        allowed.includes(deployment.runtimeMeasurements.composeHash),
    );
  };
}
const summary = (v) => ({
  signingAddress: v.signer.signingAddress,
  tcbStatus: v.tcbStatus,
  signing_algo: v.signer.signingAlgo,
  signing_address: v.signer.signingAddress,
  tcb_status: v.tcbStatus,
  advisory_ids: v.advisoryIds,
  compose_hash: v.deployment.runtimeMeasurements.composeHash,
  os_image_hash: v.deployment.runtimeMeasurements.osImageHash,
  ...(v.gpuEvidence ? { gpu_evidence: v.gpuEvidence } : {}),
});

export async function verifyNearAttestation(
  { report, nonce, model, baseUrl, policy },
) {
  need(/^[0-9a-f]{64}$/.test(nonce) && new URL(baseUrl).protocol === "https:");
  const rawGateway = report.gateway_attestation;
  need(rawGateway && /^[0-9a-f]{64}$/.test(rawGateway.tls_cert_fingerprint));
  const gatewayAttestation = {
    ...normalized(rawGateway),
    spkiFingerprint: rawGateway.tls_cert_fingerprint,
  };
  // First authenticate the quote binding; then actually check this key on the
  // peer. No inference or credentials cross this channel before both pass.
  const gateway = await verifyGatewayAttestation({
    attestation: gatewayAttestation,
    clientBinding: { nonce, spkiFingerprint: rawGateway.tls_cert_fingerprint },
    policy: { acceptedTcbStatuses: ["UpToDate"] },
    verifiers: { deployment: deploymentPolicy(policy?.gatewayComposeHashes) },
  });
  need(gateway.tlsBinding.kind === "attested");
  const pinnedFetch = createPinnedTlsFetch(gateway.tlsBinding.spkiFingerprint);
  const probe = await pinnedFetch(baseUrl + "/v1/models", {
    method: "HEAD",
    signal: AbortSignal.timeout(30000),
  });
  await probe.body?.cancel();
  need(
    Array.isArray(report.model_attestations) &&
      report.model_attestations.length > 0,
  );
  const models = await Promise.all(
    report.model_attestations.map(async (raw) => {
      need(raw.model_name === model);
      const attestation = {
        ...normalized(raw),
        signingPublicKey: raw.signing_public_key,
        nvidiaPayload: raw.nvidia_payload,
      };
      if (raw.compose_manager_attestation) {
        const manager = raw.compose_manager_attestation;
        attestation.composeManagerAttestation = {
          actions: manager.actions,
          actionsHash: manager.actions_hash,
          nonce: manager.nonce,
          intelQuote: manager.quote,
          eventLog: manager.event_log,
          reportedQuoteData: manager.report_data,
        };
      }
      return await verifyModelAttestation({
        attestation,
        clientBinding: { nonce },
        policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" },
        verifiers: { deployment: deploymentPolicy(policy?.modelComposeHashes) },
      });
    }),
  );
  need(
    models.every((m) =>
      typeof m.signingPublicKey === "string" && m.gpuEvidence === "verified"
    ),
  );
  const verifiedAt = Math.floor(Date.now() / 1000);
  let closed = false;
  return {
    modelPublicKey: models[0].signingPublicKey,
    evidence: {
      verified: true,
      verification: "verified",
      verificationScope: "preflight",
      verifier: "@nearai/inference-sdk@0.2.0",
      privacy: "NEAR TEE model via broker CVM; broker handles plaintext",
      provider: "near",
      model,
      nonce,
      mode: "broker-proxy",
      verifiedAt,
      verified_at: verifiedAt,
      expires_at: verifiedAt + 60,
      tls: {
        checkedBy: "broker",
        browserObservable: false,
        binding: "spki",
        status: "verified-by-broker",
        spki_sha256: gateway.tlsBinding.spkiFingerprint,
      },
      gateway: {
        ...summary(gateway),
        tlsFingerprint: gateway.tlsBinding.spkiFingerprint,
      },
      models: models.map((m) => ({ ...summary(m), model })),
      report,
    },
    transport: {
      close() {
        closed = true;
      },
      async fetchEncrypted(input, init) {
        need(
          !closed &&
            new URL(input instanceof Request ? input.url : input).origin ===
              new URL(baseUrl).origin,
        );
        return await pinnedFetch(input, init);
      },
      async fetch(input, init) {
        need(
          !closed &&
            new URL(input instanceof Request ? input.url : input).origin ===
              new URL(baseUrl).origin,
        );
        const prepared = await prepareE2eeChatRequest({
          request: new Request(input, init),
          modelKey: {
            signingAlgo: "ecdsa",
            publicKey: models[0].signingPublicKey,
          },
        });
        const response = await pinnedFetch(prepared.request);
        return prepared.decryptResponse(response);
      },
    },
  };
}
