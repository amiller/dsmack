// AssertionEvidence.swift — the ACTUAL contract10 domain-separated
// receipt-evidence assertion for the v2 launch path (mac-runtime-seam-repair
// lane, 2026-10-21). This replaces the prior "parallel statement" binding, in
// which the App Attest assertion signed a bare SHA256 over a bespoke
// `dsmack-general-launcher/v2-run-statement/1` document (V2Launch.swift) that
// no contract10 relying party could reconstruct or verify.
//
// The frozen contract10 attestation surface (contract10/candidate/lib/
// dsmack_compose_contract/attestation.py + interfaces/mac-attestation-interface.md)
// defines TWO domain-separated preimages; we implement BOTH, byte-for-byte:
//
//   EVIDENCE_DOMAIN = "dsmack.receipt-evidence/4"
//     evidence_sha256 = sha256( canonical([ EVIDENCE_DOMAIN, body ]) )
//     body = {                      # execution_evidence_digest()'s EXACT body
//       "attestation": null,        #   bound separately via attestation_sha256
//       "base_vm": <receipt.base_vm>,
//       "base_vm_launch": <receipt.base_vm_launch>,
//       "harness_sha256": <receipt.harness_sha256>,         # None if absent
//       "manifest_sha256": <receipt.manifest_sha256>,       # None if absent
//       "observed": <receipt.observed>,
//       "outputs": <receipt.outputs>,                       # None if absent
//       "run_id": <receipt.run_id>,                         # None if absent
//       "runtime_inputs_commitment": <receipt.runtime_inputs_commitment>,
//     }
//     The launcher populates base_vm, base_vm_launch and observed (which it
//     genuinely observed) plus manifest_sha256 = sha256(the exact submitted
//     app-compose manifest bytes), the value contract10 verify_attestation
//     re-hashes (attestation.py:875) and the compose-runner computes the same
//     way (dsmack_compose_runner sha256_hex(manifest_bytes)). This is DISTINCT
//     from the image-manifest digest (N02; mac-source-integration-early).
//     The compose-runner-world members (harness_sha256, outputs, run_id,
//     runtime_inputs_commitment) are EXPLICIT null — exactly what
//     execution_evidence_digest() yields for a partial receipt
//     (`receipt.get(k)` → None). We do NOT fabricate those fields; the
//     compose-runner lane composes the full receipt downstream, and the
//     fragment↔full-receipt evidence-digest continuity (N03) is reconciled at
//     the integration gate, not claimed here.
//
//   ASSERTION_DOMAIN = "dsmack.appattest.assertion/4"
//     the exact bytes the app signs (interfaces/mac-attestation-interface.md):
//       ASSERTION_DOMAIN \0 manifest_sha256 \0 evidence_sha256 \0 challenge [\0 counter]
//     The App Attest assertion counter binds via the authenticatorData the
//     verifier extracts (AppAttestVerify.verifyAssertion: nonce = authData ||
//     sha256(clientData); counter compared separately via expectedCounter), so
//     the attester's clientData carries the first FOUR domain-separated parts;
//     the fifth (counter) is bound by authData, not by what the app hashes.
//     This divergence from assertion_payload()'s 5-part model form (used by the
//     offline verifier stand-in) is called out in the next-review packet for
//     explicit reconciliation at the fresh source gate.

import CryptoKit
import Foundation

let assertionDomain = "dsmack.appattest.assertion/4"
let evidenceDomain = "dsmack.receipt-evidence/4"

/// Build the contract10 receipt-evidence body for the launcher's partial
/// receipt. Compose-runner-world members are explicit null (NSNull), matching
/// execution_evidence_digest()'s `receipt.get(k)` → None for absent keys.
func launcherEvidenceBody(baseVm: [String: Any], baseVmLaunch: [String: Any],
                          observed: [String: Any], manifestSha256: String) -> [String: Any] {
    return [
        "attestation": NSNull(),
        "base_vm": baseVm,
        "base_vm_launch": baseVmLaunch,
        "harness_sha256": NSNull(),
        "manifest_sha256": manifestSha256,
        "observed": observed,
        "outputs": NSNull(),
        "run_id": NSNull(),
        "runtime_inputs_commitment": NSNull(),
    ]
}

/// execution_evidence_digest(): domain-separated sha256 over the canonical
/// serialization of [EVIDENCE_DOMAIN, body].
func executionEvidenceDigest(_ body: [String: Any]) throws -> String {
    sha256hex(try canonicalJSONData([evidenceDomain, body]))
}

/// The exact client-data bytes the App Attest assertion signs: the contract10
/// domain-separated assertion payload binding the submitted compose-manifest
/// digest (sha256 of the exact app-compose manifest bytes — NOT the image
/// manifest digest; N02), the receipt-evidence digest and the fresh challenge
/// (counter binds via authenticatorData). NUL-joined, matching
/// assertion_payload()'s byte layout.
func assertionClientData(manifestSha256: String, evidenceSha256: String, challenge: String) throws -> Data {
    guard isHex64(manifestSha256) else { throw Fail("assertion manifest_sha256 must be 64-hex") }
    guard isHex64(evidenceSha256) else { throw Fail("assertion evidence_sha256 must be 64-hex") }
    guard !challenge.isEmpty, !challenge.utf8.contains(0) else {
        throw Fail("assertion challenge must be a non-empty string without NUL")
    }
    var out = Data()
    let nul = Data([0x00])
    out.append(Data(assertionDomain.utf8)); out.append(nul)
    out.append(Data(manifestSha256.utf8)); out.append(nul)
    out.append(Data(evidenceSha256.utf8)); out.append(nul)
    out.append(Data(challenge.utf8))
    return out
}
