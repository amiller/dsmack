// LaunchSpecBuilder.swift — the canonical launch-spec document and its
// digest, the value the backend ABI calls `spec_sha256` (mac-app-join lane,
// 2026-10-21; fable-native-audit F7 action item).
//
// EXACT IDENTITY MAPPING (all three digests recorded together, none
// hardcoded — every value arrives from external admitted inputs):
//
//   spec_sha256 (backend ABI field)
//     = sha256(canonical "dsmack-general-launcher/launch-spec/1" bytes)
//     = the launcher-world CONSUMED-TUPLE digest: the complete set of
//       expectations the app derived from the admitted inputs and handed
//       to the backend. Any verifier holding the same session inputs can
//       recompute it byte-for-byte (deterministic canonical serialization).
//     It is NEITHER the contract10 os_image_hash NOR the launcher
//       image_manifest_sha256 — it is derived FROM them and cross-checks
//       them (the document carries all three).
//
//   os_image_hash  (contract10 world)  — see DstackIdentity.swift.
//   image_manifest_sha256 (launcher world, what the policy admits).
//
// The backend consumes spec_sha256 opaquely (syntax-checked only) and
// re-verifies every expectation against the bytes/devices it actually
// consumes; admission authentication stays on the app/verifier side.

import CryptoKit
import Foundation

let launchSpecSchema = "dsmack-general-launcher/launch-spec/1"

/// Build the canonical launch-spec document from fully-verified inputs and
/// return (document, canonical bytes, spec_sha256).
func buildLaunchSpec(
    plan: LaunchPlan, identity: VerifiedImageIdentity, contract: ContractAdmission,
    policy: AdmissionPolicy, manifest: ImageManifest, workloadSha256: String, workloadId: String
) throws -> (doc: [String: Any], bytes: Data, specSha256: String) {
    let doc: [String: Any] = [
        "schema": launchSpecSchema,
        // ---- launcher-world admission identity ----
        "policy_id": policy.policyId,
        "policy_sha256": policy.sha256,
        "image_id": plan.imageId,
        "image_manifest_sha256": plan.manifestSha256,
        "admitted_by": plan.admittedBy,
        // ---- contract10-world identity (the F7 bridge, verified upstream) ----
        "os_image_hash": identity.osImageHash,
        "admission_sha256": contract.admissionSha256,
        "admission_version": contract.version,
        "metadata_sha256": identity.metadataSha256,
        // ---- the consumed boot tuple (what the backend receives) ----
        "cmdline": plan.cmdline,
        "cmdline_sha256": identity.cmdlineSha256,
        "kernel_sha256": manifest.kernel.sha256,
        "initrd_sha256": manifest.initrd.sha256,
        "system_disk_sha256": manifest.systemDisk.sha256,
        "system_disk_bytes": manifest.systemDisk.bytes,
        "verity_root_hash": manifest.verityRootHash,
        // ---- workload transport (untrusted content, read-only disk) ----
        "workload_sha256": workloadSha256,
        "workload_id": workloadId,
        // ---- bounded resources (declared profile within policy caps) ----
        "profile_name": plan.profileName,
        "profile_basis": plan.profileBasis,
        "ram_mib": plan.memMib,
        "vcpus": plan.vcpus,
        "runtime_seconds": plan.runtimeSeconds,
        "arch": plan.arch,
    ]
    let bytes = try canonicalJSONData(doc)
    return (doc, bytes, sha256hex(bytes))
}
