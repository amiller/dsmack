// LaunchSpecBuilderV3.swift — the v3 launch-spec document + digest. It binds
// the boot/workload tuple, the admitted blank-template identities for the two
// fresh RW disks (vdb scratch, vdd result) and the runtime_input (vde) / NIC
// presence flags, so spec_sha256 — the consumed-tuple commitment the backend
// echoes in its receipt — covers the device shape too. The backend consumes spec_sha256 opaquely
// (syntax-checked) and re-verifies every expectation against the bytes/devices
// it actually consumes; this digest is the app/verifier-side commitment.

import CryptoKit
import Foundation

let launchSpecV3Schema = "dsmack-general-launcher/launch-spec-v3/1"

func buildLaunchSpecV3(
    plan: LaunchPlan, identity: VerifiedImageIdentity, contract: ContractAdmission,
    policy: AdmissionPolicy, manifest: ImageManifest, workloadSha256: String, workloadId: String,
    templates: AdmittedTemplatesV3, privatePresent: Bool, netPresent: Bool
) throws -> (doc: [String: Any], bytes: Data, specSha256: String) {
    let doc: [String: Any] = [
        "schema": launchSpecV3Schema,
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
        // ---- v3: admitted blank-template identities for the fresh RW disks ----
        "scratch_template_sha256": templates.scratchSha256,
        "scratch_template_bytes": templates.scratchBytes,
        "result_template_sha256": templates.resultSha256,
        "result_template_bytes": templates.resultBytes,
        // ---- v3: device shape (vde unmeasured — PRESENCE only, never content) ----
        "runtime_input_present": privatePresent,
        "net_present": netPresent,
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
