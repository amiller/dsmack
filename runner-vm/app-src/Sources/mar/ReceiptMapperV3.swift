// ReceiptMapperV3.swift — maps the backend v3 launch receipt
// (dsmack-backend-v3/launch-receipt/1) into the APPROVED contract10 receipt
// world (dsmack:receipt/4) fragment, cross-checking EVERY observed fact against
// the verified admission tuple BEFORE the guest runs.
//
// The receipt carries the admitted blank-template identities for the
// two fresh RW disks (vdb scratch, vdd result) and a vde PRESENCE flag. The
// mapper binds those template identities to the admitted session values too, so
// a backend that copied a DIFFERENT template than the app admitted is caught
// before any guest executes. The receipt records vde PRESENCE only — never its
// content or size (privacy invariant, receipt_v3.rs) — so the mapper reads only
// the presence flag.

import CryptoKit
import Foundation

struct MappedReceiptV3 {
    let fragment: [String: Any]   // base_vm + base_vm_launch, contract10-shaped
    let receiptSha256: String     // digest of the EXACT backend receipt bytes
    let observed: [String: Any]   // launcher-world observed tuple
}

/// The admitted blank-template identities for the v3 fresh RW disks, resolved
/// from the external session document (vdb scratch base, vdd result base).
struct AdmittedTemplatesV3 {
    let scratchSha256: String
    let scratchBytes: Int
    let resultSha256: String
    let resultBytes: Int
}

/// Parse the backend v3 launch receipt (strict key set, optional initrd),
/// cross-check every observed fact against the verified admission tuple
/// (fail-closed), and emit the contract10 fragment + observed tuple.
func mapLaunchReceiptV3(_ receiptData: Data, plan: LaunchPlan, identity: VerifiedImageIdentity,
                        manifest: ImageManifest, contract: ContractAdmission,
                        workloadSha256: String, workloadBytes: Int, rootfsTotalBytes: Int,
                        templates: AdmittedTemplatesV3, privatePresent: Bool, netPresent: Bool,
                        expectedSpecSha256: String) throws -> MappedReceiptV3 {
    guard let r = try JSONSerialization.jsonObject(with: receiptData) as? [String: Any] else {
        throw Fail("v3 launch receipt: not a JSON object")
    }
    // Strict key set: required keys, with observed_initrd_sha256 and honesty
    // handled explicitly. Unknown keys refuse (fail-closed).
    let required: Set<String> = [
        "schema", "spec_sha256", "observed_kernel_sha256", "observed_cmdline_sha256",
        "cmdline", "system_sha256", "system_bytes", "workload_sha256", "workload_bytes",
        "scratch_path", "scratch_template_sha256", "scratch_template_bytes",
        "result_path", "result_template_sha256", "result_template_bytes",
        "runtime_input_present", "verity_root_hash", "ram_mib", "vcpus", "net_present",
        "consumption", "honesty",
    ]
    let optional: Set<String> = ["observed_initrd_sha256"]
    let keys = Set(r.keys)
    guard required.isSubset(of: keys) else {
        throw Fail("v3 launch receipt: missing keys \(required.subtracting(keys).sorted())")
    }
    guard keys.subtracting(required).isSubset(of: optional) else {
        throw Fail("v3 launch receipt: unknown keys \(keys.subtracting(required).subtracting(optional).sorted())")
    }
    guard try requireNonEmptyString(r, "schema", "v3 launch receipt") == "dsmack-backend-v3/launch-receipt/1" else {
        throw Fail("v3 launch receipt schema mismatch")
    }

    let specSha = try requireNonEmptyString(r, "spec_sha256", "v3 launch receipt")
    let observedKernel = try requireNonEmptyString(r, "observed_kernel_sha256", "v3 launch receipt")
    let observedCmdlineSha = try requireNonEmptyString(r, "observed_cmdline_sha256", "v3 launch receipt")
    let observedCmdline = try requireNonEmptyString(r, "cmdline", "v3 launch receipt")
    let observedSystem = try requireNonEmptyString(r, "system_sha256", "v3 launch receipt")
    let observedWorkload = try requireNonEmptyString(r, "workload_sha256", "v3 launch receipt")
    let observedVerity = try requireNonEmptyString(r, "verity_root_hash", "v3 launch receipt")
    let observedScratchTpl = try requireNonEmptyString(r, "scratch_template_sha256", "v3 launch receipt")
    let observedResultTpl = try requireNonEmptyString(r, "result_template_sha256", "v3 launch receipt")
    let consumption = try requireNonEmptyString(r, "consumption", "v3 launch receipt")
    let systemBytes = try strictJSONInt(r["system_bytes"] as Any, "v3 launch receipt.system_bytes")
    let workloadBytesObserved = try strictJSONInt(r["workload_bytes"] as Any, "v3 launch receipt.workload_bytes")
    let scratchTplBytes = try strictJSONInt(r["scratch_template_bytes"] as Any, "v3 launch receipt.scratch_template_bytes")
    let resultTplBytes = try strictJSONInt(r["result_template_bytes"] as Any, "v3 launch receipt.result_template_bytes")
    let ramMib = try strictJSONInt(r["ram_mib"] as Any, "v3 launch receipt.ram_mib")
    let vcpus = try strictJSONInt(r["vcpus"] as Any, "v3 launch receipt.vcpus")
    let runtimeInputPresent = try strictJSONBool(r["runtime_input_present"] as Any, "v3 launch receipt.runtime_input_present")
    let netPresentObserved = try strictJSONBool(r["net_present"] as Any, "v3 launch receipt.net_present")
    // initrd is present in every admitted manifest; the receipt field is optional
    // only because the ABI permits a no-initrd launch.
    let observedInitrd = r["observed_initrd_sha256"] as? String

    // ---- fail-closed cross-checks: observed == admitted (before run) ----
    guard specSha == expectedSpecSha256 else {
        throw Fail("v3 receipt spec_sha256 \(specSha) != launch-spec digest \(expectedSpecSha256) the app handed the backend")
    }
    guard observedKernel == manifest.kernel.sha256 else {
        throw Fail("v3 receipt observed kernel \(observedKernel) != admitted \(manifest.kernel.sha256)")
    }
    guard let observedInitrd, observedInitrd == manifest.initrd.sha256 else {
        throw Fail("v3 receipt observed initrd != admitted \(manifest.initrd.sha256)")
    }
    guard observedCmdline == plan.cmdline else {
        throw Fail("v3 receipt observed cmdline differs from admitted cmdline (byte-exact identity)")
    }
    guard observedCmdlineSha == identity.cmdlineSha256 else {
        throw Fail("v3 receipt observed cmdline digest != admitted cmdline digest")
    }
    guard observedSystem == manifest.systemDisk.sha256 else {
        throw Fail("v3 receipt observed system disk \(observedSystem) != admitted \(manifest.systemDisk.sha256)")
    }
    guard observedWorkload == workloadSha256 else {
        throw Fail("v3 receipt observed workload \(observedWorkload) != staged \(workloadSha256)")
    }
    guard observedVerity == manifest.verityRootHash else {
        throw Fail("v3 receipt observed verity root != admitted verity root")
    }
    guard ramMib == plan.memMib, vcpus == plan.vcpus else {
        throw Fail("v3 receipt resources (\(ramMib) MiB / \(vcpus) vCPUs) != resolved profile (\(plan.memMib) / \(plan.vcpus))")
    }
    guard systemBytes == manifest.systemDisk.bytes else {
        throw Fail("v3 receipt system bytes \(systemBytes) != manifest \(manifest.systemDisk.bytes)")
    }
    guard workloadBytesObserved == workloadBytes else {
        throw Fail("v3 receipt workload bytes \(workloadBytesObserved) != staged \(workloadBytes)")
    }
    // Template identities: the backend must have copied EXACTLY the admitted
    // blank templates for vdb/vdd (fresh-inode copies; the base is never mutated).
    guard observedScratchTpl == templates.scratchSha256, scratchTplBytes == templates.scratchBytes else {
        throw Fail("v3 receipt scratch template (\(observedScratchTpl)/\(scratchTplBytes)) != admitted (\(templates.scratchSha256)/\(templates.scratchBytes))")
    }
    guard observedResultTpl == templates.resultSha256, resultTplBytes == templates.resultBytes else {
        throw Fail("v3 receipt result template (\(observedResultTpl)/\(resultTplBytes)) != admitted (\(templates.resultSha256)/\(templates.resultBytes))")
    }
    // Presence flags must match what the app actually handed the backend.
    guard runtimeInputPresent == privatePresent else {
        throw Fail("v3 receipt runtime_input_present \(runtimeInputPresent) != app-provided private input \(privatePresent)")
    }
    guard netPresentObserved == netPresent else {
        throw Fail("v3 receipt net_present \(netPresentObserved) != app-provided NIC \(netPresent)")
    }

    let fragment: [String: Any] = [
        "base_vm": [
            "architecture": plan.arch,
            "cmdline": plan.cmdline,
            "initrd_sha256": manifest.initrd.sha256,
            "kernel_sha256": manifest.kernel.sha256,
            "memory_mb": plan.memMib,
            "metadata_sha256": identity.metadataSha256,
            "os_image_hash": identity.osImageHash,
            "rootfs_sha256": manifest.systemDisk.sha256,
            "vcpus": plan.vcpus,
            "verity_root_hash": manifest.verityRootHash,
        ],
        "base_vm_launch": [
            "admission": [
                "decision": "admitted",
                "os_image_hash": identity.osImageHash,
                "admission_sha256": contract.admissionSha256,
                "admission_version": contract.version,
            ],
            "boot": [
                "loader_mode": "held-fd",
                "kernel_sha256": observedKernel,
                "initrd_sha256": observedInitrd,
                "rootfs_sha256": observedSystem,
                "metadata_sha256": identity.metadataSha256,
                "cmdline": observedCmdline,
                "cmdline_sha256": observedCmdlineSha,
                "verity": [
                    "block_bytes": 4096,
                    "data_bytes": identity.rootfsDataBytes,
                    "hash_offset_bytes": identity.rootfsDataBytes,
                    "root_hash": observedVerity,
                    "salt_hex": String(repeating: "0", count: 64),
                    "total_bytes": rootfsTotalBytes,
                ],
            ],
        ],
    ]
    let observed: [String: Any] = [
        "spec_sha256": specSha,
        "observed_kernel_sha256": observedKernel,
        "observed_initrd_sha256": observedInitrd,
        "observed_cmdline_sha256": observedCmdlineSha,
        "observed_system_sha256": observedSystem,
        "observed_workload_sha256": observedWorkload,
        "observed_verity_root_hash": observedVerity,
        "scratch_template_sha256": observedScratchTpl,
        "result_template_sha256": observedResultTpl,
        "runtime_input_present": runtimeInputPresent,
        "net_present": netPresentObserved,
        "ram_mib": ramMib,
        "vcpus": vcpus,
        "consumption": consumption,
        "receipt_sha256": sha256hex(receiptData),
    ]
    return MappedReceiptV3(fragment: fragment, receiptSha256: sha256hex(receiptData), observed: observed)
}
