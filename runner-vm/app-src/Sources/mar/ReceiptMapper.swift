// ReceiptMapper.swift — maps the backend v2 launch receipt
// (dsmack-backend-v2/launch-receipt/1) into the APPROVED contract10 receipt
// world (dsmack:receipt/4), so the run's evidence hooks can consume it
// (mac-app-join lane, 2026-10-21; fable-native-audit F7 action item).
//
// MAPPING TABLE (launch-receipt field → dsmack:receipt/4 field):
//
//   observed_kernel_sha256   → base_vm.kernel_sha256      + boot.kernel_sha256
//   observed_initrd_sha256   → base_vm.initrd_sha256      + boot.initrd_sha256
//   system_sha256            → base_vm.rootfs_sha256      + boot.rootfs_sha256
//   cmdline                  → base_vm.cmdline            + boot.cmdline
//   observed_cmdline_sha256  →                               boot.cmdline_sha256
//   verity_root_hash         → base_vm.verity_root_hash   + boot.verity.root_hash
//   ram_mib                  → base_vm.memory_mb
//   vcpus                    → base_vm.vcpus
//   (app admission tuple)    → base_vm.os_image_hash, base_vm.metadata_sha256,
//                              base_vm_launch.admission{decision, os_image_hash,
//                              admission_sha256, admission_version}
//   spec_sha256 / consumption / honesty / scratch_path / workload_*  → NO
//                              contract10 slot: launcher-world additions,
//                              recorded in the app statement, never mapped.
//
// WHAT THIS MAPPER DELIBERATELY DOES NOT DO:
//   - It does NOT emit a full dsmack:receipt/4. The runner/harness/
//     runtime_inputs_commitment/observed/outputs/attestation fields belong
//     to the compose-runner execution world (dstack-runner-join lane);
//     this launcher emits only the base_vm/base_vm_launch fragment, bound
//     into its own statement for the finalmacintegration wiring.
//   - loader_mode is "held-fd", the WEAKEST honest label: kernel/initrd/
//     cmdline route through backend-owned copies (owned-copy, guest RAM
//     written from the verified owned buffers), but the rootfs disk is
//     consumed BY PATH with verify-on-open + verify-at-attach (krun
//     re-hashes), so between-verification same-inode mutation stays the
//     documented residual window (backend honesty block:
//     disk_verify_on_open). dsmack:receipt/4's enum has no mixed mode; the
//     fragment therefore claims only what the weakest link supports and
//     the app statement carries the backend receipt verbatim (its sha256)
//     alongside. Claiming "owned-copy" here would overclaim.

import CryptoKit
import Foundation

struct MappedReceipt {
    let fragment: [String: Any]   // base_vm + base_vm_launch, contract10-shaped
    let receiptSha256: String     // digest of the EXACT backend receipt bytes
    let observed: [String: Any]   // launcher-world observed tuple for the statement
}

/// Parse the backend launch receipt (strict: exact key set, all values
/// consumed), cross-check every observed fact against the verified
/// admission tuple (fail-closed — a receipt that disagrees with what the
/// app admitted stops the run BEFORE any statement exists), and emit the
/// contract10 fragment.
func mapLaunchReceipt(_ receiptData: Data, plan: LaunchPlan, identity: VerifiedImageIdentity,
                      manifest: ImageManifest,
                      contract: ContractAdmission, workloadSha256: String, workloadBytes: Int,
                      rootfsTotalBytes: Int, expectedSpecSha256: String) throws -> MappedReceipt {
    let obj = try JSONSerialization.jsonObject(with: receiptData)
    let r = try requireExactKeys(
        obj,
        ["schema", "spec_sha256", "observed_kernel_sha256", "observed_initrd_sha256",
         "observed_cmdline_sha256", "cmdline", "system_sha256", "system_bytes",
         "workload_sha256", "workload_bytes", "scratch_path", "verity_root_hash",
         "ram_mib", "vcpus", "consumption", "honesty"],
        "launch receipt")
    guard try requireNonEmptyString(r, "schema", "launch receipt") == "dsmack-backend-v2/launch-receipt/1" else {
        throw Fail("launch receipt schema mismatch")
    }
    let observedKernel = try requireNonEmptyString(r, "observed_kernel_sha256", "launch receipt")
    let observedInitrd = try requireNonEmptyString(r, "observed_initrd_sha256", "launch receipt")
    let observedCmdlineSha = try requireNonEmptyString(r, "observed_cmdline_sha256", "launch receipt")
    let observedCmdline = try requireNonEmptyString(r, "cmdline", "launch receipt")
    let observedSystem = try requireNonEmptyString(r, "system_sha256", "launch receipt")
    let observedWorkload = try requireNonEmptyString(r, "workload_sha256", "launch receipt")
    let observedVerity = try requireNonEmptyString(r, "verity_root_hash", "launch receipt")
    let specSha = try requireNonEmptyString(r, "spec_sha256", "launch receipt")
    let consumption = try requireNonEmptyString(r, "consumption", "launch receipt")
    let systemBytes = try strictJSONInt(r["system_bytes"] as Any, "launch receipt.system_bytes")
    let workloadBytesObserved = try strictJSONInt(r["workload_bytes"] as Any, "launch receipt.workload_bytes")
    let ramMib = try strictJSONInt(r["ram_mib"] as Any, "launch receipt.ram_mib")
    let vcpus = try strictJSONInt(r["vcpus"] as Any, "launch receipt.vcpus")

    // ---- fail-closed cross-checks: observed == admitted ----
    // SPEC EQUALITY REPAIR (mac-runtime-seam-repair lane; flagged by
    // mac-compile-followthrough §6). The backend records in its receipt the
    // spec_sha256 it was handed; the prior source parsed that field and copied
    // it into the statement WITHOUT ever comparing it to the launch-spec digest
    // the app itself constructed and passed. A backend that consumed (or
    // reported) a DIFFERENT spec than the one the app built from the admitted
    // inputs would go unnoticed. Bind them first, fail-closed — this is a
    // caller-side admission cross-check, performed BEFORE the handle is run
    // (see V2Launch.swift: the receipt is read and mapped before backendV2Run).
    guard specSha == expectedSpecSha256 else {
        throw Fail("receipt spec_sha256 \(specSha) != the launch-spec digest \(expectedSpecSha256) the app constructed and handed the backend")
    }
    guard observedKernel == manifest.kernel.sha256 else {
        throw Fail("receipt observed kernel \(observedKernel) != admitted \(manifest.kernel.sha256)")
    }
    guard observedInitrd == manifest.initrd.sha256 else {
        throw Fail("receipt observed initrd \(observedInitrd) != admitted \(manifest.initrd.sha256)")
    }
    guard observedCmdline == plan.cmdline else {
        throw Fail("receipt observed cmdline differs from the admitted cmdline (byte-exact identity)")
    }
    guard observedCmdlineSha == identity.cmdlineSha256 else {
        throw Fail("receipt observed cmdline digest != admitted cmdline digest")
    }
    guard observedSystem == manifest.systemDisk.sha256 else {
        throw Fail("receipt observed system disk \(observedSystem) != admitted \(manifest.systemDisk.sha256)")
    }
    guard observedWorkload == workloadSha256 else {
        throw Fail("receipt observed workload \(observedWorkload) != staged \(workloadSha256)")
    }
    guard observedVerity == manifest.verityRootHash else {
        throw Fail("receipt observed verity root != admitted verity root")
    }
    guard ramMib == plan.memMib, vcpus == plan.vcpus else {
        throw Fail("receipt resources (\(ramMib) MiB / \(vcpus) vCPUs) != resolved profile (\(plan.memMib) / \(plan.vcpus))")
    }
    guard systemBytes == manifest.systemDisk.bytes else {
        throw Fail("receipt system bytes \(systemBytes) != manifest \(manifest.systemDisk.bytes)")
    }
    guard workloadBytesObserved == workloadBytes else {
        throw Fail("receipt workload bytes \(workloadBytesObserved) != staged \(workloadBytes)")
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
                // Held-fd = the weakest honest label; see the header note.
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
        "ram_mib": ramMib,
        "vcpus": vcpus,
        "consumption": consumption,
        "receipt_sha256": sha256hex(receiptData),
    ]
    return MappedReceipt(fragment: fragment, receiptSha256: sha256hex(receiptData), observed: observed)
}
