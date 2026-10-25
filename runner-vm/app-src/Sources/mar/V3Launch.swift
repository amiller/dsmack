// V3Launch.swift — `mar hvf-v3 <out> <session.json> <challenge> <keyId>`.
// External admitted inputs (admission policy, image manifest, dstack checksum
// manifest + metadata, contract admission, compose manifest, workload disk,
// session) go through the app-side admission core and drive the v3 backend
// (BackendV3.swift) with the five-role disk set (vda/vdb/vdc/vdd + optional vde)
// and an optional virtio-net fd.
//
// Lifecycle: init -> vm_new_v3 -> receipt (mapped + cross-checked before run)
// -> run_v3 -> finalize_v3 -> result_v3 -> run-result envelope + result
// assertion. Scratch residue is reported only after all evidence is durably
// retained. The vde private input is handed to the backend read-only and never
// hashed or staged by the app.

#if canImport(Darwin)
import CryptoKit
import Darwin
import DeviceCheck
import Foundation
import marAttest

let v3SessionSchema = "dsmack-general-launcher/session/3"
let v3StatementSchema = "dsmack-general-launcher/v3-run-statement/1"
let v3ScratchTemplateMaxBytes = V3TemplateCapacity.scratchMaxBytes
let v3ResultTemplateMaxBytes = V3TemplateCapacity.resultMaxBytes
let v3PrivateMaxProbeBytes = 1 << 30      // vde size sanity bound (presence only; never hashed)
let workloadMaxBytes = 1 << 32   // 4 GiB staged-copy cap (compose image tars)
let composeManifestMaxBytes = 1 << 20
let pathMaxBytes = 1024

func runHvFV3(out: URL, sessionPath: String, challengeHex: String, keyId: String) async throws {
    // Covers preparation refusals as well as execution/retention. Inner lifecycle
    // handlers finish VM/process/FD teardown before this non-destructive report.
    defer { dropScratch() }
    setRunDeadline(started + .seconds(3600 + setupAllowanceSeconds))

    // ---- session/3 document: exact bytes, canonical JSON, exact key set ----
    let sessionBytes = try read(sessionPath, max: 65536)
    let sessionObject = try JSONSerialization.jsonObject(with: sessionBytes)
    guard try canonical(sessionObject) == sessionBytes else { throw Fail("session is not canonical JSON") }
    let s = try requireExactKeys(sessionObject, [
        "schema", "policy_path", "image_manifest_path", "checksum_manifest_path",
        "metadata_path", "admission_path", "compose_manifest_path", "profile",
        "workload_disk_path", "workload_sha256", "workload_id", "runtime_seconds",
        // v3 additions:
        "scratch_template_path", "scratch_template_sha256", "scratch_template_bytes",
        "result_template_path", "result_template_sha256", "result_template_bytes",
        "private_input_path", "net_socket_path",
    ], "session")
    guard try requireNonEmptyString(s, "schema", "session") == v3SessionSchema else {
        throw Fail("session schema != \(v3SessionSchema)")
    }
    var docPaths: [String: String] = [:]
    for k in ["policy_path", "image_manifest_path", "checksum_manifest_path", "metadata_path",
              "admission_path", "compose_manifest_path", "workload_disk_path",
              "scratch_template_path", "result_template_path"] {
        let p = try requireNonEmptyString(s, k, "session")
        guard printableASCII(p, maxBytes: pathMaxBytes), p.hasPrefix("/") else {
            throw Fail("session.\(k): absolute printable-ASCII path required")
        }
        docPaths[k] = p
    }
    // vde + NIC are OPTIONAL: the keys are REQUIRED (exact-key discipline) but an
    // EMPTY string means "none" (no vde / no NIC). A non-empty value must be an
    // absolute printable-ASCII path.
    func optionalPath(_ k: String) throws -> String? {
        let p = try requireStringAllowingEmpty(s, k, "session")
        if p.isEmpty { return nil }
        guard printableASCII(p, maxBytes: pathMaxBytes), p.hasPrefix("/") else {
            throw Fail("session.\(k): absolute printable-ASCII path required (or empty for none)")
        }
        return p
    }
    let privateInputPath = try optionalPath("private_input_path")
    let netSocketPath = try optionalPath("net_socket_path")

    let profileName = try requireNonEmptyString(s, "profile", "session")
    guard printableASCII(profileName, maxBytes: 128) else { throw Fail("session.profile: printable ASCII required") }
    let workloadSha = try requireNonEmptyString(s, "workload_sha256", "session")
    guard isHex64(workloadSha) else { throw Fail("session.workload_sha256: lowercase hex sha256 required") }
    let workloadId = try requireNonEmptyString(s, "workload_id", "session")
    guard printableASCII(workloadId, maxBytes: 128) else { throw Fail("session.workload_id: printable ASCII required") }
    let scratchTemplateSha = try requireNonEmptyString(s, "scratch_template_sha256", "session")
    let resultTemplateSha = try requireNonEmptyString(s, "result_template_sha256", "session")
    guard isHex64(scratchTemplateSha), isHex64(resultTemplateSha) else {
        throw Fail("session: scratch/result template sha256 must be lowercase hex")
    }
    let scratchTemplateBytes = try strictJSONInt(s["scratch_template_bytes"] as Any, "session.scratch_template_bytes")
    let resultTemplateBytes = try strictJSONInt(s["result_template_bytes"] as Any, "session.result_template_bytes")
    // Templates are admitted blank filesystems; the backend requires 512-byte
    // multiples (block device sizing). Refuse here too (fail-closed, cheap).
    guard V3TemplateCapacity.admitsScratch(scratchTemplateBytes),
          V3TemplateCapacity.admitsResult(resultTemplateBytes) else {
        throw Fail("session: scratch/result template bytes must be positive 512-multiples <= \(v3ScratchTemplateMaxBytes)/\(v3ResultTemplateMaxBytes)")
    }
    let runtimeRequest = try strictJSONInt(s["runtime_seconds"] as Any, "session.runtime_seconds")
    guard (1...86400).contains(runtimeRequest) else { throw Fail("session.runtime_seconds: 1..86400 required") }
    let templates = AdmittedTemplatesV3(scratchSha256: scratchTemplateSha, scratchBytes: scratchTemplateBytes,
                                        resultSha256: resultTemplateSha, resultBytes: resultTemplateBytes)
    let privatePresent = privateInputPath != nil
    let netPresent = netSocketPath != nil
    try trace("session_loaded", ["session_sha256": sha256hex(sessionBytes), "runtime_input_present": privatePresent, "net_present": netPresent])
    try checkCancellation()

    // ---- every external document: read ONCE, capped; digests over exact bytes ----
    let policyData = try read(docPaths["policy_path"]!, max: 65536)
    let manifestData = try read(docPaths["image_manifest_path"]!, max: 262144)
    let checksumData = try read(docPaths["checksum_manifest_path"]!, max: maxChecksumManifestBytes)
    let metadataData = try read(docPaths["metadata_path"]!, max: maxMetadataBytes)
    let admissionData = try read(docPaths["admission_path"]!, max: maxAdmissionBytes)
    let composeManifestData = try read(docPaths["compose_manifest_path"]!, max: composeManifestMaxBytes)
    let composeManifestSha256 = sha256hex(composeManifestData)
    try trace("compose_manifest_bound", ["compose_manifest_sha256": composeManifestSha256])

    // ---- app-side admission core ----
    let policy = try parseAdmissionPolicy(policyData)
    let manifest = try parseImageManifest(manifestData)
    let admitted = try admitImage(policy: policy, manifestSha256: manifest.sha256, manifestImageId: manifest.imageId)
    try trace("image_admitted", ["image_id": admitted.imageId, "image_manifest_sha256": manifest.sha256, "policy_sha256": policy.sha256])

    let checksumEntries = try parseChecksumManifest(checksumData)
    let identity = try verifyImageIdentity(
        manifest: manifest, checksumBytes: checksumData, checksumEntries: checksumEntries,
        metadataBytes: metadataData, metadata: try parseDstackMetadata(metadataData))
    let allowed = try parseContractAdmission(admissionData)
    let contract = try admitByOsImageHash(allowed: allowed, osImageHash: identity.osImageHash,
                                          admissionSha256: sha256hex(admissionData))
    try trace("image_identity_bound", [
        "os_image_hash": identity.osImageHash,
        "metadata_sha256": identity.metadataSha256,
        "admission_sha256": contract.admissionSha256,
    ])

    let plan = try resolveLaunch(manifest: manifest, admission: admitted, policy: policy,
                                 profileName: profileName, requestedRuntimeSeconds: runtimeRequest)
    setRunDeadline(started + .seconds(plan.runtimeSeconds + setupAllowanceSeconds + 60))

    // ---- verified-byte staging (owned-copy discipline; the backend re-verifies) ----
    try checkCancellation()
    let kernelBytes = try read(manifest.kernel.path, max: 1 << 26)
    guard sha256hex(kernelBytes) == manifest.kernel.sha256 else {
        throw Fail("kernel sha256 \(sha256hex(kernelBytes)) != manifest \(manifest.kernel.sha256)")
    }
    let initrdBytes = try read(manifest.initrd.path, max: 1 << 26)
    guard sha256hex(initrdBytes) == manifest.initrd.sha256 else {
        throw Fail("initrd sha256 \(sha256hex(initrdBytes)) != manifest \(manifest.initrd.sha256)")
    }
    try trace("boot_bytes_verified", ["kernel_sha256": manifest.kernel.sha256, "initrd_sha256": manifest.initrd.sha256])

    let systemStaged = try stageVerifiedCopy(out, "system.img.staged", src: manifest.systemDisk.path,
                                             maxBytes: 1 << 34, wantSha256: manifest.systemDisk.sha256,
                                             wantBytes: manifest.systemDisk.bytes)
    let workloadStaged = try stageVerifiedCopy(out, "workload.img.staged", src: docPaths["workload_disk_path"]!,
                                               maxBytes: workloadMaxBytes, wantSha256: workloadSha, wantBytes: nil)
    // vdb/vdd ADMITTED blank templates: staged + verified by digest AND size.
    let scratchTemplateStaged = try stageVerifiedCopy(out, "scratch-template.img.staged", src: docPaths["scratch_template_path"]!,
                                                       maxBytes: v3ScratchTemplateMaxBytes, wantSha256: scratchTemplateSha, wantBytes: scratchTemplateBytes)
    let resultTemplateStaged = try stageVerifiedCopy(out, "result-template.img.staged", src: docPaths["result_template_path"]!,
                                                      maxBytes: v3ResultTemplateMaxBytes, wantSha256: resultTemplateSha, wantBytes: resultTemplateBytes)
    try trace("disks_staged", ["system_sha256": systemStaged.sha256, "workload_sha256": workloadStaged.sha256,
                               "scratch_template_sha256": scratchTemplateStaged.sha256, "result_template_sha256": resultTemplateStaged.sha256])

    // vde: UNMEASURED. Only verify it exists and is a regular file — NEVER hash
    // or stage its bytes (no content digest/length may enter evidence).
    if let p = privateInputPath {
        var st = stat()
        guard stat(p, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else {
            throw Fail("session.private_input_path: not a regular file (vde is an unmeasured RO file)")
        }
        guard st.st_size >= 0, st.st_size <= off_t(v3PrivateMaxProbeBytes) else {
            throw Fail("session.private_input_path: size out of bounds")
        }
    }

    // spec_sha256 BINDS the admitted templates + device shape too (v3).
    let spec = try buildLaunchSpecV3(plan: plan, identity: identity, contract: contract, policy: policy,
                                     manifest: manifest, workloadSha256: workloadStaged.sha256, workloadId: workloadId,
                                     templates: templates, privatePresent: privatePresent, netPresent: netPresent)
    try save("launch-spec-v3.json", spec.bytes)
    try trace("launch_spec_built", ["spec_sha256": spec.specSha256])

    // Fresh RW dests the backend creates O_EXCL 0600 (must not pre-exist).
    let scratchPath = out.appendingPathComponent("scratch.img").path
    let resultPath = out.appendingPathComponent("result.img").path       // vdd — RETAINED evidence
    for p in [scratchPath, resultPath] where FileManager.default.fileExists(atPath: p) {
        throw Fail("\(p) already exists; the backend creates the fresh RW dests per launch")
    }
    _ = own(URL(fileURLWithPath: scratchPath))   // possible residue; never automatically deleted
    // resultPath is NOT registered as scratch: it is retained output.

    // ---- descriptors: control socketpair (backend owns fds[1]) + optional NIC ----
    var fds: [Int32] = [-1, -1]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw Fail("socketpair failed (errno \(errno))") }
    var netFd: Int32 = -1
    if let np = netSocketPath {
        do { netFd = try connectUnixStream(np) }
        catch { close(fds[0]); close(fds[1]); throw error }   // nothing handed off yet
    }

    var vmNewAttempted = false
    var liveHandle: Int64? = nil
    do {
        try backendV3Init()
        try checkCancellation()
        let consolePath = out.appendingPathComponent("console-v3.log").path
        let buildStarted = ContinuousClock.now
        vmNewAttempted = true   // from here the binding owns fds[1]+netFd on ANY return
        let handle = try backendV3VmNew(
            kernel: kernelBytes, initrd: initrdBytes,
            specSha256: spec.specSha256,
            kernelSha256: manifest.kernel.sha256, initrdSha256: manifest.initrd.sha256,
            cmdline: plan.cmdline, cmdlineSha256: identity.cmdlineSha256,
            systemSha256: manifest.systemDisk.sha256, verityRootHash: manifest.verityRootHash,
            workloadSha256: workloadStaged.sha256,
            scratchTemplateSha256: scratchTemplateSha, scratchTemplateBytes: UInt64(scratchTemplateBytes),
            resultTemplateSha256: resultTemplateSha, resultTemplateBytes: UInt64(resultTemplateBytes),
            ramMib: UInt32(plan.memMib), vcpus: UInt32(plan.vcpus),
            systemPath: systemStaged.path,
            scratchTemplatePath: scratchTemplateStaged.path, scratchPath: scratchPath,
            workloadPath: workloadStaged.path,
            resultTemplatePath: resultTemplateStaged.path, resultPath: resultPath,
            privatePath: privateInputPath,
            consoleLogPath: consolePath,
            controlFd: fds[1], netFd: netFd)
        liveHandle = handle   // must be freed on every exit from here on
        let buildMs = Int((ContinuousClock.now - buildStarted) / .milliseconds(1))

        // Receipt read + mapped + cross-checked BEFORE run (fail-closed admission
        // cross-check; a disagreeing receipt stops the run before any guest step).
        let receiptJSON = try backendV3Receipt(handle: handle)
        let receiptData = Data(receiptJSON.utf8)
        let mapped = try mapLaunchReceiptV3(receiptData, plan: plan, identity: identity, manifest: manifest,
                                            contract: contract, workloadSha256: workloadStaged.sha256,
                                            workloadBytes: workloadStaged.bytes, rootfsTotalBytes: systemStaged.bytes,
                                            templates: templates, privatePresent: privatePresent, netPresent: netPresent,
                                            expectedSpecSha256: spec.specSha256)
        try trace("v3_receipt_mapped", ["receipt_sha256": mapped.receiptSha256])

        // The launch client data depends only on the mapped receipt, so it is
        // fixed before run; its hash is the guest Attest run id.
        let evidenceBody = launcherEvidenceBody(
            baseVm: mapped.fragment["base_vm"] as! [String: Any],
            baseVmLaunch: mapped.fragment["base_vm_launch"] as! [String: Any],
            observed: mapped.observed, manifestSha256: composeManifestSha256)
        let launchEvidenceSha256 = try executionEvidenceDigest(evidenceBody)
        let launchClientData = try assertionClientData(manifestSha256: composeManifestSha256,
                                                       evidenceSha256: launchEvidenceSha256, challenge: challengeHex)

        try checkCancellation()
        let guestCtl = Task { [ctlFd = fds[0]] in
            try await serveGuestCtl(fd: ctlFd, keyId: keyId, osImageHash: try guestHex(identity.osImageHash),
                                    manifestSha256: try guestHex(composeManifestSha256),
                                    run: Data(SHA256.hash(data: launchClientData)))
        }
        let runStarted = ContinuousClock.now
        let code = try backendV3Run(handle: handle)              // proven halt (PSCI); not task success
        shutdown(fds[0], SHUT_RDWR)                              // the guest is gone; stop the Attest handler
        try await guestCtl.value
        try backendV3Finalize(handle: handle)                   // CHECKED flush/sync + exact-length hash
        let runMs = Int((ContinuousClock.now - runStarted) / .milliseconds(1))
        try checkCancellation()

        // The control peer is gone after checked teardown; the app end is ours.
        close(fds[0]); fds[0] = -1

        // Run-result (REFUSED until finalize ran). Parse + cross-check against
        // the admitted result template, the code run returned, and vde presence.
        let resultJSON = try backendV3Result(handle: handle)
        let resultData = Data(resultJSON.utf8)
        let parsed = try parseRunResultV3(resultData, expectedResultTemplateSha256: resultTemplateSha,
                                          expectedResultTemplateBytes: resultTemplateBytes,
                                          expectedVmmCode: Int(code), privatePresent: privatePresent)
        try trace("v3_run_result", ["vmm_code": parsed.vmmCode, "run_ms": runMs, "build_ms": buildMs,
                                    "result_sha256": parsed.resultSha256, "result_bytes": parsed.resultBytes,
                                    "console_sha256": parsed.consoleSha256, "console_bytes": parsed.consoleBytes,
                                    "console_truncated": parsed.consoleTruncated])

        // ---- LAUNCH assertion: contract10 receipt-evidence (client data built before run) ----
        guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
        else { throw Fail("execution cancelled before launch assertion") }
        let svc = DCAppAttestService.shared
        guard svc.isSupported else { throw Fail("App Attest unsupported in this process; refusing to run") }
        let launchAssertion = try await svc.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: launchClientData)))
        let launchCounter = try assertionCounter(launchAssertion)

        // ---- the AUTHENTICATED run-result envelope + the RESULT assertion ----
        let envelope = try composeRunResultEnvelope(
            launchEvidenceSha256: launchEvidenceSha256, manifestSha256: composeManifestSha256,
            challenge: challengeHex, keyIdB64: keyId, launchCounter: launchCounter, parsed: parsed)
        let resultClientData = try resultAssertionClientData(launchEvidenceSha256: launchEvidenceSha256,
                                                             envelopeSha256: envelope.envelopeSha256, challenge: challengeHex)
        guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
        else { throw Fail("execution cancelled before result assertion") }
        let resultAssertion = try await svc.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: resultClientData)))
        let resultCounter = try assertionCounter(resultAssertion)

        // ---- the app statement (diagnostics + bound digests) ----
        let statement = try canonicalJSONData([
            "schema": v3StatementSchema,
            "challenge": challengeHex,
            "key_id": keyId,
            "assertion": [
                "assertion_domain": assertionDomain,
                "evidence_domain": evidenceDomain,
                "manifest_sha256": composeManifestSha256,
                "evidence_sha256": launchEvidenceSha256,
                "client_data_sha256": sha256hex(launchClientData),
                "receipt_evidence_body": evidenceBody,
            ] as [String: Any],
            "result_assertion": [
                "result_assertion_domain": resultAssertionDomain,
                "envelope_domain": envelopeDomain,
                "envelope_schema": envelopeSchema,
                // SWIFT04 repair2: the result preimage binds (L, E, challenge)
                // per io-contract-reference statement.py:40-53, so the diagnostic
                // records the launch-evidence digest L it actually signed (the
                // rejected repair1 recorded manifest_sha256 M here). E is the
                // DOMAIN-SEPARATED envelope digest sha256_obj([ENVELOPE_DOMAIN,body]).
                "launch_evidence_sha256": launchEvidenceSha256,
                "envelope_sha256": envelope.envelopeSha256,
                "result_client_data_sha256": sha256hex(resultClientData),
            ] as [String: Any],
            "identity": [
                "os_image_hash": identity.osImageHash,
                "image_manifest_sha256": manifest.sha256,
                "compose_manifest_sha256": composeManifestSha256,
                "metadata_sha256": identity.metadataSha256,
                "policy_sha256": policy.sha256,
                "policy_id": policy.policyId,
                "admission_sha256": contract.admissionSha256,
                "spec_sha256": spec.specSha256,
            ],
            "consumed": mapped.observed,
            "workload": ["sha256": workloadStaged.sha256, "bytes": workloadStaged.bytes, "workload_id": workloadId],
            "resources": ["profile_name": plan.profileName, "profile_basis": plan.profileBasis,
                          "ram_mib": plan.memMib, "vcpus": plan.vcpus,
                          "runtime_bound_seconds": plan.runtimeSeconds],
            "staging": ["method": "read-once/copy-once hash + staged re-hash; backend verify-on-open; vde unmeasured",
                        "kernel_bytes": kernelBytes.count, "initrd_bytes": initrdBytes.count,
                        "system_bytes": systemStaged.bytes, "workload_bytes": workloadStaged.bytes,
                        "scratch_template_bytes": scratchTemplateBytes, "result_template_bytes": resultTemplateBytes,
                        "runtime_input_present": privatePresent, "net_present": netPresent,
                        "scratch_fresh_inode": true, "result_fresh_inode": true, "arch": plan.arch],
            "lifecycle": ["backend_abi": 3, "build_ms": buildMs, "run_ms": runMs, "vmm_code": parsed.vmmCode,
                          "vmm_code_semantics": "0 = guest halt (PSCI), never workload success"],
            "output": ["result_sha256": parsed.resultSha256, "result_bytes": parsed.resultBytes,
                       "console_sha256": parsed.consoleSha256, "console_bytes": parsed.consoleBytes,
                       "console_truncated": parsed.consoleTruncated, "console_limit_bytes": kConsoleLimitBytes],
            "contract10_receipt_fragment": mapped.fragment,
            "trace": ["head": head, "events": seq],
        ] as [String: Any])

        // ---- app-side pair-retention bundle (NOT the frozen PAIR_EVIDENCE: that
        //      binds the operator enrollment, composed at the operator/verifier
        //      gate — REF02). This retains both assertions + recovered counters +
        //      client-data digests so the pair is reconstructable. ----
        let pairRetention = try canonicalJSONData([
            "schema": "dsmack-general-launcher/runresult-pair-retention/1",
            "challenge": challengeHex,
            "key_id_b64": keyId,
            "manifest_sha256": composeManifestSha256,
            "launch_evidence_sha256": launchEvidenceSha256,
            "launch_client_data_sha256": sha256hex(launchClientData),
            "launch_counter": launchCounter,
            "envelope_sha256": envelope.envelopeSha256,
            "result_client_data_sha256": sha256hex(resultClientData),
            "result_counter": resultCounter,
            "note": "frozen dsmack.runresult-pair-evidence/1 (enrollment-bound) is composed at the operator/verifier gate (REF02); this is the producer-side retention of both assertions.",
        ] as [String: Any])

        // ---- DURABLE COMPLETE RETENTION, then (and only then) drop scratch ----
        // Every artifact is fsync'd and re-hashed from disk; cleanup is gated on
        // the complete retained set verifying (SWIFT04). result.img (vdd) and the
        // console are the backend-produced bytes; the backend already hashed them
        // at exact length through its retained descriptor, so we bind to those.
        // Self-describing index of the retained admitted inputs → exact-byte digests
        // (every digest here also appears, authenticated or bound, in statement.json).
        let admittedInputsIndex = try canonicalJSONData([
            "schema": "dsmack-general-launcher/admitted-inputs-retention/1",
            "compose_manifest": ["file": "compose-manifest.bin", "sha256": composeManifestSha256, "bytes": composeManifestData.count],
            "admission": ["file": "admission.json", "sha256": contract.admissionSha256, "bytes": admissionData.count],
            "policy": ["file": "policy.json", "sha256": policy.sha256, "bytes": policyData.count],
            "image_manifest": ["file": "image-manifest.json", "sha256": manifest.sha256, "bytes": manifestData.count],
            "checksum_manifest": ["file": "checksum-manifest.txt", "sha256": sha256hex(checksumData), "bytes": checksumData.count],
            "metadata": ["file": "metadata.json", "sha256": identity.metadataSha256, "bytes": metadataData.count],
        ] as [String: Any])

        // SWIFT04 repair3: the whole durable-retention sequence is ONE fail-closed
        // unit (RetentionV3.performDurableRetention) — documents (incl. the EXACT
        // admitted-input documents the review named: compose-manifest.bin,
        // admission.json, policy/image-manifest/checksum/metadata, so a verifier can
        // recompute M and the admission facts), then the backend-produced result.img
        // (vdd) + console re-verified from disk against the digests/lengths the
        // backend committed, then the OUT dir fsync. Console is verified on EVERY
        // accepted path (truncated is a legitimate contract state; the committed
        // digest is over the EXACT retained bytes). The call returns ONLY when the
        // complete retained set is durable; any fault throws BEFORE dropScratch()
        // below, preserving the whole OUT directory for diagnosis. The identical
        // sequence is driven by the standalone fault-injection harness.
        let retainedDocs: [RetainedDocV3] = [
            RetainedDocV3("envelope.json", envelope.bytes),
            RetainedDocV3("statement.json", statement),
            RetainedDocV3("launch-assertion.cbor", launchAssertion),
            RetainedDocV3("result-assertion.cbor", resultAssertion),
            RetainedDocV3("launch-client-data.bin", launchClientData),
            RetainedDocV3("result-client-data.bin", resultClientData),
            RetainedDocV3("backend-receipt-v3.json", receiptData),      // original guest/backend receipt bytes
            RetainedDocV3("backend-run-result-v3.json", resultData),    // original run-result bytes
            RetainedDocV3("pair-retention.json", pairRetention),
            RetainedDocV3("keyId.txt", Data(keyId.utf8)),
            RetainedDocV3("trace.jsonl", traceLines),
            RetainedDocV3("compose-manifest.bin", composeManifestData),
            RetainedDocV3("admission.json", admissionData),
            RetainedDocV3("policy.json", policyData),
            RetainedDocV3("image-manifest.json", manifestData),
            RetainedDocV3("checksum-manifest.txt", checksumData),
            RetainedDocV3("metadata.json", metadataData),
            RetainedDocV3("admitted-inputs.json", admittedInputsIndex),
        ]
        let retainedFiles: [RetainedFileV3] = [
            RetainedFileV3(path: resultPath, expectSha256: parsed.resultSha256, expectBytes: parsed.resultBytes, what: "result.img (vdd)"),
            RetainedFileV3(path: consolePath, expectSha256: parsed.consoleSha256, expectBytes: parsed.consoleBytes, what: "console-v3.log"),
        ]
        try performDurableRetention(outDir: out, documents: retainedDocs, verifications: retainedFiles)

        backendV3Free(handle: handle)   // frees handle; closes control/net/console/vdd dups once
        liveHandle = nil
        runFinished.withLock { $0 = true }
    } catch {
        // FD / handle discipline on every refusal:
        if let h = liveHandle {
            backendV3Free(handle: h)    // frees handle + its owned descriptors exactly once
            liveHandle = nil
        } else if vmNewAttempted {
            // vm_new was reached and threw: the binding already closed fds[1]+netFd.
        } else {
            if fds[1] >= 0 { close(fds[1]) }
            if netFd >= 0 && netFd != fds[1] { close(netFd) }
        }
        if fds[0] >= 0 { shutdown(fds[0], SHUT_RDWR); close(fds[0]); fds[0] = -1 }
        try? save("trace.jsonl", traceLines)
        note("hvf-v3 failed: \(error)")
        // Preserve every possible residue on refusal, including partial retention.
        // Report after backend/FD teardown; this performs no namespace mutation.
        runFinished.withLock { $0 = true }
        throw error
    }
}

/// Session scalar that MAY be the empty string (the optional-path keys). Empty
/// means "none"; the exact-key discipline still requires the key to be present.
func requireStringAllowingEmpty(_ d: [String: Any], _ k: String, _ what: String) throws -> String {
    guard let s = d[k] as? String else { throw Fail("\(what).\(k): string required (empty = none)") }
    return s
}

/// Connect a fresh SOCK_STREAM to an existing AF_UNIX path; returns the owned
/// connected fd (ownership moves into the backend on vm_new_v3). Fail-closed.
func connectUnixStream(_ path: String) throws -> Int32 {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let maxPath = MemoryLayout.size(ofValue: addr.sun_path)
    guard path.utf8.count < maxPath else { throw Fail("net_socket_path too long for sockaddr_un (\(maxPath - 1) max)") }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw Fail("net socket() failed (errno \(errno))") }
    let ok = path.withCString { src -> Bool in
        withUnsafeMutablePointer(to: &addr.sun_path) { dst in
            dst.withMemoryRebound(to: CChar.self, capacity: maxPath) { p in
                strncpy(p, src, maxPath - 1); return true
            }
        }
    }
    _ = ok
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { ap in
        ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
    }
    guard rc == 0 else { let e = errno; close(fd); throw Fail("connect(\(path)) failed (errno \(e))") }
    return fd
}

// saveDurable / verifyRetainedFile / fsyncDir moved to RetentionV3.swift (SWIFT04
// repair3) so the durable-retention sequence is one testable unit; they are
// dir-parameterized there and called via performDurableRetention above.

/// OWNED-COPY staging: read-once chunked copy into a fresh O_EXCL 0600 file
/// inside the private out dir, hashing THE COPY while it is written, then a
/// chunked read-back re-hash of the staged file (belt and braces). Refuses
/// on any size/digest mismatch; `wantBytes == nil` skips the size
/// expectation (the digest still binds the bytes).
func stageVerifiedCopy(_ dir: URL, _ name: String, src: String, maxBytes: Int,
                       wantSha256: String, wantBytes: Int?) throws -> (path: String, sha256: String, bytes: Int) {
    let path = dir.appendingPathComponent(name).path
    guard !FileManager.default.fileExists(atPath: path) else { throw Fail("\(path) already exists") }
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    guard fd >= 0 else { throw Fail("cannot create \(path): \(String(cString: strerror(errno)))") }
    // Register as soon as creation succeeds, including every partial-copy refusal.
    // This is a possible namespace residue, never a claim of inode ownership.
    _ = own(URL(fileURLWithPath: path))
    var verified = false
    defer {
        if !verified { reportDeferredResidue(paths: [path]) }
    }
    var h = SHA256()
    var total = 0
    do {
        let srcFd = open(src, O_RDONLY)
        guard srcFd >= 0 else { throw Fail("cannot open \(src): \(String(cString: strerror(errno)))") }
        defer { close(srcFd) }
        var st = stat()
        guard fstat(srcFd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else {
            throw Fail("\(src) is not a regular file")
        }
        let file = FileHandle(fileDescriptor: srcFd, closeOnDealloc: false)
        while true {
            try checkCancellation()
            let chunk = try file.read(upToCount: 1 << 20) ?? Data()
            if chunk.isEmpty { break }
            total += chunk.count
            guard total <= maxBytes else { throw Fail("\(src) exceeds the \(maxBytes)-byte staging cap") }
            h.update(data: chunk)
            try chunk.withUnsafeBytes { p in
                var written = 0
                while written < p.count {
                    let n = write(fd, p.baseAddress!.advanced(by: written), p.count - written)
                    guard n > 0 else { throw Fail("short write staging \(path)") }
                    written += n
                }
            }
        }
        guard fsync(fd) == 0 else { throw Fail("cannot sync staged copy \(path): errno \(errno)") }
        close(fd)
    } catch {
        close(fd)
        throw error
    }
    let digest = h.finalize().map { String(format: "%02x", $0) }.joined()
    if let want = wantBytes, total != want {
        throw Fail("\(name): staged copy is \(total) bytes, manifest says \(want)")
    }
    guard digest == wantSha256 else {
        throw Fail("\(name): staged copy sha256 \(digest) != expected \(wantSha256)")
    }
    // Chunked read-back re-hash of the staged file (the bytes the backend
    // will open) — no full in-memory read of multi-gigabyte disks.
    let rehashed = try sha256File(path)
    guard rehashed == wantSha256 else {
        throw Fail("\(name): staged copy changed after write (re-hash \(rehashed) != \(wantSha256))")
    }
    verified = true
    return (path, digest, total)
}

/// Chunked sha256 over a file's bytes (no full in-memory read).
func sha256File(_ path: String) throws -> String {
    let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
    defer { try? file.close() }
    var h = SHA256()
    while true {
        let chunk = try file.read(upToCount: 1 << 20) ?? Data()
        if chunk.isEmpty { break }
        h.update(data: chunk)
    }
    return h.finalize().map { String(format: "%02x", $0) }.joined()
}

#endif
