// V2Launch.swift — `mar hvf-v2`: the COMPLETE generic v2 launch entry point
// (mac-app-join lane, 2026-10-21). This is the mode the retired v1
// hvf-control refused to approximate: the full command path from EXTERNAL
// admitted inputs (admission policy, image manifest, dstack checksum
// manifest + metadata, contract10 admission document, workload disk,
// session) through the app-side admission core to BackendV2 (the krun HVF
// factory) and out through the genuine Apple assertion API.
//
//   mar hvf-v2 <out> <session.json> <challenge> <keyId>
//
// GENERIC APP DISCIPLINES (unchanged from the v1 modes):
//   - zero compiled-in image identity: every digest arrives from the
//     external admitted inputs; a new admitted base image is a policy edit
//     plus a manifest, never a rebuild or re-sign;
//   - every statement field is computed from bytes this process read or
//     observed; nothing comes from argv but paths;
//   - fail-closed refusals before anything exists; no receipt/statement on
//     any failure path (evidence first, nothing that looks like a result);
//   - the observed consumed tuple (what the BACKEND actually verified) is
//     cross-checked against the admission tuple BEFORE the statement is
//     built; backendV2Receipt is read BEFORE backendV2Run (the handle is
//     consumed by run); the console log is read only AFTER run returns
//     (checked teardown);
//   - the assertion is a REAL DCAppAttestService.generateAssertion over
//     sha256(exact statement bytes) — the only DeviceCheck call on this
//     path — with the challenge + statement binding the whole run;
//   - a returning code 0 is a guest HALT (PSCI), never workload success;
//     compose/task semantics live outside this app entirely.

#if canImport(Darwin)
import CryptoKit
import Darwin
import DeviceCheck
import Foundation

// session/2 (mac-source-integration-early): adds the REQUIRED compose_manifest_path
// input (N02 — the launcher binds sha256(exact app-compose bytes) as
// manifest_sha256). The key-set change is explicit via the version bump, not a
// silent addition; a session/1 document is rejected by the schema guard.
let v2SessionSchema = "dsmack-general-launcher/session/2"
let v2StatementSchema = "dsmack-general-launcher/v2-run-statement/1"
let v2WorkloadMaxBytes = 1 << 32   // 4 GiB staged-copy cap (compose image tars)
let v2ComposeManifestMaxBytes = 1 << 20   // 1 MiB cap for the app-compose manifest bytes
let v2PathMaxBytes = 1024

func runHvFV2(out: URL, sessionPath: String, challengeHex: String, keyId: String) async throws {
    // Provisional whole-run bound while the external documents are parsed;
    // tightened to the resolved runtime bound below (A5: the watchdog is
    // already live, so even a stuck parse is bounded).
    setRunDeadline(started + .seconds(3600 + setupAllowanceSeconds))

    // ---- session document: exact bytes, canonical JSON, exact key set ----
    let sessionBytes = try read(sessionPath, max: 65536)
    let sessionObject = try JSONSerialization.jsonObject(with: sessionBytes)
    guard try canonical(sessionObject) == sessionBytes else { throw Fail("session is not canonical JSON") }
    let s = try requireExactKeys(sessionObject, [
        "schema", "policy_path", "image_manifest_path", "checksum_manifest_path",
        "metadata_path", "admission_path", "compose_manifest_path", "profile",
        "workload_disk_path", "workload_sha256", "workload_id", "runtime_seconds",
    ], "session")
    guard try requireNonEmptyString(s, "schema", "session") == v2SessionSchema else {
        throw Fail("session schema != \(v2SessionSchema)")
    }
    var docPaths: [String: String] = [:]
    for k in ["policy_path", "image_manifest_path", "checksum_manifest_path", "metadata_path", "admission_path", "compose_manifest_path", "workload_disk_path"] {
        let p = try requireNonEmptyString(s, k, "session")
        guard printableASCII(p, maxBytes: v2PathMaxBytes), p.hasPrefix("/") else {
            throw Fail("session.\(k): absolute printable-ASCII path required")
        }
        docPaths[k] = p
    }
    let profileName = try requireNonEmptyString(s, "profile", "session")
    guard printableASCII(profileName, maxBytes: 128) else { throw Fail("session.profile: printable ASCII required") }
    let workloadSha = try requireNonEmptyString(s, "workload_sha256", "session")
    guard isHex64(workloadSha) else { throw Fail("session.workload_sha256: lowercase hex sha256 required") }
    let workloadId = try requireNonEmptyString(s, "workload_id", "session")
    guard printableASCII(workloadId, maxBytes: 128) else { throw Fail("session.workload_id: printable ASCII required") }
    let runtimeRequest = try strictJSONInt(s["runtime_seconds"] as Any, "session.runtime_seconds")
    guard (1...86400).contains(runtimeRequest) else { throw Fail("session.runtime_seconds: 1..86400 required") }
    try trace("session_loaded", ["session_sha256": sha256hex(sessionBytes)])
    try checkCancellation()

    // ---- every external document: read ONCE, capped; digests over exact bytes ----
    let policyData = try read(docPaths["policy_path"]!, max: 65536)
    let manifestData = try read(docPaths["image_manifest_path"]!, max: 262144)
    let checksumData = try read(docPaths["checksum_manifest_path"]!, max: maxChecksumManifestBytes)
    let metadataData = try read(docPaths["metadata_path"]!, max: maxMetadataBytes)
    let admissionData = try read(docPaths["admission_path"]!, max: maxAdmissionBytes)
    // The submitted app-compose/workload manifest: read as EXACT OPAQUE bytes
    // (compose/task semantics live outside this signed app — it never parses
    // them). The attestation binds manifest_sha256 = sha256(these exact bytes),
    // the SAME digest the compose-runner computes (dsmack_compose_runner
    // sha256_hex(manifest_bytes)) and contract10 verify_attestation re-hashes
    // (attestation.py:875). This is DISTINCT from the image-manifest digest
    // (kernel/initrd/system-disk descriptor) carried as
    // identity.image_manifest_sha256. (N02; mac-source-integration-early lane:
    // the prior source bound the IMAGE-manifest digest into manifest_sha256,
    // which contract10 verify_attestation REJECTS as "does not match the
    // manifest bytes".)
    let composeManifestData = try read(docPaths["compose_manifest_path"]!, max: v2ComposeManifestMaxBytes)
    let composeManifestSha256 = sha256hex(composeManifestData)
    try trace("compose_manifest_bound", ["compose_manifest_sha256": composeManifestSha256])

    // ---- app-side admission core (parse strictly separate from decision) ----
    let policy = try parseAdmissionPolicy(policyData)
    let manifest = try parseImageManifest(manifestData)
    let admitted = try admitImage(policy: policy, manifestSha256: manifest.sha256, manifestImageId: manifest.imageId)
    try trace("image_admitted", ["image_id": admitted.imageId, "image_manifest_sha256": manifest.sha256, "policy_sha256": policy.sha256])

    // ---- contract10 identity world: checksum manifest + metadata + admission ----
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

    // ---- resolve (declared profile x policy caps) + the launch-spec digest ----
    let plan = try resolveLaunch(manifest: manifest, admission: admitted, policy: policy,
                                 profileName: profileName, requestedRuntimeSeconds: runtimeRequest)
    // The workload digest is verified against the STAGED COPY below; the
    // spec document is built after staging so it binds the staged reality.
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
    try trace("system_staged", ["sha256": systemStaged.sha256, "bytes": systemStaged.bytes])

    let workloadStaged = try stageVerifiedCopy(out, "workload.img.staged", src: docPaths["workload_disk_path"]!,
                                               maxBytes: v2WorkloadMaxBytes, wantSha256: workloadSha,
                                               wantBytes: nil)
    try trace("workload_staged", ["sha256": workloadStaged.sha256, "bytes": workloadStaged.bytes])

    let spec = try buildLaunchSpec(plan: plan, identity: identity, contract: contract, policy: policy,
                                   manifest: manifest, workloadSha256: workloadStaged.sha256,
                                   workloadId: workloadId)
    try save("launch-spec.json", spec.bytes)
    try trace("launch_spec_built", ["spec_sha256": spec.specSha256])

    // The scratch inode belongs to the BACKEND (fresh O_EXCL 0600; the app
    // only names the path and refuses a pre-existing one).
    let scratchPath = out.appendingPathComponent("scratch.img").path
    guard !FileManager.default.fileExists(atPath: scratchPath) else {
        throw Fail("scratch \(scratchPath) already exists; the backend creates it fresh per launch")
    }

    // ---- the control channel: socketpair; the backend owns fds[1] on EVERY return ----
    var fds: [Int32] = [-1, -1]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
        throw Fail("socketpair failed (errno \(errno))")
    }

    do {
        try backendV2Init()
        try checkCancellation()
        let consolePath = out.appendingPathComponent("console-v2.log").path
        let buildStarted = ContinuousClock.now
        let handle = try backendV2VmNew(
            kernel: kernelBytes, initrd: initrdBytes,
            specSha256: spec.specSha256,
            kernelSha256: manifest.kernel.sha256, initrdSha256: manifest.initrd.sha256,
            cmdline: plan.cmdline, cmdlineSha256: identity.cmdlineSha256,
            systemSha256: manifest.systemDisk.sha256, verityRootHash: manifest.verityRootHash,
            workloadSha256: workloadStaged.sha256,
            ramMib: UInt32(plan.memMib), vcpus: UInt32(plan.vcpus),
            systemPath: systemStaged.path, scratchPath: scratchPath, workloadPath: workloadStaged.path,
            consoleLogPath: consolePath, controlFd: fds[1])
        // On success fds[1] lives inside the backend handle; the app end
        // stays open until the run returns (closing it early would hand the
        // guest control console an EOF).
        let buildMs = Int((ContinuousClock.now - buildStarted) / .milliseconds(1))

        // R5: the receipt is read BEFORE run (the handle is consumed by run).
        let receiptData = Data(try backendV2Receipt(handle: handle).utf8)

        // ---- observed-vs-admitted cross-check + contract10 receipt mapping,
        //      performed BEFORE run (ORDERING REPAIR, mac-runtime-seam-repair
        //      lane; flagged by mac-compile-followthrough §6). The prior source
        //      mapped the receipt AFTER backendV2Run — i.e. a receipt whose
        //      spec_sha256 / observed tuple disagreed with the admitted inputs
        //      was only caught after the guest had already executed. The
        //      receipt is available before run (R5) and mapLaunchReceipt
        //      consumes only receipt + admission inputs (never run outputs), so
        //      the full fail-closed cross-check — including the new spec_sha256
        //      equality against the locally constructed launch-spec digest —
        //      now runs here, stopping a disagreeing receipt BEFORE any VM runs.
        let mapped = try mapLaunchReceipt(receiptData, plan: plan, identity: identity, manifest: manifest, contract: contract,
                                          workloadSha256: workloadStaged.sha256, workloadBytes: workloadStaged.bytes,
                                          rootfsTotalBytes: systemStaged.bytes, expectedSpecSha256: spec.specSha256)

        try checkCancellation()
        let runStarted = ContinuousClock.now
        let code = try backendV2Run(handle: handle)
        try checkCancellation()   // between backend return and publication only
        let runMs = Int((ContinuousClock.now - runStarted) / .milliseconds(1))
        // The control peer is gone (checked teardown); the app end is ours again.
        close(fds[0])
        fds[0] = -1

        // Console commitments over the FINAL bytes, after checked teardown.
        // THROWING bounded read (console_swift repair, CROSS-LANE-VERIFIED-FINDINGS
        // console_swift: "Use throwing bounded read, no empty hash substitution").
        // The prior `(try? …) ?? Data()` silently substituted empty Data on any
        // open/read failure, so a missing or unreadable console committed to the
        // EMPTY-string sha256 — a false "clean console" in the signed statement.
        // The backend created the console O_EXCL and finished checked teardown
        // before returning, so an unreadable console here is a genuine refusal:
        // fail closed, no statement/assertion is produced.
        let consoleBytes = try FileHandle(forReadingFrom: URL(fileURLWithPath: consolePath)).read(upToCount: outputLimit + 1) ?? Data()
        let consoleCut = consoleBytes.count > outputLimit
        try trace("backend_returned", ["vmm_code": Int(code), "run_ms": runMs, "build_ms": buildMs,
                                       "console_sha256": sha256hex(consoleBytes.prefix(outputLimit)),
                                       "console_bytes": consoleBytes.count, "console_truncated": consoleCut])

        // ---- the contract10 domain-separated receipt-evidence assertion ----
        // (ASSERTION REPAIR, mac-runtime-seam-repair lane; flagged by
        // mac-compile-followthrough §6. COMPOSE-MANIFEST BINDING REPAIR,
        // mac-source-integration-early lane; N02.) evidence_sha256 is computed
        // over the frozen receipt-evidence body under EVIDENCE_DOMAIN; the App
        // Attest assertion signs the ASSERTION_DOMAIN client-data binding the
        // SUBMITTED COMPOSE-MANIFEST digest (= sha256 of the exact app-compose
        // manifest bytes, the value contract10 verify_attestation re-hashes),
        // that evidence digest and the challenge — NOT the image-manifest digest
        // (which contract10 rejects) and NOT a bare hash of a bespoke parallel
        // statement schema (see AssertionEvidence.swift).
        let evidenceBody = launcherEvidenceBody(
            baseVm: mapped.fragment["base_vm"] as! [String: Any],
            baseVmLaunch: mapped.fragment["base_vm_launch"] as! [String: Any],
            observed: mapped.observed, manifestSha256: composeManifestSha256)
        let evidenceSha256 = try executionEvidenceDigest(evidenceBody)
        let clientData = try assertionClientData(manifestSha256: composeManifestSha256,
                                                 evidenceSha256: evidenceSha256, challenge: challengeHex)

        // ---- run record: the contract10 receipt-evidence body + the exact
        //      digests the assertion binds (NOT a parallel attested schema).
        //      Run outputs (lifecycle/console) are recorded for operators but
        //      are compose-runner-world evidence bound downstream, not by this
        //      launcher's base-VM-launch assertion.
        let statement = try canonicalJSONData([
            "schema": v2StatementSchema,
            "challenge": challengeHex,
            "key_id": keyId,
            // The contract10 domain-separated receipt-evidence assertion this
            // run signs (replacing the prior parallel-statement hash): the
            // assertion client-data is assertionClientData(manifest_sha256,
            // evidence_sha256, challenge) and the clientDataHash is its SHA256.
            "assertion": [
                "assertion_domain": assertionDomain,
                "evidence_domain": evidenceDomain,
                "manifest_sha256": composeManifestSha256,
                "evidence_sha256": evidenceSha256,
                "client_data_sha256": sha256hex(clientData),
                "receipt_evidence_body": evidenceBody,
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
                          "runtime_bound_seconds": plan.runtimeSeconds,
                          "policy_limits": ["max_mem_mib": policy.limits.maxMemMib,
                                            "max_vcpus": policy.limits.maxVcpus,
                                            "max_runtime_seconds": policy.limits.maxRuntimeSeconds] as [String: Any]],
            "staging": ["method": "read-once/copy-once hash + private staged copy re-hash; backend verify-on-open (dual control)",
                        "kernel_bytes": kernelBytes.count, "initrd_bytes": initrdBytes.count,
                        "system_bytes": systemStaged.bytes, "workload_bytes": workloadStaged.bytes,
                        "scratch_fresh_inode": true, "arch": plan.arch],
            "lifecycle": ["backend_abi": 2, "build_ms": buildMs, "run_ms": runMs, "vmm_code": Int(code),
                          "vmm_code_semantics": "0 = guest halt (PSCI), never workload success"],
            "output": ["limit_bytes": outputLimit, "console_sha256": sha256hex(consoleBytes.prefix(outputLimit)),
                       "console_bytes": consoleBytes.count, "console_truncated": consoleCut],
            "contract10_receipt_fragment": mapped.fragment,
            "honesty": [
                "host_root_confidentiality": "NOT established: App Attest / signing / boot do NOT prove host-root cannot read guest memory or devices (ledger 13.4)",
                "boot_loader_modes": "kernel/initrd/cmdline: backend-owned-copy buffers (guest RAM written from the verified owned copies); system/workload disks: verify-on-open + verify-at-attach BY PATH — the fragment's loader_mode claims only the weakest link (held-fd)",
                "cmdline_boot_tuple": "the admitted hvc0-only cmdline is DERIVED from the dstack bundle identity; the x86 TCG smoke ran a ttyAMA0-prepended console order — the first native HVF boot is the first execution of this exact tuple (fable-native-audit F6)",
                "workload_semantics": "compose/Claude/task/marketplace policy is OUTSIDE this app; the workload is untrusted transport content on a read-only disk the guest supervisor re-verifies (SHA256SUMS dual control)",
                "mac_attestation": "a real DCAppAttestService.generateAssertion; the clientDataHash is SHA256 of the contract10 domain-separated assertion client-data (dsmack.appattest.assertion/4 binding the SUBMITTED COMPOSE-MANIFEST digest = sha256(exact app-compose manifest bytes), the dsmack.receipt-evidence/4 evidence digest, and the challenge) — this is the value contract10 verify_attestation re-hashes; the DISTINCT image-manifest digest is carried as identity.image_manifest_sha256 and is NOT what the attestation binds. NOT a bare hash of a parallel statement schema. The App Attest assertion counter binds via authenticatorData (verifier side). Assertion verification is the separate relying-party boundary.",
                "guest_private_logs": "console markers + digest commitments only; guest-private state dies with the fresh scratch disk",
            ] as [String: Any],
            "trace": ["head": head, "events": seq],
        ] as [String: Any])

        guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
        else { throw Fail("execution cancelled before assertion") }
        let svc = DCAppAttestService.shared
        guard svc.isSupported else { throw Fail("App Attest unsupported in this process; refusing to run") }
        let assertion = try await svc.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
        guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
        else { throw Fail("execution cancelled before publication") }
        try save("statement.json", statement)
        try save("assertion.cbor", assertion)
        try save("keyId.txt", Data(keyId.utf8))
        dropScratch()
        runFinished.withLock { $0 = true }
    } catch {
        // fds discipline: on any refusal inside backendV2VmNew the backend
        // already closed fds[1] exactly once; on a caller-side pre-check
        // throw it is still open and ours. Probe, never guess.
        if fds[1] >= 0, fcntl(fds[1], F_GETFD) != -1 { close(fds[1]) }
        if fds[0] >= 0 { close(fds[0]) }
        note("hvf-v2 failed: \(error)")
        dropScratch()
        runFinished.withLock { $0 = true }
        throw error
    }
}

/// OWNED-COPY staging: read-once chunked copy into a fresh O_EXCL 0600 file
/// inside the private out dir, hashing THE COPY while it is written, then a
/// chunked read-back re-hash of the staged file (belt and braces). Refuses
/// on any size/digest mismatch; `wantBytes == nil` skips the size
/// expectation (the digest still binds the bytes).
// Module-internal (not file-private) so the v3 launch path reuses this exact
// owned-copy staging discipline (loop40-swift-repair1 lane; SWIFT03).
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

/// Chunked sha256 over a file's bytes (no full in-memory read). Module-internal
/// (shared with the v3 launch path).
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
