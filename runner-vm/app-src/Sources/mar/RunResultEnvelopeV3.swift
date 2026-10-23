// RunResultEnvelopeV3.swift — the AUTHENTICATED run-result envelope + result
// assertion composer for the v3 launch path (loop40-swift-repair1 lane,
// 2026-10-22; SWIFT04). The rejected candidate stopped at the launch assertion
// (base-VM admission). This composes the SEPARATE run-result attestation the
// review demanded: it binds the finalized result-disk / console / lifecycle
// digests the backend produced through CHECKED finalize_v3 — NOT a relabelled
// launch assertion.
//
// Domains / schemas are the io-contract-reference normative constants
// (io-contract-reference/candidate/runresult_ref/protocol.py). The exact key
// sets (ENVELOPE_KEYS, ENVELOPE_*_KEYS) are reproduced verbatim; a strict parse
// of the backend run-result (dsmack-backend-v3/run-result/1) feeds them.
//
// Relationship of the two assertions (both REAL DCAppAttestService.generateAssertion,
// both retained — SWIFT04 "retain both assertions"):
//   LAUNCH  assertion signs assertionClientData(M, L, challenge)  [AssertionEvidence.swift]
//           where L = execution_evidence_digest(launch receipt-evidence body).
//   RESULT  assertion signs resultAssertionClientData(L, E, challenge)
//           where L = the SAME launch-evidence digest the launch assertion
//           bound and E = sha256_obj([ENVELOPE_DOMAIN, envelope_body]) — the
//           DOMAIN-SEPARATED envelope digest. This is byte-for-byte the
//           io-contract-reference result preimage (statement.py result_client_data:
//           domain, L, E, challenge) and envelope digest (statement.py
//           envelope_digest: sha256_obj([ENVELOPE_DOMAIN, body])). SWIFT04 repair2:
//           the rejected repair1 signed (M, E) with E over the BARE envelope — both
//           are corrected here to the reference so the signed bytes verify.
// A PSCI halt (lifecycle.vmm_code == 0) is NOT workload success: the envelope
// records the finalized outputs; whether the WORKLOAD succeeded is a downstream
// checker determination over the retained result-disk bytes, never claimed here.

import CryptoKit
import Foundation

// io-contract-reference normative constants (protocol.py).
let envelopeSchema = "dsmack-general-launcher/run-result-envelope/1"   // ENVELOPE_SCHEMA
let envelopeDomain = "dsmack.run-result-envelope/1"                    // ENVELOPE_DOMAIN
let resultAssertionDomain = "dsmack.appattest.run-result/1"            // RESULT_ASSERTION_DOMAIN
let kConsoleLimitBytes = 16_777_216                                    // MAX_CONSOLE_BYTES (R06)
let kConsoleSlackBytes = 0                                             // CONSOLE_SLACK_BYTES (protocol.py:190)
let kResultTemplateBytesMax = 1 << 30                                  // RESULT_TEMPLATE_BYTES_MAX (protocol.py:192)
let kResultDiskMinBytes = 512                                          // schemas.py result_disk bytes/template_bytes lo=512

/// Strictly parsed backend run-result (dsmack-backend-v3/run-result/1), with the
/// four envelope-aligned sections cross-checked against the admitted/observed
/// facts. A failure here is fail-closed: no envelope, no result assertion.
///
/// The four section dicts are REBUILT from the strictly-parsed NATIVE Swift
/// scalars (not carried verbatim from JSONSerialization): JSONSerialization
/// delivers every number as NSNumber, and canonicalJSONData's `case let n as Int`
/// would match an NSNumber-boolean before the Bool case and serialize `true` as
/// `1`. Rebuilding with real Int/Bool/String/NSNull keeps the canonical envelope
/// bytes correct and independent of the backend's key ordering.
struct RunResultV3Parsed {
    let resultDisk: [String: Any]
    let console: [String: Any]
    let runtimeInput: [String: Any]
    let lifecycle: [String: Any]
    // flattened, for the retention bundle / cross-checks
    let resultSha256: String
    let resultBytes: Int
    let consoleSha256: String
    let consoleBytes: Int
    let consoleTruncated: Bool
    let vmmCode: Int
}

/// Parse + cross-check the backend run-result JSON. `expectedResultTemplate*`
/// bind the vdd result disk to the SAME admitted template the receipt already
/// cross-checked (continuity); `expectedVmmCode` binds the result to the code
/// `backendV3Run` returned; `privatePresent` binds runtime_input.present.
func parseRunResultV3(_ resultData: Data, expectedResultTemplateSha256: String,
                      expectedResultTemplateBytes: Int, expectedVmmCode: Int,
                      privatePresent: Bool) throws -> RunResultV3Parsed {
    let r = try requireExactKeys(
        try JSONSerialization.jsonObject(with: resultData),
        ["schema", "result_disk", "console", "runtime_input", "lifecycle"],
        "v3 run-result")
    guard try requireNonEmptyString(r, "schema", "v3 run-result") == "dsmack-backend-v3/run-result/1" else {
        throw Fail("v3 run-result schema mismatch")
    }

    let rd = try requireExactKeys(r["result_disk"] as Any,
                                  ["role", "template_sha256", "template_bytes", "sha256", "bytes"],
                                  "v3 run-result.result_disk")
    let resultRole = try requireNonEmptyString(rd, "role", "v3 run-result.result_disk")
    let resultTemplateSha = try requireNonEmptyString(rd, "template_sha256", "v3 run-result.result_disk")
    let resultTemplateBytes = try strictJSONInt(rd["template_bytes"] as Any, "v3 run-result.result_disk.template_bytes")
    let resultSha = try requireNonEmptyString(rd, "sha256", "v3 run-result.result_disk")
    let resultBytes = try strictJSONInt(rd["bytes"] as Any, "v3 run-result.result_disk.bytes")
    guard isHex64(resultSha), isHex64(resultTemplateSha) else { throw Fail("v3 run-result.result_disk: sha256 fields must be 64-hex") }
    // SWIFT04 repair3: the reviewed envelope schema (schemas.py:134) pins the
    // result-disk ROLE to "vdd" — the finalized fifth-role returning disk. repair2
    // accepted an arbitrary non-empty role (so a relabelled scratch/vdb disk would
    // have composed an envelope the reference then refused with bad_result_disk_role).
    guard resultRole == "vdd" else { throw Fail("v3 run-result.result_disk.role must be \"vdd\" (got \"\(resultRole)\")") }
    // template_bytes bounds (schemas.py:136-137: lo=512, hi=RESULT_TEMPLATE_BYTES_MAX).
    guard resultTemplateBytes >= kResultDiskMinBytes, resultTemplateBytes <= kResultTemplateBytesMax else {
        throw Fail("v3 run-result.result_disk.template_bytes \(resultTemplateBytes) out of [\(kResultDiskMinBytes), \(kResultTemplateBytesMax)]")
    }
    guard resultTemplateSha == expectedResultTemplateSha256, resultTemplateBytes == expectedResultTemplateBytes else {
        throw Fail("v3 run-result result template (\(resultTemplateSha)/\(resultTemplateBytes)) != admitted (\(expectedResultTemplateSha256)/\(expectedResultTemplateBytes))")
    }
    // bytes bound lo=512 (schemas.py:139) AND the vdd disk is the SAME SIZE as its
    // template (schemas.py:140 result_disk_size_mismatch). repair2 only required
    // bytes>=0 and never compared bytes to template_bytes, so a size-divergent
    // result disk composed an envelope the reference refused.
    guard resultBytes >= kResultDiskMinBytes else { throw Fail("v3 run-result.result_disk.bytes \(resultBytes) < \(kResultDiskMinBytes)") }
    guard resultBytes == resultTemplateBytes else {
        throw Fail("v3 run-result.result_disk.bytes \(resultBytes) != template_bytes \(resultTemplateBytes) (result_disk_size_mismatch)")
    }

    let co = try requireExactKeys(r["console"] as Any,
                                  ["sha256", "bytes", "truncated", "limit_bytes"],
                                  "v3 run-result.console")
    let consoleSha = try requireNonEmptyString(co, "sha256", "v3 run-result.console")
    guard isHex64(consoleSha) else { throw Fail("v3 run-result.console.sha256 must be 64-hex") }
    let consoleBytes = try strictJSONInt(co["bytes"] as Any, "v3 run-result.console.bytes")
    let consoleTruncated = try strictJSONBool(co["truncated"] as Any, "v3 run-result.console.truncated")
    let consoleLimit = try strictJSONInt(co["limit_bytes"] as Any, "v3 run-result.console.limit_bytes")
    guard consoleLimit == kConsoleLimitBytes else {
        throw Fail("v3 run-result.console.limit_bytes \(consoleLimit) != contract R06 \(kConsoleLimitBytes)")
    }
    guard consoleBytes >= 0 else { throw Fail("v3 run-result.console.bytes negative") }
    // console_over_limit (schemas.py:149): final size <= limit + slack (slack 0).
    guard consoleBytes <= consoleLimit + kConsoleSlackBytes else {
        throw Fail("v3 run-result.console.bytes \(consoleBytes) > limit+slack \(consoleLimit + kConsoleSlackBytes)")
    }

    let ri = try requireExactKeys(r["runtime_input"] as Any,
                                  ["present", "max_bytes", "commitment_claim"],
                                  "v3 run-result.runtime_input")
    let riPresent = try strictJSONBool(ri["present"] as Any, "v3 run-result.runtime_input.present")
    guard riPresent == privatePresent else {
        throw Fail("v3 run-result runtime_input.present \(riPresent) != app-provided private input \(privatePresent)")
    }
    let riMaxBytes = try strictJSONInt(ri["max_bytes"] as Any, "v3 run-result.runtime_input.max_bytes")
    guard riMaxBytes >= 0 else { throw Fail("v3 run-result.runtime_input.max_bytes negative") }
    // SWIFT04 repair3: commitment_claim is EITHER JSON null OR a STRUCTURED claim
    // object {alg, scope, inputs_sha256} (schemas.py:155-161), NEVER a bare string.
    // repair2 accepted any string here, so a producer could have emitted a
    // string commitment_claim that the reference then refused (not_object). The
    // claim is still never derived from the UNMEASURED vde bytes — alg/scope/
    // inputs_sha256 are a CALLER-supplied opaque commitment binding; nothing about
    // vde content is read. The structured value is rebuilt from native scalars so
    // the canonical envelope bytes are correct and key-order independent.
    let riCommitment: Any
    switch ri["commitment_claim"] {
    case is NSNull, nil:
        riCommitment = NSNull()
    case let claimObj as [String: Any]:
        let c = try requireExactKeys(claimObj, ["alg", "scope", "inputs_sha256"],
                                     "v3 run-result.runtime_input.commitment_claim")
        let alg = try requireNonEmptyString(c, "alg", "v3 run-result.runtime_input.commitment_claim")
        // schemas.need_str(claim.alg, 128): bounded AND NUL-free. The reference
        // `need_str` bounds Python `len(value)`, which counts UNICODE CODE POINTS
        // (schemas.py:34). repair4 used Swift `alg.count`, which counts extended
        // grapheme CLUSTERS, so an alg of 65 "e\u{0301}" clusters (65 Characters but
        // 130 code points) passed the producer self-check while the reference refused
        // it with str_too_long — composition could still sign a reference-invalid
        // envelope (SWIFT04 repair5). `alg.unicodeScalars.count` is the Unicode-scalar
        // (code-point) count matching the reference bound; NUL-freeness is still
        // checked separately below (nul_in_str).
        guard alg.unicodeScalars.count <= 128 else { throw Fail("v3 run-result.runtime_input.commitment_claim.alg too long (<=128 code points)") }
        guard !alg.utf8.contains(0) else { throw Fail("v3 run-result.runtime_input.commitment_claim.alg contains NUL") }
        let inputsSha = try requireNonEmptyString(c, "inputs_sha256", "v3 run-result.runtime_input.commitment_claim")
        guard isHex64(inputsSha) else { throw Fail("v3 run-result.runtime_input.commitment_claim.inputs_sha256 must be 64-hex") }
        guard let scope = c["scope"] as? [String: Any] else {
            throw Fail("v3 run-result.runtime_input.commitment_claim.scope must be a JSON object")
        }
        riCommitment = ["alg": alg, "inputs_sha256": inputsSha,
                        "scope": try rebuildCanonicalValue(scope)]
    default:
        throw Fail("v3 run-result.runtime_input.commitment_claim must be null or a structured claim object {alg, scope, inputs_sha256}")
    }

    let lc = try requireExactKeys(r["lifecycle"] as Any,
                                  ["vmm_code", "run_ms", "backend_abi"],
                                  "v3 run-result.lifecycle")
    let vmmCode = try strictJSONInt(lc["vmm_code"] as Any, "v3 run-result.lifecycle.vmm_code")
    let runMs = try strictJSONInt(lc["run_ms"] as Any, "v3 run-result.lifecycle.run_ms")
    // schemas.need_int(run_ms) uses the default lo=0: run_ms is a NONNEGATIVE
    // elapsed-milliseconds count. repair3 checked only its integer type, so a
    // backend result with run_ms=-1 composed an envelope the reference then refused
    // with bad_int — the SWIFT04 negative-run_ms producer regression.
    guard runMs >= 0 else { throw Fail("v3 run-result.lifecycle.run_ms \(runMs) is negative (need_int lo=0)") }
    let backendAbi = try strictJSONInt(lc["backend_abi"] as Any, "v3 run-result.lifecycle.backend_abi")
    guard backendAbi == 3 else { throw Fail("v3 run-result lifecycle.backend_abi \(backendAbi) != 3") }
    guard vmmCode == expectedVmmCode else {
        throw Fail("v3 run-result lifecycle.vmm_code \(vmmCode) != the code run_v3 returned (\(expectedVmmCode))")
    }

    // Rebuild each envelope section from NATIVE scalars (see the struct note).
    let resultDisk: [String: Any] = [
        "role": resultRole, "template_sha256": resultTemplateSha, "template_bytes": resultTemplateBytes,
        "sha256": resultSha, "bytes": resultBytes,
    ]
    let console: [String: Any] = [
        "sha256": consoleSha, "bytes": consoleBytes, "truncated": consoleTruncated, "limit_bytes": consoleLimit,
    ]
    let runtimeInput: [String: Any] = [
        "present": riPresent, "max_bytes": riMaxBytes, "commitment_claim": riCommitment,
    ]
    let lifecycle: [String: Any] = [
        "vmm_code": vmmCode, "run_ms": runMs, "backend_abi": backendAbi,
    ]

    return RunResultV3Parsed(
        resultDisk: resultDisk, console: console, runtimeInput: runtimeInput, lifecycle: lifecycle,
        resultSha256: resultSha, resultBytes: resultBytes,
        consoleSha256: consoleSha, consoleBytes: consoleBytes,
        consoleTruncated: consoleTruncated, vmmCode: vmmCode)
}

/// Compose the authenticated run-result envelope (ENVELOPE_KEYS). Returns the
/// document, its exact canonical bytes (the RETAINED envelope.json — the verifier
/// re-parses these and recomputes the digest) and the DOMAIN-SEPARATED envelope
/// digest E = sha256_obj([ENVELOPE_DOMAIN, body]) (statement.py:146-147
/// `envelope_digest`). SWIFT04 repair2: repair1 returned sha256(BARE bytes); the
/// reference verifier hashes [ENVELOPE_DOMAIN, envelope], so a bare-envelope E
/// never matched and the result assertion could not verify. Corrected here.
func composeRunResultEnvelope(launchEvidenceSha256: String, manifestSha256: String,
                              challenge: String, keyIdB64: String, launchCounter: Int,
                              parsed: RunResultV3Parsed) throws -> (doc: [String: Any], bytes: Data, envelopeSha256: String) {
    let doc: [String: Any] = [
        "schema": envelopeSchema,
        "launch": [
            "evidence_sha256": launchEvidenceSha256,
            "manifest_sha256": manifestSha256,
            "challenge": challenge,
            "key_id_b64": keyIdB64,
            "counter": launchCounter,
        ],
        "result_disk": parsed.resultDisk,
        "console": parsed.console,
        "runtime_input": parsed.runtimeInput,
        "lifecycle": parsed.lifecycle,
        // The envelope exists only after CHECKED finalize_v3 ran the guest to a
        // proven PSCI halt and flushed/synced + hashed the retained result disk
        // and console. The io-contract-reference pins this production state as
        // "halted" (schemas.py:167 `need(obj["status"] == "halted")`); repair1's
        // "finalized" was rejected by validate_envelope_body. It is NOT a
        // workload-success claim (vmm_code lives in lifecycle; task outcome is
        // pinned downstream over the retained result bytes).
        "status": "halted",
    ]
    // SWIFT04 repair3: the producer SELF-VALIDATES the composed body against the
    // EXACT reviewed envelope schema (schemas.validate_envelope_body) BEFORE it is
    // retained, digested or signed. This fails CLOSED on any bound the reference
    // would refuse (role!=vdd, size mismatch, console over limit, string/malformed
    // commitment_claim, nonzero vmm_code, status!=halted, backend_abi!=3, bad key
    // sets) so the app can never emit an envelope + result assertion over bytes the
    // reference verifier then rejects. repair2 computed E / signed first and only a
    // downstream consumer discovered the divergence.
    try validateEnvelopeBodyV3(doc)
    // The RETAINED bytes are the bare canonical envelope (verifier parses these).
    let bytes = try canonicalJSONData(doc)
    // E is the DOMAIN-SEPARATED digest the result assertion / pair evidence bind:
    // sha256 over canonical([ENVELOPE_DOMAIN, body]) == statement.py envelope_digest.
    let envelopeSha256 = sha256hex(try canonicalJSONData([envelopeDomain, doc]))
    return (doc, bytes, envelopeSha256)
}

/// The exact client-data bytes the RESULT App Attest assertion signs: the
/// contract domain-separated run-result preimage binding the launch-evidence
/// digest (L — the SAME value the launch assertion bound), the domain-separated
/// envelope digest (E) and the fresh challenge (counter binds via
/// authenticatorData). NUL-joined under RESULT_ASSERTION_DOMAIN — byte-for-byte
/// io-contract-reference statement.py:40-53 `result_client_data(L, E, challenge)`.
/// SWIFT04 repair2: repair1 bound (M, E); the reference binds (L, E), so the
/// manifest digest M is replaced by the launch-evidence digest L. Binding L
/// chains the result assertion to the exact authenticated launch statement
/// (whose only authenticated content is the receipt-evidence body whose digest
/// IS L), not merely to the compose-manifest bytes.
func resultAssertionClientData(launchEvidenceSha256: String, envelopeSha256: String, challenge: String) throws -> Data {
    guard isHex64(launchEvidenceSha256) else { throw Fail("result assertion launch_evidence_sha256 (L) must be 64-hex") }
    guard isHex64(envelopeSha256) else { throw Fail("result assertion envelope_sha256 (E) must be 64-hex") }
    guard !challenge.isEmpty, !challenge.utf8.contains(0) else {
        throw Fail("result assertion challenge must be a non-empty string without NUL")
    }
    var out = Data()
    let nul = Data([0x00])
    out.append(Data(resultAssertionDomain.utf8)); out.append(nul)
    out.append(Data(launchEvidenceSha256.utf8)); out.append(nul)   // L
    out.append(Data(envelopeSha256.utf8)); out.append(nul)         // E
    out.append(Data(challenge.utf8))
    return out
}

/// Recursively rebuild a JSONSerialization value tree from NATIVE Swift scalars
/// (NSNumber → Int / Bool with the strict objCType discipline, String / NSNull
/// pass through, arrays / objects recurse). This keeps `canonicalJSONData`'s
/// byte output correct and key-order independent for nested values the strict
/// scalar rules (CanonicalJSON.swift) must still apply to — e.g. the
/// commitment_claim.scope object. Double / unexpected types are refused, exactly
/// as the top-level canonical emitter refuses them.
func rebuildCanonicalValue(_ v: Any) throws -> Any {
    switch v {
    case is NSNull:
        return NSNull()
    case let n as NSNumber:
        let t = String(cString: n.objCType)
        if t == "c" || t == "B" { return n.boolValue }
        switch t {
        case "q", "l", "i", "s", "Q", "I", "L", "S": return n.intValue
        default: throw Fail("commitment_claim.scope: unsupported number objCType \"\(t)\" (Int/Bool only)")
        }
    case let s as String:
        return s
    case let a as [Any]:
        return try a.map { try rebuildCanonicalValue($0) }
    case let d as [String: Any]:
        var out: [String: Any] = [:]
        for (k, vv) in d { out[k] = try rebuildCanonicalValue(vv) }
        return out
    default:
        throw Fail("commitment_claim.scope: unsupported value type \(type(of: v))")
    }
}

/// Self-validate a composed run-result envelope body against the EXACT reviewed
/// schema (io-contract-reference schemas.validate_envelope_body, pin
/// 308b15d9…). Mirrors every exact-key set and numeric bound; fails CLOSED. The
/// producer calls this before retaining/digesting/signing so it can never emit an
/// envelope the reference verifier would reject (SWIFT04 repair3).
func validateEnvelopeBodyV3(_ obj: [String: Any]) throws {
    let e = try requireExactKeys(obj, ["schema", "launch", "result_disk", "console",
                                       "runtime_input", "lifecycle", "status"], "envelope")
    guard (e["schema"] as? String) == envelopeSchema else { throw Fail("envelope.schema != \(envelopeSchema)") }

    let launch = try requireExactKeys(e["launch"] as Any,
                                      ["evidence_sha256", "manifest_sha256", "challenge", "key_id_b64", "counter"],
                                      "envelope.launch")
    guard isHex64(try requireNonEmptyString(launch, "evidence_sha256", "envelope.launch")) else { throw Fail("envelope.launch.evidence_sha256 must be 64-hex") }
    guard isHex64(try requireNonEmptyString(launch, "manifest_sha256", "envelope.launch")) else { throw Fail("envelope.launch.manifest_sha256 must be 64-hex") }
    let lch = try requireNonEmptyString(launch, "challenge", "envelope.launch")
    guard lch.utf8.count <= 4096, !lch.utf8.contains(0) else { throw Fail("envelope.launch.challenge bounds") }
    let kid = try requireNonEmptyString(launch, "key_id_b64", "envelope.launch")
    // schemas.need_b64(key_id_b64, MAX_KEY_ID_B64=60, max_decoded=32): the key id is
    // the App Attest SHA-256 key-id, so it must be CANONICAL base64 that decodes to
    // at most 32 bytes. repair3 checked only the character length (<=60), so a
    // non-canonical or over-long-decoding key_id_b64 passed the producer self-check
    // yet the reference refused it with bad_b64 / noncanonical_b64 / b64_too_large.
    _ = try requireCanonicalBase64(kid, maxChars: 60, maxDecoded: 32, "envelope.launch.key_id_b64")
    // schemas.need_int(launch.counter) default lo=0: the assertion counter is
    // nonnegative. repair3 checked only the integer type.
    guard try strictJSONInt(launch["counter"] as Any, "envelope.launch.counter") >= 0 else {
        throw Fail("envelope.launch.counter is negative (need_int lo=0)")
    }

    let disk = try requireExactKeys(e["result_disk"] as Any,
                                    ["role", "template_sha256", "template_bytes", "sha256", "bytes"],
                                    "envelope.result_disk")
    guard (disk["role"] as? String) == "vdd" else { throw Fail("envelope.result_disk.role != vdd") }
    guard isHex64(try requireNonEmptyString(disk, "template_sha256", "envelope.result_disk")) else { throw Fail("envelope.result_disk.template_sha256 must be 64-hex") }
    let tb = try strictJSONInt(disk["template_bytes"] as Any, "envelope.result_disk.template_bytes")
    guard tb >= kResultDiskMinBytes, tb <= kResultTemplateBytesMax else { throw Fail("envelope.result_disk.template_bytes out of bounds") }
    guard isHex64(try requireNonEmptyString(disk, "sha256", "envelope.result_disk")) else { throw Fail("envelope.result_disk.sha256 must be 64-hex") }
    let db = try strictJSONInt(disk["bytes"] as Any, "envelope.result_disk.bytes")
    guard db >= kResultDiskMinBytes else { throw Fail("envelope.result_disk.bytes < \(kResultDiskMinBytes)") }
    guard db == tb else { throw Fail("envelope.result_disk size mismatch (bytes \(db) != template_bytes \(tb))") }

    let console = try requireExactKeys(e["console"] as Any,
                                       ["sha256", "bytes", "truncated", "limit_bytes"], "envelope.console")
    guard isHex64(try requireNonEmptyString(console, "sha256", "envelope.console")) else { throw Fail("envelope.console.sha256 must be 64-hex") }
    let cb = try strictJSONInt(console["bytes"] as Any, "envelope.console.bytes")
    _ = try strictJSONBool(console["truncated"] as Any, "envelope.console.truncated")
    let cl = try strictJSONInt(console["limit_bytes"] as Any, "envelope.console.limit_bytes")
    guard cl == kConsoleLimitBytes else { throw Fail("envelope.console.limit_bytes != \(kConsoleLimitBytes)") }
    guard cb >= 0, cb <= cl + kConsoleSlackBytes else { throw Fail("envelope.console.bytes over limit+slack") }

    let rti = try requireExactKeys(e["runtime_input"] as Any,
                                   ["present", "max_bytes", "commitment_claim"], "envelope.runtime_input")
    _ = try strictJSONBool(rti["present"] as Any, "envelope.runtime_input.present")
    guard try strictJSONInt(rti["max_bytes"] as Any, "envelope.runtime_input.max_bytes") >= 0 else {
        throw Fail("envelope.runtime_input.max_bytes is negative (need_int lo=0)")
    }
    switch rti["commitment_claim"] {
    case is NSNull, nil:
        break
    case let claim as [String: Any]:
        let c = try requireExactKeys(claim, ["alg", "scope", "inputs_sha256"], "envelope.runtime_input.commitment_claim")
        let alg = try requireNonEmptyString(c, "alg", "envelope.runtime_input.commitment_claim")
        // Unicode CODE-POINT bound matching the reference `need_str` len() (see the
        // producer-parse note above); Swift `.count` (grapheme clusters) under-counts
        // combining sequences and let a reference-invalid alg pass (SWIFT04 repair5).
        guard alg.unicodeScalars.count <= 128 else { throw Fail("commitment_claim.alg too long (<=128 code points, str_too_long)") }
        guard !alg.utf8.contains(0) else { throw Fail("commitment_claim.alg contains NUL (nul_in_str)") }
        guard isHex64(try requireNonEmptyString(c, "inputs_sha256", "envelope.runtime_input.commitment_claim")) else { throw Fail("commitment_claim.inputs_sha256 must be 64-hex") }
        guard c["scope"] is [String: Any] else { throw Fail("commitment_claim.scope must be an object") }
    default:
        throw Fail("envelope.runtime_input.commitment_claim must be null or a structured claim object")
    }

    let life = try requireExactKeys(e["lifecycle"] as Any,
                                    ["vmm_code", "run_ms", "backend_abi"], "envelope.lifecycle")
    guard try strictJSONInt(life["vmm_code"] as Any, "envelope.lifecycle.vmm_code") == 0 else { throw Fail("envelope.lifecycle.vmm_code != 0 (nonzero_vmm_code); no envelope exists for a non-halt") }
    guard try strictJSONInt(life["run_ms"] as Any, "envelope.lifecycle.run_ms") >= 0 else {
        throw Fail("envelope.lifecycle.run_ms is negative (need_int lo=0)")
    }
    guard try strictJSONInt(life["backend_abi"] as Any, "envelope.lifecycle.backend_abi") == 3 else { throw Fail("envelope.lifecycle.backend_abi != 3") }

    guard (e["status"] as? String) == "halted" else { throw Fail("envelope.status != halted") }
}

/// Validate a CANONICAL base64 string, mirroring the reference schemas.need_b64
/// (SWIFT04 repair4): within the character cap, strictly decodable, canonical (a
/// re-encode of the decoded bytes reproduces the input byte-for-byte — this rejects
/// non-canonical trailing bits and alternate paddings the way Python's
/// `base64.b64encode(raw).decode() == value` does) and, when `maxDecoded` is given,
/// decoding to at most that many bytes. Returns the decoded bytes. repair3 checked
/// only key_id_b64's character length, so a non-canonical or over-decoding key id
/// passed the producer self-check while the reference refused it.
func requireCanonicalBase64(_ s: String, maxChars: Int, maxDecoded: Int?, _ what: String) throws -> Data {
    guard s.utf8.count <= maxChars else { throw Fail("\(what): base64 too long (<=\(maxChars) chars)") }
    guard let raw = Data(base64Encoded: s, options: []) else { throw Fail("\(what): not valid base64 (bad_b64)") }
    guard raw.base64EncodedString() == s else { throw Fail("\(what): non-canonical base64 (noncanonical_b64)") }
    if let md = maxDecoded {
        guard raw.count <= md else { throw Fail("\(what): base64 decodes to \(raw.count) bytes (> \(md), b64_too_large)") }
    }
    return raw
}
