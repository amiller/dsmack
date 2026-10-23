// main.swift — PRODUCER-side golden check (SWIFT04 repair3).
//
// SWIFT04 repair3: this file is named main.swift (NOT GoldenMain.swift) so its
// top-level guard/for/if statements are legal top-level executable code. The
// repair2 harness named it GoldenMain.swift with top-level statements in a
// non-main file, which swiftc rejects outright ("expressions are not allowed at
// the top level") — the "executable producer proof" never compiled. It now
// compiles and RUNS the REAL production compose path against the committed vectors.
//
// Compiles the REAL pure contract sources (CanonicalJSON.swift, AssertionEvidence.swift,
// RunResultEnvelopeV3.swift) + GoldenShim.swift and proves the launcher's production
// functions reproduce the committed golden bytes the io-contract-reference verifier
// accepts (vectors/ produced by gen_golden.py; verified by consumer.py).
//
// For each golden case it:
//   1. feeds the committed backend-run-result JSON to the REAL parseRunResultV3,
//   2. composes the envelope with the REAL composeRunResultEnvelope(L, M, …),
//   3. asserts the canonical envelope bytes == the committed envelope.<case>.json,
//   4. asserts the domain-separated envelope digest E == the committed expected E,
//   5. asserts resultAssertionClientData(L, E, challenge) hex == the committed hex,
//   6. asserts assertionClientData(M, L, challenge) hex == the committed launch hex.
//
// Run via run_golden_swift.sh (needs a Swift toolchain with CryptoKit, i.e. a Mac /
// the Mini). It is NOT wired into `swift build --product mar`, so it cannot affect
// the app build graph.
import CryptoKit
import Foundation

func die(_ s: String) -> Never { FileHandle.standardError.write(Data((s + "\n").utf8)); exit(1) }

let args = CommandLine.arguments
guard args.count == 2 else { die("usage: golden <vectors-dir>") }
let vectors = URL(fileURLWithPath: args[1], isDirectory: true)

func readData(_ name: String) -> Data {
    guard let d = try? Data(contentsOf: vectors.appendingPathComponent(name)) else { die("missing \(name)") }
    return d
}
func readJSON(_ name: String) -> [String: Any] {
    guard let o = try? JSONSerialization.jsonObject(with: readData(name)) as? [String: Any] else { die("bad json \(name)") }
    return o
}

let index = readJSON("INDEX.json")
guard let cases = index["cases"] as? [String] else { die("no cases") }

var failures = 0
for name in cases {
    let caseDoc = readJSON("case.\(name).json")
    let inputs = caseDoc["inputs"] as! [String: Any]
    let expected = caseDoc["expected"] as! [String: Any]
    let L = inputs["launch_evidence_sha256_L"] as! String
    let M = inputs["manifest_sha256_M"] as! String
    let challenge = inputs["challenge"] as! String
    let keyId = inputs["key_id_b64"] as! String
    let launchCounter = (inputs["launch_counter"] as! NSNumber).intValue
    let templateSha = inputs["result_template_sha256"] as! String
    let templateBytes = (inputs["result_template_bytes"] as! NSNumber).intValue
    let vmmCode = (inputs["expected_vmm_code"] as! NSNumber).intValue
    let privatePresent = (inputs["private_present"] as! NSNumber).boolValue

    let backend = readData("backend-run-result.\(name).json")
    let committedEnvelope = readData("envelope.\(name).json")

    do {
        // (1) REAL strict parse of the backend run-result.
        let parsed = try parseRunResultV3(backend, expectedResultTemplateSha256: templateSha,
                                          expectedResultTemplateBytes: templateBytes,
                                          expectedVmmCode: vmmCode, privatePresent: privatePresent)
        // (2) REAL envelope composition (L, M, challenge, keyId, counter).
        let env = try composeRunResultEnvelope(launchEvidenceSha256: L, manifestSha256: M,
                                               challenge: challenge, keyIdB64: keyId,
                                               launchCounter: launchCounter, parsed: parsed)
        // (3) exact canonical envelope bytes.
        guard env.bytes == committedEnvelope else {
            print("FAIL \(name): envelope bytes differ from committed golden"); failures += 1; continue
        }
        // (4) domain-separated envelope digest E.
        guard env.envelopeSha256 == (expected["envelope_digest_E"] as! String) else {
            print("FAIL \(name): E \(env.envelopeSha256) != expected \(expected["envelope_digest_E"]!)"); failures += 1; continue
        }
        // (5) result preimage over (L, E, challenge).
        let rcd = try resultAssertionClientData(launchEvidenceSha256: L,
                                                envelopeSha256: env.envelopeSha256, challenge: challenge)
        guard rcd.map({ String(format: "%02x", $0) }).joined() == (expected["result_client_data_hex"] as! String) else {
            print("FAIL \(name): result client-data hex mismatch"); failures += 1; continue
        }
        // (6) launch preimage over (M, L, challenge).
        let lcd = try assertionClientData(manifestSha256: M, evidenceSha256: L, challenge: challenge)
        guard lcd.map({ String(format: "%02x", $0) }).joined() == (expected["launch_client_data_hex"] as! String) else {
            print("FAIL \(name): launch client-data hex mismatch"); failures += 1; continue
        }
        print("PASS \(name)")
    } catch {
        print("FAIL \(name): \(error)"); failures += 1
    }
}
// --------------------------------------------------------------------------
// SWIFT04 repair3 — PRODUCER-BOUNDS negative suite. The review said the repair2
// parseRunResultV3 "accepts an arbitrary result role, nonmatching final/template
// sizes and string commitment_claim values, while the reference requires vdd,
// equal sizes and a structured claim or null." These cases feed the REAL
// parseRunResultV3 the exact counterexamples and assert it now REFUSES each (and
// still ACCEPTS a well-formed structured claim). This executes the fix, not a
// reconstruction.
// --------------------------------------------------------------------------
func expectThrow(_ label: String, _ body: () throws -> Void) {
    do { try body(); print("FAIL \(label): accepted (should have refused)"); failures += 1 }
    catch { print("PASS \(label): refused (\(error))") }
}
func expectOK(_ label: String, _ body: () throws -> Void) {
    do { try body(); print("PASS \(label): accepted") }
    catch { print("FAIL \(label): refused (\(error))"); failures += 1 }
}

print("== producer-bounds negative suite (parseRunResultV3 refuses the repair2 gaps) ==")
let n0 = cases[0]
let c0 = readJSON("case.\(n0).json")
let in0 = c0["inputs"] as! [String: Any]
let tSha = in0["result_template_sha256"] as! String
let tBytes = (in0["result_template_bytes"] as! NSNumber).intValue
let vmm0 = (in0["expected_vmm_code"] as! NSNumber).intValue
// The committed (valid) backend run-result as a mutable dict.
let baseBackend = (try! JSONSerialization.jsonObject(with: readData("backend-run-result.\(n0).json"))) as! [String: Any]
func backendData(_ d: [String: Any]) -> Data { try! JSONSerialization.data(withJSONObject: d) }
func withResultDisk(_ mutate: (inout [String: Any]) -> Void) -> Data {
    var b = baseBackend; var rd = b["result_disk"] as! [String: Any]; mutate(&rd); b["result_disk"] = rd; return backendData(b)
}
func withRuntimeInput(_ mutate: (inout [String: Any]) -> Void) -> Data {
    var b = baseBackend; var ri = b["runtime_input"] as! [String: Any]; mutate(&ri); b["runtime_input"] = ri; return backendData(b)
}
func parse(_ data: Data, present: Bool = false) throws {
    _ = try parseRunResultV3(data, expectedResultTemplateSha256: tSha, expectedResultTemplateBytes: tBytes,
                             expectedVmmCode: vmm0, privatePresent: present)
}

// sanity: the unmutated committed vector still parses.
expectOK("baseline_valid_backend_run_result_parses") { try parse(backendData(baseBackend)) }
// (a) arbitrary result role (not "vdd").
expectThrow("result_role_scratch_refused") { try parse(withResultDisk { $0["role"] = "scratch" }) }
// (b) result bytes != template bytes (final/template size mismatch).
expectThrow("result_size_mismatch_refused") { try parse(withResultDisk { $0["bytes"] = tBytes + 512 }) }
// (c) commitment_claim as a bare string.
expectThrow("string_commitment_claim_refused") { try parse(withRuntimeInput { $0["commitment_claim"] = "opaque-string" }) }
// (d) commitment_claim as a malformed object (missing keys) is refused too.
expectThrow("malformed_claim_object_refused") {
    try parse(withRuntimeInput { ri in ri["present"] = true; ri["commitment_claim"] = ["alg": "sha256"] }, present: true)
}
// (e) a WELL-FORMED structured claim {alg, scope, inputs_sha256} is ACCEPTED.
expectOK("structured_commitment_claim_accepted") {
    try parse(withRuntimeInput { ri in
        ri["present"] = true
        ri["commitment_claim"] = ["alg": "sha256", "inputs_sha256": String(repeating: "ab", count: 32),
                                  "scope": ["kind": "dir", "entries": 3]]
    }, present: true)
}

print("== envelope self-validation negative suite (validateEnvelopeBodyV3) ==")
// Build a valid composed envelope doc, then mutate individual fields and assert
// the producer's self-validation refuses each (so no envelope is ever signed
// over bytes the reference verifier would reject).
let parsed0 = try! parseRunResultV3(backendData(baseBackend), expectedResultTemplateSha256: tSha,
                                    expectedResultTemplateBytes: tBytes, expectedVmmCode: vmm0, privatePresent: false)
let env0 = try! composeRunResultEnvelope(launchEvidenceSha256: in0["launch_evidence_sha256_L"] as! String,
                                         manifestSha256: in0["manifest_sha256_M"] as! String,
                                         challenge: in0["challenge"] as! String, keyIdB64: in0["key_id_b64"] as! String,
                                         launchCounter: (in0["launch_counter"] as! NSNumber).intValue, parsed: parsed0)
func mutatedEnv(_ mutate: (inout [String: Any]) -> Void) -> [String: Any] { var d = env0.doc; mutate(&d); return d }
expectThrow("envelope_status_finalized_refused") { try validateEnvelopeBodyV3(mutatedEnv { $0["status"] = "finalized" }) }
expectThrow("envelope_nonzero_vmm_code_refused") {
    try validateEnvelopeBodyV3(mutatedEnv { d in var lc = d["lifecycle"] as! [String: Any]; lc["vmm_code"] = 1; d["lifecycle"] = lc })
}
expectThrow("envelope_bad_role_refused") {
    try validateEnvelopeBodyV3(mutatedEnv { d in var rd = d["result_disk"] as! [String: Any]; rd["role"] = "vde"; d["result_disk"] = rd })
}

// --------------------------------------------------------------------------
// SWIFT04 repair4 — the reviewer's EXACT remaining counterexamples. The repair3
// validator checked only the integer TYPE of run_ms / counter, only the character
// LENGTH of key_id_b64, and never rejected a NUL in commitment_claim.alg, so each
// of these composed a body the reference schemas.validate_envelope_body refuses
// (bad_int / noncanonical_b64 / b64_too_large / nul_in_str). These feed the REAL
// validateEnvelopeBodyV3 (and the REAL parseRunResultV3 for run_ms/alg) and assert
// the producer now refuses each — matching the independent reference.
// --------------------------------------------------------------------------
print("== SWIFT04 repair4 bounds/encoding negative suite ==")
func withLifecycle(_ m: (inout [String: Any]) -> Void) -> [String: Any] {
    mutatedEnv { d in var lc = d["lifecycle"] as! [String: Any]; m(&lc); d["lifecycle"] = lc }
}
func withLaunch(_ m: (inout [String: Any]) -> Void) -> [String: Any] {
    mutatedEnv { d in var l = d["launch"] as! [String: Any]; m(&l); d["launch"] = l }
}
func withClaim(_ claim: Any) -> [String: Any] {
    mutatedEnv { d in var ri = d["runtime_input"] as! [String: Any]; ri["commitment_claim"] = claim; d["runtime_input"] = ri }
}
// (a) negative run_ms — in BOTH the self-validator AND the producer parse path.
expectThrow("envelope_negative_run_ms_refused") { try validateEnvelopeBodyV3(withLifecycle { $0["run_ms"] = -1 }) }
expectThrow("producer_negative_run_ms_refused") {
    var b = baseBackend; var lc = b["lifecycle"] as! [String: Any]; lc["run_ms"] = -1; b["lifecycle"] = lc
    try parse(backendData(b))
}
// (b) negative launch.counter.
expectThrow("envelope_negative_counter_refused") { try validateEnvelopeBodyV3(withLaunch { $0["counter"] = -1 }) }
// (c) key_id_b64 non-canonical base64: "QR==" decodes to 0x41 but its canonical
//     form is "QQ==" (the final quantum's unused low bits are nonzero), so the
//     re-encode comparison refuses it (noncanonical_b64) — repair3 accepted it
//     because it only checked the character length.
expectThrow("envelope_noncanonical_key_id_refused") { try validateEnvelopeBodyV3(withLaunch { $0["key_id_b64"] = "QR==" }) }
// (d) key_id_b64 decoding to > 32 bytes (canonical, but too large).
expectThrow("envelope_key_id_decodes_over_32_refused") {
    let big = Data(repeating: 0x41, count: 33).base64EncodedString()   // 33 bytes -> 44 chars, within <=60
    return try validateEnvelopeBodyV3(withLaunch { $0["key_id_b64"] = big })
}
// (e) commitment_claim.alg containing a NUL — self-validator AND producer parse.
let algNul = "sha\u{00}256"
expectThrow("envelope_claim_alg_nul_refused") {
    try validateEnvelopeBodyV3(withClaim(["alg": algNul, "inputs_sha256": String(repeating: "ab", count: 32), "scope": ["k": "v"]]))
}
expectThrow("producer_claim_alg_nul_refused") {
    try parse(withRuntimeInput { ri in ri["present"] = true
        ri["commitment_claim"] = ["alg": algNul, "inputs_sha256": String(repeating: "ab", count: 32), "scope": ["k": "v"]] }, present: true)
}
// (f) a canonical, <=32-byte key_id and a NUL-free bounded alg are still ACCEPTED.
expectOK("envelope_canonical_key_id_accepted") {
    try validateEnvelopeBodyV3(withLaunch { $0["key_id_b64"] = Data(repeating: 0x7, count: 32).base64EncodedString() })
}

// --------------------------------------------------------------------------
// SWIFT04 repair5 — commitment_claim.alg LENGTH must be bounded by CODE POINTS,
// not grapheme clusters. The reference `need_str(claim.alg, 128)` (schemas.py:34)
// bounds Python `len()`, which counts Unicode code points. repair4 used Swift
// `alg.count` (extended grapheme clusters), so the reviewer's exact counterexample
// — an alg of 65 "e\u{0301}" clusters (65 Characters but 130 code points) — passed
// the producer self-check while the reference refused it (str_too_long); the signed
// envelope would then fail reference verification. These cases feed the REAL
// validateEnvelopeBodyV3 (composition/self-validation) and the REAL parseRunResultV3
// (producer parse) the combining-character strings, with BOUNDARY acceptance cases.
// --------------------------------------------------------------------------
print("== SWIFT04 repair5 alg code-point length negative suite ==")
// The reviewer's exact string: 65 × "é" (NFD: e + U+0301) = 65 clusters / 130 scalars.
let algOverlongCombining = String(repeating: "e\u{0301}", count: 65)
// Boundary: 64 × "é" = 64 clusters / 128 scalars — exactly at the code-point bound.
let algBoundaryCombining = String(repeating: "e\u{0301}", count: 64)
func scalars(_ s: String) -> Int { s.unicodeScalars.count }
func clusters(_ s: String) -> Int { s.count }
print("  (combining alg) overlong clusters=\(clusters(algOverlongCombining)) codepoints=\(scalars(algOverlongCombining)); boundary clusters=\(clusters(algBoundaryCombining)) codepoints=\(scalars(algBoundaryCombining))")
func claimWith(_ alg: String) -> [String: Any] {
    return ["alg": alg, "inputs_sha256": String(repeating: "ab", count: 32), "scope": ["k": "v"]]
}
// (g) 130-code-point combining alg — self-validator AND producer parse REFUSE.
expectThrow("envelope_alg_130_codepoints_refused") { try validateEnvelopeBodyV3(withClaim(claimWith(algOverlongCombining))) }
expectThrow("producer_alg_130_codepoints_refused") {
    try parse(withRuntimeInput { ri in ri["present"] = true; ri["commitment_claim"] = claimWith(algOverlongCombining) }, present: true)
}
// (h) 129 ASCII code points also refused (plain boundary, both paths).
let ascii129 = String(repeating: "a", count: 129)
expectThrow("envelope_alg_129_ascii_refused") { try validateEnvelopeBodyV3(withClaim(claimWith(ascii129))) }
expectThrow("producer_alg_129_ascii_refused") {
    try parse(withRuntimeInput { ri in ri["present"] = true; ri["commitment_claim"] = claimWith(ascii129) }, present: true)
}
// (i) BOUNDARY ACCEPTANCE: 128 code points (combining) accepted, self-validator AND
//     producer parse — proves the fix did not over-reject at the bound.
expectOK("envelope_alg_128_codepoints_accepted") { try validateEnvelopeBodyV3(withClaim(claimWith(algBoundaryCombining))) }
expectOK("producer_alg_128_codepoints_accepted") {
    try parse(withRuntimeInput { ri in ri["present"] = true; ri["commitment_claim"] = claimWith(algBoundaryCombining) }, present: true)
}
// (j) BOUNDARY ACCEPTANCE: 128 ASCII code points accepted.
expectOK("envelope_alg_128_ascii_accepted") { try validateEnvelopeBodyV3(withClaim(claimWith(String(repeating: "a", count: 128)))) }

if failures == 0 { print("SWIFT GOLDEN: ALL PASS") } else { die("SWIFT GOLDEN: \(failures) FAILURE(S)") }
