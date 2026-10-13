import Foundation
import CryptoKit
import Security

// Port of verifier/core.py verify_attestation (attestation path only), same reject reasons. Copied unchanged from
// app/macos/account_authority/AppAttest.swift at work/native-core-ledger-20261012 aa80468, less AppAttestAdmission.
// Root, App ID and profile are compiled in so the admitted CDHash covers them; no files or subprocesses.
struct AppAttestReject: Error, Equatable { let reason: String }
func require(_ ok: Bool, _ reason: String) throws { if !ok { throw AppAttestReject(reason: reason) } }
func sha(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }

enum AppAttestProfile {
    static let appID = "DC9JH5DRMY.dev.dsmack.provider"
    static let aaguid = Data("appattest".utf8) + Data(count: 7)  // production environment
    static let categories = [3]
    static let rootSHA256 = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"
    static let rootDER = Data(base64Encoded: """
    MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\
    QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\
    biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\
    NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\
    MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\
    53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD
    """)!
    static let macACL = Data([0x30, 0x46, 0xa3, 0x44, 0x04, 0x42]) + Data(base64Encoded:
        "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB")!
}

indirect enum CBOR: Hashable {
    case int(Int), bytes(Data), text(String), array([CBOR]), map([CBOR: CBOR]), bool(Bool), null
    subscript(_ key: String) -> CBOR? { if case .map(let m) = self { return m[.text(key)] }; return nil }
    var data: Data? { if case .bytes(let d) = self { return d }; return nil }
}

struct CBORReader {
    let data: [UInt8]
    var pos = 0
    init(_ d: Data) throws { try require(d.count <= 100_000, "invalid_cbor_size"); data = [UInt8](d) }
    mutating func take(_ n: Int) throws -> [UInt8] {
        try require(n >= 0 && n <= data.count - pos, "truncated_cbor")
        defer { pos += n }
        return Array(data[pos..<pos + n])
    }
    mutating func read(_ depth: Int = 0) throws -> CBOR {
        try require(depth < 12, "cbor_depth")
        let head = try take(1)[0], major = head >> 5, info = Int(head & 31)
        if major == 7 && (20...22).contains(info) { return info == 22 ? .null : .bool(info == 21) }
        try require(major <= 5 && info <= 27, "unsupported_cbor_type")
        var n = UInt64(info)
        if info >= 24 { n = try take(1 << (info - 24)).reduce(UInt64(0)) { $0 << 8 | UInt64($1) } }
        if major <= 1 {
            try require(n <= UInt64(Int.max), "cbor_integer")  // core.py has unbounded ints; out of App Attest profile
            return .int(major == 0 ? Int(n) : -1 - Int(n))
        }
        try require(n <= 100_000, "cbor_length")
        if major == 2 { return .bytes(Data(try take(Int(n)))) }
        if major == 3 {
            guard let s = String(validating: try take(Int(n)), as: UTF8.self) else { throw AppAttestReject(reason: "invalid_cbor_utf8") }
            return .text(s)
        }
        try require(n <= 100, "cbor_container_size")
        if major == 4 {
            var items: [CBOR] = []
            for _ in 0..<n { items.append(try read(depth + 1)) }
            return .array(items)
        }
        var result: [CBOR: CBOR] = [:]
        for _ in 0..<n {
            let key = try read(depth + 1)
            switch key { case .int, .text, .bytes: break; default: throw AppAttestReject(reason: "invalid_cbor_map_key") }
            try require(result[key] == nil, "duplicate_cbor_key")
            result[key] = try read(depth + 1)
        }
        return .map(result)
    }
}

func cborDecode(_ d: Data) throws -> CBOR {
    var reader = try CBORReader(d)
    let value = try reader.read()
    try require(reader.pos == reader.data.count, "trailing_cbor")
    return value
}

// Minimal DER walk for certificate extensions; malformed input maps to core.py's chain failure.
func derItems(_ a: ArraySlice<UInt8>) throws -> [(tag: UInt8, body: ArraySlice<UInt8>)] {
    var items: [(tag: UInt8, body: ArraySlice<UInt8>)] = [], i = a.startIndex
    while i < a.endIndex {
        try require(a.endIndex - i >= 2, "invalid_certificate_chain")
        let tag = a[i]; var len = Int(a[i + 1]); i += 2
        if len & 0x80 != 0 {
            let k = len & 0x7f
            try require((1...3).contains(k) && a.endIndex - i >= k, "invalid_certificate_chain")
            len = a[i..<i + k].reduce(0) { $0 << 8 | Int($1) }; i += k
        }
        try require(a.endIndex - i >= len, "invalid_certificate_chain")
        items.append((tag: tag, body: a[i..<i + len])); i += len
    }
    return items
}

func certificateExtensions(_ der: Data) throws -> [Data: Data] {
    let cert = try derItems(ArraySlice(der))
    try require(cert.count == 1 && cert[0].tag == 0x30, "invalid_certificate_chain")
    let tbs = try derItems(cert[0].body)
    try require(tbs.first?.tag == 0x30, "invalid_certificate_chain")
    guard let wrapper = try derItems(tbs[0].body).first(where: { $0.tag == 0xa3 }) else { return [:] }
    let list = try derItems(wrapper.body)
    try require(list.count == 1 && list[0].tag == 0x30, "invalid_certificate_chain")
    var out: [Data: Data] = [:]
    for ext in try derItems(list[0].body) {
        let parts = try derItems(ext.body)
        try require(ext.tag == 0x30 && parts.first?.tag == 0x06 && parts.last?.tag == 0x04, "invalid_certificate_chain")
        let oid = Data(parts[0].body)
        try require(out[oid] == nil, "invalid_certificate_chain")
        out[oid] = Data(parts.last!.body)
    }
    return out
}

let oidBasicConstraints = Data([0x55, 0x1d, 0x13])
let oidNonce = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02])
let oidMacACL = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x06])

func isCA(_ extensions: [Data: Data]) throws -> Bool {
    guard let value = extensions[oidBasicConstraints] else { throw AppAttestReject(reason: "invalid_certificate_chain") }
    let seq = try derItems(ArraySlice(value))
    try require(seq.count == 1 && seq[0].tag == 0x30, "invalid_certificate_chain")
    guard let first = try derItems(seq[0].body).first, first.tag == 0x01 else { return false }
    return first.body.first == 0xff
}

func verifyChain(_ chain: CBOR?, at: Date?, anchor: Data) throws -> (leaf: SecCertificate, extensions: [Data: Data]) {
    guard case .array(let items)? = chain, items.count == 2, let leafDER = items[0].data, let interDER = items[1].data else {
        throw AppAttestReject(reason: "expected_leaf_and_intermediate")
    }
    guard let leaf = SecCertificateCreateWithData(nil, leafDER as CFData),
          let inter = SecCertificateCreateWithData(nil, interDER as CFData),
          let root = SecCertificateCreateWithData(nil, anchor as CFData) else {
        throw AppAttestReject(reason: "invalid_certificate_chain")
    }
    let leafExtensions = try certificateExtensions(leafDER)
    let leafIsCA = try isCA(leafExtensions)
    try require(!leafIsCA, "leaf_is_ca")
    let interIsCA = try isCA(try certificateExtensions(interDER))
    try require(interIsCA, "intermediate_not_ca")
    var trust: SecTrust?
    try require(SecTrustCreateWithCertificates([leaf, inter] as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
                "invalid_certificate_chain")
    try require(SecTrustSetAnchorCertificates(trust!, [root] as CFArray) == errSecSuccess
                && SecTrustSetAnchorCertificatesOnly(trust!, true) == errSecSuccess
                && SecTrustSetNetworkFetchAllowed(trust!, false) == errSecSuccess, "invalid_certificate_chain")
    if let at { try require(SecTrustSetVerifyDate(trust!, at as CFDate) == errSecSuccess, "invalid_certificate_chain") }
    try require(SecTrustEvaluateWithError(trust!, nil), "certificate_chain_failed")
    return (leaf, leafExtensions)
}

// core.py authenticator(); cdhashes empty means report without policy check. Attested credential data is parsed only
// for an attestation (Apple's legacy assertions keep AT=1 without it). appID is the rpId: ours by default; an
// open-admission caller passes the App ID the attested code's own entitlements name (CodeMeasurement.appIdentifier).
func authenticator(_ auth: Data?, cdhashes: [Data], attestation: Bool, appID: String = AppAttestProfile.appID) throws -> (counter: UInt32, credential: Data?, cose: CBOR?, cdhash: Data?) {
    guard let auth else { throw AppAttestReject(reason: "short_authenticator") }
    let d = [UInt8](auth)
    try require(d.count >= 37, "short_authenticator")
    try require(Data(d[0..<32]) == sha(Data(appID.utf8)), "wrong_app_id")
    let flags = d[32], counter = d[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    try require(flags & 0x3e == 0, "unsupported_authenticator_flags")
    var offset = 37, cose: CBOR?
    if attestation {
        try require(flags & 0x40 != 0, "wrong_attested_data_flag")
        try require(d.count >= 55, "short_attested_data")
        try require(counter == 0, "nonzero_initial_counter")
        try require(Data(d[37..<53]) == AppAttestProfile.aaguid, "wrong_environment_aaguid")
        let size = Int(d[53]) << 8 | Int(d[54])
        try require(size == 32 && d.count >= 55 + size, "invalid_credential_length")
        var reader = try CBORReader(Data(d[87...]))
        cose = try reader.read()
        offset = 87 + reader.pos
    }
    var extensions: [CBOR: CBOR] = [:]
    if flags & 0x80 != 0 {
        guard case .map(let m) = try cborDecode(Data(d[offset...])) else { throw AppAttestReject(reason: "invalid_extensions") }
        extensions = m
    } else {
        try require(d.count == offset, "unflagged_extension_or_trailing_data")
    }
    var category = extensions[.text("apple_validation_category_01")]
    let version = extensions[.text("apple_bundle_version_01")]
    let cdhash = extensions[.text("apple_cd_hash_hash_01")]?.data
    let sha256Type = extensions[.text("apple_cd_hash_type_01")] == .bytes(Data([2]))
    if !cdhashes.isEmpty {
        try require(sha256Type, "unsupported_cdhash_type")
        try require(cdhash?.count == 32, "missing_or_invalid_cdhash")
        try require(cdhashes.contains(cdhash!), "cdhash_policy_failed")
    }
    if case .bytes(let b)? = category {
        try require(b.count == 4, "invalid_category_encoding")
        category = .int(b.reversed().reduce(0) { $0 << 8 | Int($1) })
    }
    var categoryValue: Int?
    switch category { case nil: categoryValue = nil; case .int(let v)?: categoryValue = v
    default: throw AppAttestReject(reason: "invalid_category") }
    switch version { case nil, .some(.text): break; default: throw AppAttestReject(reason: "invalid_bundle_version") }
    try require(categoryValue.map { AppAttestProfile.categories.contains($0) } ?? false, "category_policy_failed")
    // Reported only in the observed macOS 27 profile (SHA-256 selector, 32 bytes), as core.py enforces it.
    return (counter, attestation ? Data(d[55..<87]) : nil, cose, sha256Type && cdhash?.count == 32 ? cdhash : nil)
}

func unb64(_ text: String) throws -> Data {
    try require(text.utf8.count <= 200_000, "invalid_base64")
    guard let d = Data(base64Encoded: text) else { throw AppAttestReject(reason: "invalid_base64") }
    try require(d.base64EncodedString() == text, "noncanonical_base64")
    return d
}

// Returns the Apple-attested current CDHash and attested public key of the process that produced `raw`.
// `anchor` is the Apple root in production (AppAttestAdmission); only the self-test passes its synthetic root.
func verifyAttestation(_ raw: Data, keyID: String, challenge: Data, cdhashes: [Data], at: Date?, anchor: Data,
                       appID: String = AppAttestProfile.appID) throws -> (cdhash: Data?, publicKey: Data) {
    let obj = try cborDecode(raw)
    try require(obj["fmt"] == .text("apple-appattest"), "wrong_attestation_format")
    guard let statement = obj["attStmt"], case .map = statement else { throw AppAttestReject(reason: "missing_attestation_statement") }
    try require((statement["receipt"]?.data?.count ?? 0) > 0, "missing_receipt")
    let (leaf, extensions) = try verifyChain(statement["x5c"], at: at, anchor: anchor)
    let auth = obj["authData"]?.data
    let (_, credential, cose, cdhash) = try authenticator(auth, cdhashes: cdhashes, attestation: true, appID: appID)
    let kid = try unb64(keyID)
    try require(kid.count == 32 && credential! == kid, "credential_id_mismatch")
    guard let key = SecCertificateCopyKey(leaf),
          let attrs = SecKeyCopyAttributes(key) as? [String: Any],
          attrs[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
          attrs[kSecAttrKeySizeInBits as String] as? Int == 256,
          let point = SecKeyCopyExternalRepresentation(key, nil) as Data?, point.count == 65 else {
        throw AppAttestReject(reason: "wrong_key_curve")
    }
    try require(sha(point) == kid, "key_id_mismatch")
    try require(cose! == .map([.int(1): .int(2), .int(3): .int(-7), .int(-1): .int(1),
                              .int(-2): .bytes(point[1..<33]), .int(-3): .bytes(point[33...])]), "cose_key_mismatch")
    guard let nonce = extensions[oidNonce] else { throw AppAttestReject(reason: "missing_nonce_extension") }
    try require(nonce == Data([0x30, 0x24, 0xa1, 0x22, 0x04, 0x20]) + sha(auth! + sha(challenge)), "attestation_nonce_mismatch")
    guard let acl = extensions[oidMacACL] else { throw AppAttestReject(reason: "missing_macos_acl") }
    try require(acl == AppAttestProfile.macACL, "macos_acl_policy_failed")
    return (cdhash, point)
}

// core.py verify_assertion: an assertion by the attested key `publicKey` (X9.63) over SHA256(clientData), its counter
// above `previousCounter`. Returns the counter and the asserted CDHash.
func verifyAssertion(_ raw: Data, clientData: Data, publicKey: Data, previousCounter: UInt32, cdhashes: [Data],
                     appID: String = AppAttestProfile.appID) throws -> (counter: UInt32, cdhash: Data?) {
    let obj = try cborDecode(raw)
    guard case .map = obj else { throw AppAttestReject(reason: "invalid_assertion") }
    guard let signature = obj["signature"]?.data else { throw AppAttestReject(reason: "missing_signature") }
    let auth = obj["authenticatorData"]?.data, a = try authenticator(auth, cdhashes: cdhashes, attestation: false, appID: appID)
    try require(a.counter > previousCounter, "counter_replay")
    guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
          let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature),
          key.isValidSignature(sig, for: sha(auth! + sha(clientData))) else { throw AppAttestReject(reason: "invalid_assertion_signature") }
    return (a.counter, a.cdhash)
}
