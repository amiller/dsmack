// Offline App Attest evidence verification — the app-side half of
// verifier/attest_core.py. This is what lets the app CONFIRM (never merely
// claim) the assertion it just generated binds the exact control_statement
// bytes and the predicted counter, BEFORE publishing anything.
//
// Verified locally, mirroring the trusted core rule for rule:
//   enrollment: fmt apple-appattest; attStmt.x5c leaf SPKI is an ECDSA P-256
//     key; credentialId == sha256(public point) == base64(keyId.txt); the
//     authData COSE key equals the certified point; appIdHash == sha256(app_id);
//     enrollment counter == 0; the leaf's 1.2.840.113635.100.8.2 nonce
//     extension equals 30 24 a1 22 04 20 || sha256(authData || sha256(clientData)).
//   assertion: ECDSA-P256/SHA-256 (X9.63 point, DER r||s signature) over
//     sha256(authenticatorData || sha256(clientData)) — Apple's documented
//     nonce construction — with the enrollment-certified public key, and the
//     recovered counter equal to the counter committed in the statement.
//
// Deliberately NOT verified here (external verifier authority, stated in
// RESULT/INTEGRATION): the x5c chain to the operator-pinned root, the fraud
// receipt, the macOS ACL and cdhash/category policy pins. The public-root
// pin itself (DER sha256 == 1cb9823b…) IS checked when a root PEM is
// supplied, using only the sprint's public root certificate.
import CryptoKit
import Foundation

/// sha256 (hex) of the DER inside the operator-pinned Apple App Attestation
/// Root PEM — identical to verifier/approval_policy.APPLE_APP_ATTEST_ROOT_SHA256.
public let appleAppAttestRootDERSHA256 = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"

public enum AppAttestError: Error, Equatable, CustomStringConvertible {
    case wrongFormat(String)
    case missingField(String)
    case shortAuthenticator(Int)
    case wrongAppId
    case unsupportedFlags(UInt8)
    case wrongAttestedDataFlag
    case nonzeroInitialCounter(Int)
    case wrongEnvironmentAAGUID
    case invalidCredentialLength(Int)
    case credentialIdMismatch
    case keyIdMismatch
    case wrongKeyCurve
    case coseKeyMismatch
    case missingNonceExtension
    case attestationNonceMismatch
    case invalidBase64
    case invalidAssertion
    case missingSignature
    case invalidSignature          // the crypto itself failed: never publish
    case counterBinding(predicted: Int, recovered: Int)
    case counterOutOfRange(Int)
    case der(String)
    case rootPinMismatch(found: String)

    public var description: String {
        switch self {
        case .wrongFormat(let f): return "app_attest: wrong attestation format \(f)"
        case .missingField(let f): return "app_attest: missing field \(f)"
        case .shortAuthenticator(let n): return "app_attest: authenticator data \(n) bytes is too short"
        case .wrongAppId: return "app_attest: app id hash mismatch"
        case .unsupportedFlags(let f): return "app_attest: unsupported authenticator flags 0x\(String(f, radix: 16))"
        case .wrongAttestedDataFlag: return "app_attest: missing attested-data flag"
        case .nonzeroInitialCounter(let c): return "app_attest: enrollment counter must be 0, got \(c)"
        case .wrongEnvironmentAAGUID: return "app_attest: environment aaguid mismatch"
        case .invalidCredentialLength(let n): return "app_attest: credential length \(n) invalid"
        case .credentialIdMismatch: return "app_attest: credential id does not match key id"
        case .keyIdMismatch: return "app_attest: key id is not sha256(certificate public point)"
        case .wrongKeyCurve: return "app_attest: certified key is not ECDSA P-256"
        case .coseKeyMismatch: return "app_attest: cose key does not equal the certified point"
        case .missingNonceExtension: return "app_attest: leaf has no 1.2.840.113635.100.8.2 nonce extension"
        case .attestationNonceMismatch: return "app_attest: attestation nonce does not bind this client data"
        case .invalidBase64: return "app_attest: key id is not canonical base64"
        case .invalidAssertion: return "app_attest: assertion object malformed"
        case .missingSignature: return "app_attest: assertion has no signature"
        case .invalidSignature: return "app_attest: assertion signature invalid over these bytes"
        case .counterBinding(let p, let r):
            return "app_attest: counter binding failed (statement \(p), assertion \(r))"
        case .counterOutOfRange(let c): return "app_attest: counter \(c) outside 1...2^31"
        case .der(let m): return "app_attest: certificate der: \(m)"
        case .rootPinMismatch(let f):
            return "app_attest: root pem der sha256 \(f) is not the pinned Apple root"
        }
    }
}

// MARK: - Minimal DER (TLV) reader — only what the checks above need

struct DERReader {
    let data: Data
    var pos: Int
    init(_ data: Data, at: Int = 0) { self.data = data; self.pos = at }

    /// Read one TLV; returns (tag, content range, next position).
    mutating func tlv() throws -> (tag: UInt8, content: Range<Int>, end: Int) {
        let base = data.startIndex
        guard pos + 2 <= data.endIndex else { throw AppAttestError.der("truncated header") }
        let tag = data[base + pos]
        var len = Int(data[base + pos + 1])
        var header = 2
        if len & 0x80 != 0 {
            let width = len & 0x7f
            guard width > 0, width <= 4, pos + 2 + width <= data.endIndex else {
                throw AppAttestError.der("bad length header")
            }
            len = 0
            for i in 0..<width { len = (len << 8) | Int(data[base + pos + 2 + i]) }
            header = 2 + width
        }
        guard len >= 0, pos + header + len <= data.endIndex else { throw AppAttestError.der("content overruns") }
        let content = (pos + header)..<(pos + header + len)
        pos += header + len              // advance: successive tlv() calls walk forward
        return (tag, content, pos)
    }
}

public enum DER {
    /// Walk a certificate's tbsCertificate and return the subjectPublicKeyInfo
    /// raw point (0x04 || X || Y) for an ECDSA P-256 key, plus the raw bytes of
    /// the 1.2.840.113635.100.8.2 extension's extnValue contents if present.
    /// Anything unexpected is a refusal, never a best-effort parse.
    static func parseLeafCertificate(_ input: Data) throws -> (publicPoint: Data, nonceExtension: Data?) {
        // All index math below is 0-based; normalize sliced Data (a slice
        // preserves its parent indices, which would skew every range).
        let der = input.startIndex == 0 ? input : Data(input)
        var outer = DERReader(der)
        let cert = try outer.tlv()
        guard cert.tag == 0x30, cert.end == der.count else { throw AppAttestError.der("not a certificate SEQUENCE") }
        var tbs = DERReader(der, at: cert.content.lowerBound)
        let tbsTLV = try tbs.tlv()
        guard tbsTLV.tag == 0x30 else { throw AppAttestError.der("no tbsCertificate") }
        var cursor = tbsTLV.content.lowerBound
        // version [0] EXPLICIT (optional), serialNumber INTEGER, signature
        // AlgorithmIdentifier SEQUENCE, issuer Name, validity, subject Name,
        // subjectPublicKeyInfo SEQUENCE, ..., extensions [3] EXPLICIT.
        var first = DERReader(der, at: cursor)
        var item = try first.tlv()
        if item.tag == 0xa0 {           // version
            cursor = item.end
            first = DERReader(der, at: cursor)
            item = try first.tlv()
        }
        guard item.tag == 0x02 else { throw AppAttestError.der("expected serialNumber") }
        cursor = item.end
        var r = DERReader(der, at: cursor)
        // signature AlgorithmIdentifier
        var t = try r.tlv(); guard t.tag == 0x30 else { throw AppAttestError.der("expected signature algorithm") }
        // issuer, validity, subject
        for _ in 0..<3 {
            r = DERReader(der, at: t.end)
            t = try r.tlv()
            guard t.tag == 0x30 else { throw AppAttestError.der("expected name/validity SEQUENCE") }
        }
        // subjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }
        r = DERReader(der, at: t.end)
        var spki = try r.tlv()
        guard spki.tag == 0x30 else { throw AppAttestError.der("expected subjectPublicKeyInfo") }
        var spkiReader = DERReader(der, at: spki.content.lowerBound)
        let alg = try spkiReader.tlv()
        guard alg.tag == 0x30, alg.content.count >= 10 else { throw AppAttestError.der("bad spki algorithm") }
        // id-ecPublicKey 1.2.840.10045.2.1 (06 07 2a 86 48 ce 3d 02 01)
        // prime256v1    1.2.840.10045.3.1.1 (06 08 2a 86 48 ce 3d 03 01 07)
        let base = der.startIndex
        let algBytes = der.subdata(in: alg.content)
        guard algBytes == Data([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
        else { throw AppAttestError.wrongKeyCurve }
        let bitString = try spkiReader.tlv()
        guard bitString.tag == 0x03, bitString.content.count == 66,
              der[base + bitString.content.lowerBound] == 0x00       // no unused bits
        else { throw AppAttestError.wrongKeyCurve }
        let point = der.subdata(in: (bitString.content.lowerBound + 1)..<bitString.content.upperBound)
        guard point.count == 65, point.first == 0x04 else { throw AppAttestError.wrongKeyCurve }

        // extensions [3] EXPLICIT SEQUENCE OF Extension — the LAST
        // tbsCertificate child. The walk is bounded by the tbs end so it
        // cannot cross into the cert-level signatureAlgorithm/signature.
        var nonceExt: Data? = nil
        r = DERReader(der, at: spki.end)
        while r.pos < tbsTLV.content.upperBound {
            spki = try r.tlv()
            r = DERReader(der, at: spki.end)
        }
        if spki.tag == 0xa3 {                       // extensions wrapper
            var seq = DERReader(der, at: spki.content.lowerBound)
            let extSeq = try seq.tlv()
            guard extSeq.tag == 0x30 else { throw AppAttestError.der("extensions not a SEQUENCE") }
            var er = DERReader(der, at: extSeq.content.lowerBound)
            while er.pos < extSeq.content.upperBound {
                let ext = try er.tlv()
                guard ext.tag == 0x30 else { throw AppAttestError.der("extension not a SEQUENCE") }
                var e = DERReader(der, at: ext.content.lowerBound)
                let oid = try e.tlv()
                guard oid.tag == 0x06 else { throw AppAttestError.der("extension has no OID") }
                let oidBytes = der.subdata(in: oid.content)
                // 1.2.840.113635.100.8.2 -> 06 0a 2a 86 48 86 f7 63 64 08 02
                let target: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02]
                if oidBytes.count == 9, Array(oidBytes) == target {
                    // Optional critical BOOLEAN; when absent, the TLV just read
                    // past the OID IS the extnValue.
                    let maybeCritical = try e.tlv()
                    let value = maybeCritical.tag == 0x01 ? try e.tlv() : maybeCritical
                    guard value.tag == 0x04 else { throw AppAttestError.der("extnValue not an OCTET STRING") }
                    nonceExt = der.subdata(in: value.content)
                    break
                }
            }
        }
        return (point, nonceExt)
    }

    /// sha256 of the DER carried by a PEM body (the operator pin identity).
    public static func pemDERSha256(_ pem: Data) throws -> String {
        guard let text = String(data: pem, encoding: .utf8) else { throw AppAttestError.der("root pem is not utf-8") }
        let lines = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        let body = lines.filter { !$0.isEmpty && !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body, options: .ignoreUnknownCharacters),
              !der.isEmpty
        else { throw AppAttestError.der("root pem body is not base64") }
        return sha256(der).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Authenticator data (shared by enrollment + assertion)

public struct AttestPolicy {
    public let appId: String
    /// 'appattestdevelop' (development) or 'appattest' + 7 zero bytes (production).
    public let aaguid: Data
    public init(appId: String, environment: String = "development",
                developmentAAGUID: String = "appattestdevelop") {
        self.appId = appId
        if environment == "production" {
            var g = Data("appattest".utf8); g.append(Data(count: 7)); self.aaguid = g
        } else {
            self.aaguid = Data(developmentAAGUID.utf8)
        }
    }
}

struct AuthenticatorParse {
    let counter: Int
    let credentialId: Data?
    let coseKey: AttestCBORValue?
    let extensions: [AttestCBORMapKey: AttestCBORValue]
}

enum Authenticator {
    /// Mirrors attest_core.authenticator (same offsets, same flag rules).
    /// `attestation` selects the attested-credential-data layout.
    static func parse(_ data: Data, policy: AttestPolicy, attestation: Bool) throws -> AuthenticatorParse {
        guard data.count >= 37 else { throw AppAttestError.shortAuthenticator(data.count) }
        guard data.prefix(32) == Data(sha256(Data(policy.appId.utf8))) else {
            throw AppAttestError.wrongAppId
        }
        let flags = data[data.startIndex + 32]
        let counter = Int(data[data.startIndex + 33]) << 24 | Int(data[data.startIndex + 34]) << 16
                    | Int(data[data.startIndex + 35]) << 8 | Int(data[data.startIndex + 36])
        guard flags & 0x3e == 0 else { throw AppAttestError.unsupportedFlags(flags) }
        var offset = 37
        var credential: Data? = nil
        var cose: AttestCBORValue? = nil
        if attestation {
            guard flags & 0x40 != 0 else { throw AppAttestError.wrongAttestedDataFlag }
            guard counter == 0 else { throw AppAttestError.nonzeroInitialCounter(counter) }
            guard data.count >= 55 else { throw AppAttestError.shortAuthenticator(data.count) }
            let aaguid = data.subdata(in: (data.startIndex + 37)..<(data.startIndex + 53))
            guard aaguid == policy.aaguid else { throw AppAttestError.wrongEnvironmentAAGUID }
            let size = Int(data[data.startIndex + 53]) << 8 | Int(data[data.startIndex + 54])
            guard size == 32, data.count >= 55 + size else { throw AppAttestError.invalidCredentialLength(size) }
            credential = data.subdata(in: (data.startIndex + 55)..<(data.startIndex + 87))
            // The COSE key map ends where the reader stops; extensions (if the
            // ED flag is set) begin exactly there. subdata re-bases indices to
            // zero, so reader.pos counts from data.startIndex + 87.
            let coseRegion = data.subdata(in: (data.startIndex + 87)..<data.endIndex)
            var reader = try AttestCBORReader(coseRegion)
            cose = try reader.read()
            offset = 87 + reader.pos
        }
        var extensions: [AttestCBORMapKey: AttestCBORValue] = [:]
        if flags & 0x80 != 0 {
            let tail = data.subdata(in: (data.startIndex + offset)..<data.endIndex)
            let value = try AttestCBOR.decode(tail)
            guard case .map(let m) = value else { throw AppAttestError.wrongFormat("extensions not a map") }
            extensions = m
        } else if data.count != offset {
            throw AppAttestError.wrongFormat("unflagged extension or trailing data")
        }
        return AuthenticatorParse(counter: counter, credentialId: credential, coseKey: cose,
                                  extensions: extensions)
    }
}

// MARK: - Enrollment (offline structural + nonce binding; chain = verifier)

public struct VerifiedEnrollment {
    /// X9.63 uncompressed point (0x04 || X || Y) of the certified key.
    public let publicPoint: Data
    public let keyId: String
    public let appId: String
    public let counterAtEnrollment: Int
}

public enum AppAttestVerify {

    /// Strict-canonical base64 decode (the keyId wire form), attest_core-style.
    static func unbase64(_ text: String) throws -> Data {
        guard let decoded = Data(base64Encoded: text) else { throw AppAttestError.invalidBase64 }
        guard decoded.base64EncodedString() == text else { throw AppAttestError.invalidBase64 }
        return decoded
    }

    /// Verify the retained enrollment evidence against THIS app identity and
    /// the enrollment client data. Returns the certified public key that
    /// assertion verification must use.
    public static func verifyEnrollment(enrollmentCbor: Data, keyId: String, appId: String,
                                        enrollClientData: Data,
                                        environment: String = "development") throws -> VerifiedEnrollment {
        let policy = AttestPolicy(appId: appId, environment: environment)
        let value = try AttestCBOR.decode(enrollmentCbor)
        guard case .map(let obj) = value else { throw AppAttestError.wrongFormat("not an object") }
        guard case .text(let fmt)? = obj[.str("fmt")], fmt == "apple-appattest" else {
            throw AppAttestError.wrongFormat("fmt")
        }
        guard case .map(let attStmt)? = obj[.str("attStmt")],
              case .bytes(let receipt)? = attStmt[.str("receipt")], !receipt.isEmpty
        else { throw AppAttestError.missingField("attStmt.receipt") }
        guard case .array(let x5c)? = attStmt[.str("x5c")], x5c.count == 2,
              case .bytes(let leaf) = x5c[0], case .bytes(let intermediate) = x5c[1],
              !leaf.isEmpty, !intermediate.isEmpty
        else { throw AppAttestError.missingField("attStmt.x5c") }
        guard case .bytes(let authData)? = obj[.str("authData")], !authData.isEmpty else {
            throw AppAttestError.missingField("authData")
        }

        let parsed = try Authenticator.parse(authData, policy: policy, attestation: true)
        let (point, nonceExt) = try DER.parseLeafCertificate(leaf)
        let kid = try unbase64(keyId)
        guard kid.count == 32, parsed.credentialId == kid else { throw AppAttestError.credentialIdMismatch }
        guard Data(sha256(point)) == kid else { throw AppAttestError.keyIdMismatch }
        // COSE key must be exactly the certified point: {1:2, 3:-7, -1:1, -2:X, -3:Y}
        guard case .map(let cose)? = parsed.coseKey,
              cose[.int(1)] == .unsigned(2), cose[.int(3)] == .negative(-7),
              cose[.int(-1)] == .unsigned(1),
              case .bytes(let x)? = cose[.int(-2)], case .bytes(let y)? = cose[.int(-3)],
              x == point.subdata(in: 1..<33), y == point.subdata(in: 33..<65)
        else { throw AppAttestError.coseKeyMismatch }
        guard let nonce = nonceExt else { throw AppAttestError.missingNonceExtension }
        var expected = Data([0x30, 0x24, 0xa1, 0x22, 0x04, 0x20])
        expected.append(Data(sha256(authData + Data(sha256(enrollClientData)))))
        guard nonce == expected else { throw AppAttestError.attestationNonceMismatch }
        return VerifiedEnrollment(publicPoint: point, keyId: keyId, appId: appId,
                                  counterAtEnrollment: parsed.counter)
    }

    /// Verify an assertion over EXACT client-data bytes with a certified key,
    /// requiring the recovered counter to equal the counter the statement
    /// committed. This is the app-side half of
    /// attest_core.verify_assertion + receipt_profile's counter_binding.
    public static func verifyAssertion(assertionCbor: Data, clientData: Data,
                                       publicPoint: Data, appId: String,
                                       expectedCounter: Int) throws -> Int {
        let policy = AttestPolicy(appId: appId)
        let value = try AttestCBOR.decode(assertionCbor)
        guard case .map(let obj) = value else { throw AppAttestError.invalidAssertion }
        guard case .bytes(let authData)? = obj[.str("authenticatorData")] else {
            throw AppAttestError.invalidAssertion
        }
        guard case .bytes(let signature)? = obj[.str("signature")], !signature.isEmpty else {
            throw AppAttestError.missingSignature
        }
        let parsed = try Authenticator.parse(authData, policy: policy, attestation: false)
        guard parsed.counter >= 1, parsed.counter <= 1 << 31 else {
            throw AppAttestError.counterOutOfRange(parsed.counter)
        }
        // Byte-exact with attest_core.verify_assertion: it passes
        // sha256(authenticatorData || sha256(clientData)) as the DATA to
        // ECDSA(SHA256()), which pre-hashes that data — CryptoKit's
        // isValidSignature(_:for:) also pre-hashes its data once, so the
        // argument here is exactly attest_core's DATA (empirically confirmed
        // against both rig families' verifier-admitted signatures).
        var nonce = authData
        nonce.append(Data(sha256(clientData)))
        let message = Data(sha256(nonce))
        // This SDK's CryptoKit P256.Signing.PublicKey.rawRepresentation is the
        // RAW 64-byte X||Y — NOT the x9.63 point. publicPoint IS x9.63
        // (0x04 || X || Y, the certificate COSE form), so strip the prefix.
        guard publicPoint.count == 65, publicPoint.first == 0x04,
              let key = try? P256.Signing.PublicKey(rawRepresentation: Data(publicPoint.dropFirst())),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              key.isValidSignature(sig, for: message)
        else { throw AppAttestError.invalidSignature }
        guard parsed.counter == expectedCounter else {
            throw AppAttestError.counterBinding(predicted: expectedCounter, recovered: parsed.counter)
        }
        return parsed.counter
    }

    /// Check an operator-supplied root PEM against the pinned Apple App
    /// Attestation Root DER hash (public data; no secrets involved).
    public static func verifyRootPin(rootPem: Data) throws {
        let found = try DER.pemDERSha256(rootPem)
        guard found == appleAppAttestRootDERSHA256 else {
            throw AppAttestError.rootPinMismatch(found: found)
        }
    }
}

private func sha256(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }
