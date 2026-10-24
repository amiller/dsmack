// Offline AppAttestVerify coverage over rig-generated enrollment/assertion bytes
// (Fixtures/appattest-variants.json): assertion verification, key representation,
// counter and client-data binding, enrollment nonce binding and root-pin mechanics.
import CryptoKit
import XCTest

@testable import marAttest

private struct VariantsFixture {
    let json: [String: Any]
    init() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent("appattest-variants.json")
        self.json = try JSONSerialization.jsonObject(with: try Data(contentsOf: url)) as! [String: Any]
    }
    func str(_ key: String) -> String { json[key] as! String }
    func data(_ key: String) -> Data {
        let s = str(key)
        var d = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            d.append(UInt8(s[i..<s.index(i, offsetBy: 2)], radix: 16)!)
            i = s.index(i, offsetBy: 2)
        }
        return d
    }
}

final class AppAttestVerifyTests: XCTestCase {

    // The enrollment verifies and the counter-1 assertion over the statement
    // bytes verifies with the certified point.
    func testAdmittedEnrollmentAndAssertionVerifyLocally() throws {
        let v = try VariantsFixture()
        let appId = v.str("app_id")
        let enroll = try AppAttestVerify.verifyEnrollment(
            enrollmentCbor: v.data("enrollment_hex"),
            keyId: v.str("key_id"),
            appId: appId,
            enrollClientData: v.data("enroll_client_data_hex"))
        XCTAssertEqual(Data(SHA256.hash(data: enroll.publicPoint)),
                       Data(base64Encoded: v.str("key_id"))!,
                       "keyId must be sha256(certificate public point)")
        XCTAssertEqual(enroll.counterAtEnrollment, 0, "enrollment counter is 0")

        let statement = v.data("statement_hex")
        let counter = try AppAttestVerify.verifyAssertion(
            assertionCbor: v.data("assertion_positive_hex"),
            clientData: statement,
            publicPoint: v.data("public_point_hex"),
            appId: appId,
            expectedCounter: 1)
        XCTAssertEqual(counter, 1)
    }

    // Key representation (Xcode-27 CryptoKit): the certified point is the
    // 65-byte x9.63 form; this SDK's rawRepresentation is the RAW 64-byte
    // X||Y — verifyAssertion must accept the point form (prefix stripped
    // internally), and the reconstructed key's raw form must equal the
    // stripped point.
    func testKeyRepresentationPointVersusRaw() throws {
        let v = try VariantsFixture()
        let point = v.data("public_point_hex")
        XCTAssertEqual(point.count, 65)
        XCTAssertEqual(point.first, 0x04)
        let key = try P256.Signing.PublicKey(x963Representation: point)
        XCTAssertEqual(key.rawRepresentation, point.dropFirst())
        XCTAssertEqual(Data([0x04]) + key.rawRepresentation, point)
        // and the public key derived from the fixture scalar matches BOTH forms
        let scalar = v.data("leaf_private_scalar_hex")
        XCTAssertEqual(scalar.count, 32)
        let fromScalar = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        XCTAssertEqual(fromScalar.publicKey.x963Representation, point)

    }

    // THE CIRCULARITY RESOLUTION, refusal half: an assertion whose recovered
    // counter differs from the statement's committed prediction is refused —
    // never accepted as new state (the python verifier refuses the same bytes
    // with hvf_control:counter_binding — generation anchor 3).
    func testCounterMismatchRefused() throws {
        let v = try VariantsFixture()
        XCTAssertThrowsError(try AppAttestVerify.verifyAssertion(
            assertionCbor: v.data("assertion_counter2_hex"),
            clientData: v.data("statement_hex"),
            publicPoint: v.data("public_point_hex"),
            appId: v.str("app_id"),
            expectedCounter: 1)) { error in
            guard case AppAttestError.counterBinding(let predicted, let recovered) = error else {
                return XCTFail("expected counterBinding, got \(error)")
            }
            XCTAssertEqual(predicted, 1)
            XCTAssertEqual(recovered, 2)
        }
    }

    // Challenge binding: an assertion produced over DIFFERENT client-data
    // bytes must not verify over the committed statement bytes.
    func testAssertionOverDifferentBytesRefused() throws {
        let v = try VariantsFixture()
        XCTAssertThrowsError(try AppAttestVerify.verifyAssertion(
            assertionCbor: v.data("assertion_other_client_hex"),
            clientData: v.data("statement_hex"),
            publicPoint: v.data("public_point_hex"),
            appId: v.str("app_id"),
            expectedCounter: 1)) { error in
            guard case AppAttestError.invalidSignature = error else {
                return XCTFail("expected invalidSignature, got \(error)")
            }
        }
    }

    // Wrong key: an assertion by a DIFFERENT key over the same bytes + app id
    // is refused against the fixture's certified point.
    func testWrongKeyRefused() throws {
        let v = try VariantsFixture()
        XCTAssertThrowsError(try AppAttestVerify.verifyAssertion(
            assertionCbor: v.data("assertion_foreign_key_hex"),
            clientData: v.data("statement_hex"),
            publicPoint: v.data("public_point_hex"),
            appId: v.str("app_id"),
            expectedCounter: 1)) { error in
            guard case AppAttestError.invalidSignature = error else {
                return XCTFail("expected invalidSignature, got \(error)")
            }
        }
    }

    // Enrollment nonce binding: an attestation whose nonce extension is not
    // sha256(authData ‖ sha256(enroll client data)) is refused.
    func testEnrollmentNonceNotBoundToClientDataRefused() throws {
        let v = try VariantsFixture()
        XCTAssertThrowsError(try AppAttestVerify.verifyEnrollment(
            enrollmentCbor: v.data("enrollment_wrong_nonce_hex"),
            keyId: v.str("key_id"),
            appId: v.str("app_id"),
            enrollClientData: v.data("enroll_client_data_hex"))) { error in
            guard case AppAttestError.attestationNonceMismatch = error else {
                return XCTFail("expected attestationNonceMismatch, got \(error)")
            }
        }
    }

    // Root-pin mechanics: pemDERSha256 is plain sha256 of the DER body.
    func testPEMDERSha256() throws {
        let der = Data((0..<48).map { UInt8($0 & 0xff) })
        let b64 = der.base64EncodedString()
        var pem = "-----BEGIN CERTIFICATE-----\n"
        var i = b64.startIndex
        while i < b64.endIndex {
            let lo = i
            let hi = b64.index(i, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            pem += String(b64[lo..<hi]) + "\n"
            i = hi
        }
        pem += "-----END CERTIFICATE-----\n"
        XCTAssertEqual(try DER.pemDERSha256(Data(pem.utf8)), SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined())
    }

    func testRootPinMismatchRefused() throws {
        let der = Data(repeating: 0x41, count: 64)
        let pem = "-----BEGIN CERTIFICATE-----\n\(der.base64EncodedString())\n-----END CERTIFICATE-----\n"
        XCTAssertThrowsError(try AppAttestVerify.verifyRootPin(rootPem: Data(pem.utf8))) { error in
            guard case AppAttestError.rootPinMismatch = error else {
                return XCTFail("expected rootPinMismatch, got \(error)")
            }
        }
    }
}
