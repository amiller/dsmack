// Direct AppAttestVerify unit coverage — assertion verification, key
// representation, challenge (client-data) binding, enrollment nonce binding,
// and root-pin mechanics — imported from the overnight glm-attestation-path
// lane (its AppAttestVerifyTests ran green there, 8 tests) and adapted to THIS
// candidate's committed fixture layout.
//
// The variants fixture (Fixtures/appattest-variants.json) is generated from
// the ACTUAL verifier rig (evidence/gen-appattest-variants.py:
// deterministic_rig == the committed enrollment's leaf scalar 0x2001/P-256)
// with three python-side anchors asserted at generation: rig key_id == the
// committed fixture key_id; the rebuilt statement == the committed
// hvf-control-statement.bin; the positive counter-1 variant verifies through
// the REAL hvf_control.verify_receipt (verified_task_success, counter 1)
// while the counter-2 variant is refused counter_binding. NO DeviceCheck, NO
// keychain: every case here is offline verification of rig bytes.
import CryptoKit
import XCTest

import marControl
@testable import marAttest

/// Loads Fixtures/appattest-variants.json (same #filePath pattern as
/// HvFFixture: no resource-bundle dependency).
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

    // Positive: the committed enrollment verifies locally and the rig's
    // counter-1 assertion over the EXACT committed statement bytes verifies
    // with the certified point (the python verifier admitted these bytes —
    // generation anchor 3).
    func testAdmittedEnrollmentAndAssertionVerifyLocally() throws {
        let fx = try HvFFixture()
        let v = try VariantsFixture()
        let appId = fx.identity["app_id"]!
        let enroll = try AppAttestVerify.verifyEnrollment(
            enrollmentCbor: fixtureData(fx, "enrollment_hex"),
            keyId: fx.enroll["key_id"] as! String,
            appId: appId,
            enrollClientData: fixtureData(fx, "client_data_hex"))
        XCTAssertEqual(Data(SHA256.hash(data: enroll.publicPoint)),
                       Data(base64: fx.enroll["key_id"] as! String),
                       "keyId must be sha256(certificate public point)")
        XCTAssertEqual(enroll.counterAtEnrollment, 0, "enrollment counter is 0")

        let statement = fx.expectedStatement
        XCTAssertEqual(SHA256.hex(statement), v.str("statement_sha256"))
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
        let fx = try HvFFixture()
        let scalar = fixtureScalar(fx)
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
            clientData: try HvFFixture().expectedStatement,
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
            clientData: try HvFFixture().expectedStatement,
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
            clientData: try HvFFixture().expectedStatement,
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
        let fx = try HvFFixture()
        let v = try VariantsFixture()
        XCTAssertThrowsError(try AppAttestVerify.verifyEnrollment(
            enrollmentCbor: v.data("enrollment_wrong_nonce_hex"),
            keyId: fx.enroll["key_id"] as! String,
            appId: fx.identity["app_id"]!,
            enrollClientData: fixtureData(fx, "client_data_hex"))) { error in
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
        XCTAssertEqual(try DER.pemDERSha256(Data(pem.utf8)), SHA256.hex(der))
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

extension Data {
    init(base64: String) {
        self = Data(base64Encoded: base64) ?? Data()
    }
}
