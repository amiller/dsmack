import Foundation
import DeviceCheck
import CryptoKit
import Darwin

// Capability only by default. --attest <new-output-directory> requires an
// independently signed/provisioned app; it never contacts a network registry.
@main struct MacAppAttestProbe {
    static func emit(_ value: [String: Any]) {
        let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self)); fflush(stdout)
    }
    static func operation<T>(_ start: (@escaping (T?, Error?) -> Void) -> Void) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            start { value, error in
                if let error { continuation.resume(throwing: error) }
                else if let value { continuation.resume(returning: value) }
                else { continuation.resume(throwing: NSError(domain: "ProbeMissingResult", code: 1)) }
            }
        }
    }
    static func main() async {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        emit(["stage": "os", "version": ProcessInfo.processInfo.operatingSystemVersionString,
              "macOS27Required": true])
        guard os.majorVersion >= 27 else {
            emit(["result": "unsupported_os"]); return
        }
        let service = DCAppAttestService.shared
        emit(["stage": "isSupported", "supported": service.isSupported,
              "context": "this exact executable and signing context"])
        guard service.isSupported else { emit(["result": "unsupported_context"]); return }
        guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--attest" else {
            emit(["result": "capability_only", "attestationVerified": false]); return
        }
        var stage = "output"
        do {
            let out = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
            guard !FileManager.default.fileExists(atPath: out.path) else {
                throw NSError(domain: "ProbeOutputAlreadyExists", code: 1)
            }
            try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
            stage = "generateKey"
            let key: String = try await operation { service.generateKey(completionHandler: $0) }
            emit(["stage": stage, "result": "ok"])
            // Public fresh challenge; only the App Attest key ID is exported.
            let challenge = Data(UUID().uuidString.utf8)
            let digest = Data(SHA256.hash(data: challenge))
            stage = "attestKey"
            let attestation: Data = try await operation { service.attestKey(key, clientDataHash: digest, completionHandler: $0) }
            emit(["stage": stage, "result": "ok"])
            stage = "generateAssertion"
            let assertion: Data = try await operation { service.generateAssertion(key, clientDataHash: digest, completionHandler: $0) }
            let hex = challenge.map { String(format: "%02x", $0) }.joined()
            let evidence: [String: Any] = ["keyId": key, "clientData": hex,
                "attestation": attestation.base64EncodedString(), "assertion": assertion.base64EncodedString(),
                "assertionClientDataHash": digest.base64EncodedString()]
            try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
                .write(to: out.appendingPathComponent("evidence.json"), options: [.atomic])
            emit(["stage": stage, "result": "ok", "verifierAcceptance": "not_tested",
                  "networkEnrollmentSubmitted": false])
        } catch {
            let e = error as NSError
            emit(["stage": stage, "result": "error", "domain": e.domain, "code": e.code])
            exit(1)
        }
    }
}
