import SwiftUI
import DeviceCheck
import CryptoKit

@main
struct AppAttestLab: App {
    @StateObject private var model = LabModel()
    var body: some Scene { WindowGroup { LabView(model: model) } }
}

struct LabError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

@MainActor
final class LabModel: ObservableObject {
    @Published var endpoint = UserDefaults.standard.string(forKey: "labEndpoint") ?? Bundle.main.object(forInfoDictionaryKey: "LabDefaultEndpoint") as! String
    @Published var keyID = UserDefaults.standard.string(forKey: "labKeyID") ?? ""
    @Published var status = "Ready. This app tests app identity, not fixed-code membership."
    @Published var busy = false
    @Published var exportURL: URL?
    private var records: [[String: Any]] = []
    private let sessionID = UUID().uuidString
    private let service = DCAppAttestService.shared

    init() {
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "--endpoint"), arguments.indices.contains(index + 1) {
            endpoint = arguments[index + 1]
        }
        if let previous = UserDefaults.standard.string(forKey: "labLatestCapture") {
            let url = Self.documents.appendingPathComponent(previous)
            if FileManager.default.fileExists(atPath: url.path) { exportURL = url }
        }
    }

    private static var documents: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    var supported: Bool { service.isSupported }
    var localOutput: Int {
        #if MODIFIED
        return 5
        #else
        return 2 * 2
        #endif
    }
    var runtime: String {
        #if targetEnvironment(simulator)
        return "simulator"
        #else
        return "device"
        #endif
    }
    var variant: String {
        #if MODIFIED
        return "modified (2 → 5)"
        #else
        return "honest (2 → 4)"
        #endif
    }

    private func record(_ item: [String: Any]) throws {
        records.append(item)
        let object: [String: Any] = [
            "format": "ios-app-attest-lab-capture/v1",
            "client_metadata_untrusted": [
                "variant": variant,
                "session_id": sessionID,
                "runtime": runtime,
                "app_attest_supported": supported,
                "bundle_id": Bundle.main.bundleIdentifier ?? "",
                "bundle_version": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "",
                "os": ProcessInfo.processInfo.operatingSystemVersionString
            ], "records": records
        ]
        // A new file per process launch preserves the evidence across app updates.
        let url = Self.documents.appendingPathComponent("capture-\(sessionID).json")
        try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]).write(to: url, options: .atomic)
        UserDefaults.standard.set(url.lastPathComponent, forKey: "labLatestCapture")
        exportURL = url
    }

    private func baseURL() throws -> URL {
        guard let base = URL(string: endpoint), base.scheme == "https", base.host != nil,
              base.user == nil, base.password == nil, base.query == nil, base.fragment == nil else {
            throw LabError(message: "Enter an HTTPS server URL. Normal certificate validation is required.")
        }
        return base
    }

    func checkSetup() {
        guard !busy else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let base = try baseURL()
                UserDefaults.standard.set(endpoint, forKey: "labEndpoint")
                var request = URLRequest(url: base.appendingPathComponent("health"))
                request.timeoutInterval = 15
                request.cachePolicy = .reloadIgnoringLocalCacheData
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                      let health = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      health["status"] as? String == "ready",
                      health["evidence_origin"] as? String == "apple_root",
                      health["fixed_code_verified"] as? Bool == false,
                      health["root_sha256"] as? String == "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932",
                      let policy = health["policy"] as? [String: Any],
                      let appID = policy["app_id"] as? String,
                      appID.hasSuffix("." + (Bundle.main.bundleIdentifier ?? "")) else {
                    throw LabError(message: "Verifier health or app policy mismatch.")
                }
                try record(["path": "health", "response": health,
                            "local_output_unattested": localOutput, "fresh_attestation": false,
                            "timestamp": ISO8601DateFormatter().string(from: Date())])
                status = "HTTPS verified. Local output \(localOutput) (unattested). App Attest: \(supported ? "supported; ready for enrollment" : "unsupported on this runtime; enrollment disabled")."
            } catch {
                let error = error as NSError
                status = "Setup failed: \(error.localizedDescription)"
                try? record(["path": "health", "client_error_untrusted": status,
                             "error_domain": error.domain, "error_code": error.code,
                             "fresh_attestation": false])
            }
        }
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        let base = try baseURL()
        UserDefaults.standard.set(endpoint, forKey: "labEndpoint")
        var request = URLRequest(url: base.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw LabError(message: "Missing HTTP response") }
        let result = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        try record(["path": path, "request": body, "response": result,
                    "response_bytes": data.base64EncodedString(), "http_status": http.statusCode,
                    "timestamp": ISO8601DateFormatter().string(from: Date())])
        guard http.statusCode == 200 else {
            throw LabError(message: "Server rejected (\(http.statusCode)): \(result["reason"] ?? "see capture")")
        }
        return result
    }

    private func generate() async throws -> String {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            service.generateKey { key, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let key = key { continuation.resume(returning: key) }
                else { continuation.resume(throwing: LabError(message: "Missing generated key")) }
            }
        }
    }

    private func attest(_ key: String, _ hash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            service.attestKey(key, clientDataHash: hash) { data, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let data = data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: LabError(message: "Missing attestation")) }
            }
        }
    }

    private func assertion(_ key: String, _ hash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            service.generateAssertion(key, clientDataHash: hash) { data, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let data = data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: LabError(message: "Missing assertion")) }
            }
        }
    }

    func perform(_ action: String) {
        guard !busy else { return }
        guard supported else { status = "Unsupported device. No attestation bypass."; return }
        busy = true
        Task {
            defer { busy = false }
            do {
                if action == "new" {
                    keyID = try await generate()
                    UserDefaults.standard.set(keyID, forKey: "labKeyID")
                    status = "New key generated. Attest it next. Previous keys remain in server evidence."
                    return
                }
                guard !keyID.isEmpty else { throw LabError(message: "Generate a key first.") }
                let purpose = action == "attest" ? "attestation" : "assertion"
                let challenge = try await post("challenge", ["purpose": purpose, "key_id": keyID])
                guard let cid = challenge["challenge_id"] as? String,
                      let encoded = challenge["challenge"] as? String,
                      let nonce = Data(base64Encoded: encoded), nonce.count == 32 else {
                    throw LabError(message: "Malformed server challenge")
                }
                if action == "attest" {
                    let raw = try await attest(keyID, Data(SHA256.hash(data: nonce)))
                    let body: [String: Any] = ["challenge_id": cid, "key_id": keyID,
                                               "attestation": raw.base64EncodedString()]
                    // Save proof before transmission, including when the network fails.
                    try record(["path": "attest-pending", "request": body])
                    _ = try await post("attest", body)
                    status = "App identity enrolled. Fixed code has NOT been verified."
                } else {
                    let output = localOutput
                    let client: [String: Any] = ["protocol": "ios-app-attest-sok/v1", "challenge_id": cid,
                        "challenge": encoded, "key_id": keyID, "operation": "double", "input": 2, "output": output]
                    let clientData = try JSONSerialization.data(withJSONObject: client, options: [.sortedKeys])
                    let raw = try await assertion(keyID, Data(SHA256.hash(data: clientData)))
                    let body: [String: Any] = ["challenge_id": cid, "key_id": keyID,
                        "assertion": raw.base64EncodedString(), "client_data": clientData.base64EncodedString()]
                    try record(["path": "assert-pending", "request": body])
                    let result = try await post("assert", body)
                    status = "Identity accepted; output \(output). Matches expected computation: \(result["computation_matches"] ?? false)."
                }
            } catch {
                status = error.localizedDescription
                try? record(["client_error_untrusted": status,
                             "timestamp": ISO8601DateFormatter().string(from: Date())])
            }
        }
    }
}

struct LabView: View {
    @ObservedObject var model: LabModel
    var body: some View {
        NavigationStack {
            Form {
                Section("Experiment") {
                    Text("Variant: \(model.variant)")
                    Text("App Attest supported: \(model.supported ? "yes" : "no")")
                        .accessibilityIdentifier("appAttestSupport")
                    Text("Local double(2): \(model.localOutput) (unattested)")
                        .accessibilityIdentifier("localOutput")
                    TextField("HTTPS verifier URL", text: $model.endpoint)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .keyboardType(.URL).disabled(model.busy)
                    Text("Key: \(model.keyID.isEmpty ? "none" : model.keyID)")
                        .font(.caption).textSelection(.enabled)
                }
                Section("Setup") {
                    Button("Check HTTPS and device support") { model.checkSetup() }
                        .accessibilityIdentifier("checkSetup").disabled(model.busy)
                }
                Section("Run") {
                    Button("Generate new key") { model.perform("new") }
                        .accessibilityIdentifier("generateKey")
                    Button("Attest current key") { model.perform("attest") }
                        .accessibilityIdentifier("attestKey")
                    Button("Run double(2) and assert") { model.perform("assert") }
                        .accessibilityIdentifier("assertOperation")
                }.disabled(model.busy || !model.supported)
                Section("Result") {
                    Text(model.status).textSelection(.enabled).accessibilityIdentifier("labStatus")
                    if model.busy { ProgressView() }
                    if let url = model.exportURL { ShareLink("Export capture", item: url) }
                }
            }.navigationTitle("App Attest Lab")
        }
    }
}
