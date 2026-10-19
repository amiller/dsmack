import Foundation
import CryptoKit
struct Fail: Error { let message: String; init(_ message: String) { self.message = message } }
struct Onchain: Codable { let rpc: String; let apps: [String] }
struct ProviderQuote: Codable { let kind, attestation_url: String; let compose_hashes: [String]?; let onchain: Onchain?; let model: String? }
struct Quote { let sha256: String; let spki: Set<String>; let report: Data; let onchain: Any? }
let anchorsDER: [String] = []
let scriptText = "// inert synthetic helper: must never execute\n"
let providerQuoteHelperSHA256 = sha256hex(Data(scriptText.utf8))
func sha256hex(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }
func log(_ s: String) { print(s) }
func object(_ d: Data, _ name: String) throws -> [String: Any] { guard let o = try JSONSerialization.jsonObject(with: d) as? [String: Any] else { throw Fail(name) }; return o }
struct QuoteHelper {
    let node: URL, script: URL, out: URL

    func check() throws {
        let h = sha256hex(try Data(contentsOf: script))
        guard h == providerQuoteHelperSHA256 else { throw Fail("quote helper \(script.path) sha256 \(h) != compiled-in \(providerQuoteHelperSHA256)") }
    }

    // nearai: the API key goes to the helper on stdin (NEAR's report endpoint needs it).
    func run(_ pq: ProviderQuote, host: String, key: String) async throws -> Quote {
        try check()
        let p = Process(), so = Pipe(), se = Pipe()
        p.executableURL = node
        p.arguments = [script.path, String(decoding: try JSONEncoder().encode(pq), as: UTF8.self), host, anchorsDER.joined(separator: ",")]
        let si = Pipe()
        p.standardInput = si
        p.currentDirectoryURL = script.deletingLastPathComponent()
        (p.standardOutput, p.standardError) = (so, se)
        let (o, e, status): (Data, Data, Int32) = try await withCheckedThrowingContinuation { c in
            DispatchQueue.global().async {
                do {
                    try p.run()
                    try si.fileHandleForWriting.write(contentsOf: Data((pq.kind == "nearai" ? key : "").utf8))
                    try si.fileHandleForWriting.close()
                    let o = so.fileHandleForReading.readDataToEndOfFile(), e = se.fileHandleForReading.readDataToEndOfFile()
                    p.waitUntilExit()
                    c.resume(returning: (o, e, p.terminationStatus))
                } catch { c.resume(throwing: error) }
            }
        }
        guard status == 0 else { throw Fail(String(decoding: e, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) }
        let r = try object(o, "quote helper output")
        guard let report = (r["report_b64"] as? String).flatMap({ Data(base64Encoded: $0) }), let spki = r["tls_spki_sha256"] as? [String] else {
            throw Fail("quote helper output lacks report_b64/tls_spki_sha256")
        }
        let sha = sha256hex(report)
        try o.write(to: out.appendingPathComponent("provider-quote-\(sha.prefix(16)).json"))
        log("provider quote verified: \(pq.kind) \(pq.attestation_url) for \(host), report sha256 \(sha)\(r["onchain"].map { ", onchain \($0)" } ?? "")")
        return Quote(sha256: sha, spki: Set(spki), report: report, onchain: r["onchain"])
    }
}

@main struct Probe {
 static func main() async throws {
  let dir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
  let script = dir.appendingPathComponent("inert.mjs")
  let wrapper = dir.appendingPathComponent("unmeasured-node.sh")
  try Data(scriptText.utf8).write(to: script)
  let shell = """
#!/bin/sh
/bin/cat > "$1.capture"
/usr/bin/printf '%s' '{"report_b64":"e30=","tls_spki_sha256":[]}'

"""
  try Data(shell.utf8).write(to: wrapper)
  try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: wrapper.path)
  let helper = QuoteHelper(node: wrapper, script: script, out: dir)
  let dummy = "SYNTHETIC-NONSECRET-NEAR-KEY-20261011"
  let pq = ProviderQuote(kind: "nearai", attestation_url: "https://provider.example.invalid/unused", compose_hashes: nil, onchain: nil, model: nil)
  let quote = try await helper.run(pq, host: "provider.example.invalid", key: dummy)
  let capture = URL(fileURLWithPath: script.path + ".capture")
  let bytes = try Data(contentsOf: capture)
  guard bytes == Data(dummy.utf8), quote.report == Data("{}".utf8) else { throw Fail("dummy capture or synthetic report mismatch") }
  print("PASS current QuoteHelper sends complete dummy NEAR credential to caller-selected node executable")
  print("PASS valid helper hash unchanged; malicious node bypasses helper execution and returns accepted synthetic report")
  let other = ProviderQuote(kind: "redpill", attestation_url: "https://provider.example.invalid/unused", compose_hashes: nil, onchain: nil, model: nil)
  _ = try await helper.run(other, host: "provider.example.invalid", key: dummy)
  guard try Data(contentsOf: capture).isEmpty else { throw Fail("non-NEAR control received credential") }
  print("PASS non-NEAR control passes empty stdin")
  try Data("modified".utf8).write(to: script)
  do { _ = try await helper.run(pq, host: "provider.example.invalid", key: dummy); throw Fail("bad helper accepted") }
  catch let e as Fail { guard e.message.contains("!= compiled-in") else { throw e } }
  guard try Data(contentsOf: capture).isEmpty else { throw Fail("wrapper ran despite hash rejection") }
  print("PASS changed helper hash rejected before subprocess; no network or real credential used")
 }
}
