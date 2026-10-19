import Foundation
import DeviceCheck
import CryptoKit

func log(_ s: String) { FileHandle.standardError.write((s+"\n").data(using: .utf8)!) }

let svc = DCAppAttestService.shared
log("isSupported=\(svc.isSupported)")
guard svc.isSupported else { log("NOT SUPPORTED"); exit(2) }

let outDir = ("~/.dsmack-demo/appattest" as NSString).expandingTildeInPath
try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

let sem = DispatchSemaphore(value: 0)
var keyId = ""
svc.generateKey { kid, err in
  if let err = err { log("generateKey error: \(err)"); exit(3) }
  keyId = kid ?? ""; sem.signal()
}
sem.wait()
log("keyId=\(keyId)")

let challenge = "dsmack-appattest-probe-2026-09-15".data(using: .utf8)!
let clientDataHash = Data(SHA256.hash(data: challenge))

svc.attestKey(keyId, clientDataHash: clientDataHash) { attestation, err in
  if let err = err { log("attestKey error: \(err)"); exit(4) }
  let att = attestation ?? Data()
  try? att.write(to: URL(fileURLWithPath: outDir + "/attestation.cbor"))
  try? keyId.write(toFile: outDir + "/keyId.txt", atomically: true, encoding: .utf8)
  try? challenge.write(to: URL(fileURLWithPath: outDir + "/challenge.bin"))
  try? clientDataHash.write(to: URL(fileURLWithPath: outDir + "/clientDataHash.bin"))
  log("attestation bytes=\(att.count) -> \(outDir)")
  sem.signal()
}
sem.wait()
log("DONE")
