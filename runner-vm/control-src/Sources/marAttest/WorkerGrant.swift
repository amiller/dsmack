// The run's worker grant, the pure half: the request client data the app asserts to
// the coordinator, and opening the coordinator's reply, whose root key is sealed to
// the app's ephemeral P-256 key. Reference: dstack-compat/grant.py; shared vector:
// Tests/marAttestTests/Fixtures/worker-grant-vector.json.
import CryptoKit
import Foundation

public let grantRequestDomain = "dsmack.appattest.grant-request/1"

/// domain || manifest_sha256 || run || sha256(seal_pub) || sha256(task_id), 160 bytes.
public func grantRequestClientData(manifestSha256: Data, run: Data, sealPub: Data, taskId: String) -> Data {
    Data(grantRequestDomain.utf8) + manifestSha256 + run + Data(SHA256.hash(data: sealPub))
        + Data(SHA256.hash(data: Data(taskId.utf8)))
}

/// The public grant text and the scoped root key, held only in this process.
public struct WorkerGrant {
    public let text: String
    public let rootKey: Data
    /// sha256(grant text): the worker-grant event payload and the seal's associated data.
    public var digest: Data { Data(SHA256.hash(data: Data(text.utf8))) }

    /// Opens {grant, epk, nonce, ct}: ECDH with `key`, HKDF-SHA256, AES-GCM over the digest.
    public init(sealed r: [String: Any], key: P256.KeyAgreement.PrivateKey) throws {
        guard let text = r["grant"] as? String, let epkHex = r["epk"] as? String,
              let nonce = r["nonce"] as? String, let ct = r["ct"] as? String else {
            throw GuestAttestRefusal("grant reply lacks grant, epk, nonce or ct")
        }
        let epk = try guestHex(epkHex)
        let shared = try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: epk))
        let k = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(),
                                               sharedInfo: Data("dsmack-grant-seal/1".utf8) + key.publicKey.x963Representation + epk,
                                               outputByteCount: 32)
        self.text = text
        rootKey = try AES.GCM.open(AES.GCM.SealedBox(combined: try guestHex(nonce) + guestHex(ct)), using: k,
                                   authenticating: Data(SHA256.hash(data: Data(text.utf8))))
    }
}
