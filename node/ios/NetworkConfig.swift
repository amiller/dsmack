import Foundation

// Measured release network; operational metadata cannot redirect the peer.
// Admission is activated only after the exact signed build is registered.
enum ReleaseNetwork {
    static let name = "Apple peer testnet"
    static let settings: [String:Any]? = try! JSONSerialization.jsonObject(with:Data(#"""
{
  "category": "0x654effd95d2f6a4403e34c4f0965b3b2e22622d2468ce95baeb3d9a31bd474db",
  "chainId": 84532,
  "peer": "release-nft-seed",
  "persistentIdentity": true,
  "protocolVersion": 2,
  "registry": "0xd4B33C83576a6049d29c6B849ec73491e52781a0",
  "relay": "https://pod.dstack.soc1024.com/apple-attest-p2p-relay/ios",
  "rpc": "https://sepolia.base.org",
  "badges": "0xaFc976776bBB397636657B1AE05915C34917591D",
  "accountFactory": "0xcEd9EE12852DE52326B20CeD10bB56652500ceb4"
}
"""#.utf8)) as? [String:Any]
}
