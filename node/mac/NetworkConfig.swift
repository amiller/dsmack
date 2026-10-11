import Foundation

// Measured release network; operational metadata cannot redirect the peer.
// Admission is activated only after the exact signed build is registered.
enum ReleaseNetwork {
    static let name = "Apple peer testnet"
    static let settings: [String:Any]? = try! JSONSerialization.jsonObject(with:Data(#"""
{
  "category": "0xbbbb9ea44ff8fbd35e60f06bdf52445c102d8d1ffa10f5df51582dbd45cda9b6",
  "chainId": 84532,
  "peer": "release-nft-seed",
  "persistentIdentity": true,
  "protocolVersion": 2,
  "registry": "0xd4B33C83576a6049d29c6B849ec73491e52781a0",
  "relay": "https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft",
  "rpc": "https://sepolia.base.org",
  "badges": "0x6Ac5fb83f5BF615842b5A9a6C50b8011FaB50c3B",
  "accountFactory": "0x18B5c72c48622661aEEadb596443C5E0E99F5188"
}
"""#.utf8)) as? [String:Any]
}
