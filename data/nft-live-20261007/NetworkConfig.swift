import Foundation
enum ReleaseNetwork {
static let name="Apple peer testnet — NFT validation"
static let settings:[String:Any]? = try! JSONSerialization.jsonObject(with:Data(#"""
{
  "category": "0xc74823c806be6ac234fdb49f4f84cd01ecc265c7f21c82a2c7baeb86862e03ef",
  "chainId": 31337,
  "peer": "nft-seed-20261007",
  "persistentIdentity": true,
  "protocolVersion": 2,
  "registry": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
  "relay": "http://127.0.0.1:18586",
  "rpc": "http://127.0.0.1:18585",
  "badges": "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
  "accountFactory": "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
}
"""#.utf8)) as? [String:Any]
}
