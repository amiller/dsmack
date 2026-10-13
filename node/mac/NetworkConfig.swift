import Foundation

// Measured release network; operational metadata cannot redirect the peer.
// Measured category: admission is an open MeasurementRegistry window for this build's M.
// appRegistry: the dsmack-sdk AppRegistry on this chain; every non-test build's SDK reads it and no other (Node.swift Config).
// sdkPort: the GUI serves the SDK there when runner measurements are compiled in (build_mac.py --sdk-runner).
enum ReleaseNetwork {
    static let name = "Apple peer testnet"
    static let settings: [String:Any]? = try! JSONSerialization.jsonObject(with:Data(#"""
{
  "category": "0xfea7ca3e37ca38760ee1b6b754c54abec93064e5513ffe5e15d955087a4014cb",
  "chainId": 84532,
  "peer": "release-nft-seed",
  "persistentIdentity": true,
  "protocolVersion": 2,
  "registry": "0xd4B33C83576a6049d29c6B849ec73491e52781a0",
  "measurementRegistry": "0x976C2F9DF2bab0616f25D07CEC77cab7C5272203",
  "relay": "https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft",
  "rpc": "https://sepolia.base.org",
  "badges": "0x6Ac5fb83f5BF615842b5A9a6C50b8011FaB50c3B",
  "accountFactory": "0x18B5c72c48622661aEEadb596443C5E0E99F5188",
  "appRegistry": "0xa4d26deDf4d086216a0E2cFbc7bdA49918f5C5c3",
  "sdkPort": 18960
}
"""#.utf8)) as? [String:Any]
}
