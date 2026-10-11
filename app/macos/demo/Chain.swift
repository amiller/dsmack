import Foundation

let demoRegistry = "0xCea3a2E7cBec98d0f2672E1b885f72B2705a24F6"
let demoRPC = URL(string:"https://sepolia.base.org")!
// Explicit v1 trust assumption: authenticated HTTPS RPC, not a light client.
// The host cannot substitute the endpoint or inject RPC response files.
func rpc(_ method: String,_ params: [Any]) throws -> Any {
    var request=URLRequest(url:demoRPC);request.httpMethod="POST";request.timeoutInterval=20
    request.setValue("application/json",forHTTPHeaderField:"Content-Type")
    request.httpBody=try JSONSerialization.data(withJSONObject:["jsonrpc":"2.0","id":1,"method":method,"params":params])
    let wait=DispatchSemaphore(value:0);var responseData:Data?;var failure:Error?;var status=0
    URLSession.shared.dataTask(with:request){data,response,error in
        responseData=data;failure=error;status=(response as? HTTPURLResponse)?.statusCode ?? 0;wait.signal()
    }.resume()
    guard wait.wait(timeout:.now()+25) == .success else {throw DemoError.invalid("RPC timeout")}
    if let e=failure {throw e};try need(status==200,"RPC HTTP status")
    guard let data=responseData,let result=try JSONSerialization.jsonObject(with:data) as? [String:Any],result["error"]==nil,let value=result["result"] else {throw DemoError.invalid("RPC result")}
    return value
}
func quantity(_ value:Any?) throws -> UInt64 {
    guard let s=value as? String,let n=UInt64(s.hasPrefix("0x") ? String(s.dropFirst(2)):s,radix:16) else {throw DemoError.invalid("RPC quantity")};return n
}
func call(_ signature:String,_ words:Data=Data(),to:String=demoRegistry) throws -> Data {
    let payload=keccak(Data(signature.utf8)).prefix(4)+words
    guard let s=try rpc("eth_call",[["to":to,"data":hex(payload)],"latest"]) as? String else {throw DemoError.invalid("call response")}
    return try unhex(s)
}
func smallWord(_ data:Data) throws -> UInt64 {
    try need(data.count==32 && data.prefix(24)==Data(repeating:0,count:24),"uint64 encoding")
    return data.suffix(8).reduce(UInt64(0)){($0<<8)|UInt64($1)}
}
func groupPublic(_ scope:Data) throws -> Data {
    let value=try call("sharedKeys(bytes32)",scope);try need(value.count==128,"shared key encoding")
    try need(try smallWord(value.subdata(in:96..<128))==1,"key not committed")
    return Data([4])+value.prefix(64)
}
func eligible(_ member:Data,_ category:Data,_ scope:Data) throws {
    try need(try smallWord(call("isActive(bytes32)",member))==1,"inactive peer")
    if scope==Data(repeating:0,count:32){
        let c=try call("categories(bytes32)",category);try need(c.count==192,"category encoding")
        try need(try smallWord(c.subdata(in:128..<160))==1,"overall ineligible")
    }else{try need(category==scope,"wrong recipient category")}
}
struct CheckedPeer {let member:Data;let category:Data;let context:Data;let session:Data;let logs:[[String:Any]]}
func checkedPeer(_ transaction:String) throws -> CheckedPeer {
    try need(try unhex(transaction).count==32,"transaction width")
    guard let receipt=try rpc("eth_getTransactionReceipt",[transaction]) as? [String:Any],
          let blockHash=receipt["blockHash"] as? String,let blockNumber=receipt["blockNumber"] as? String,
          let logs=receipt["logs"] as? [[String:Any]] else {throw DemoError.invalid("unmined receipt")}
    try need(try quantity(receipt["status"])==1,"failed transaction")
    guard let block=try rpc("eth_getBlockByNumber",[blockNumber,false]) as? [String:Any],let canonicalHash=block["hash"] as? String else {throw DemoError.invalid("missing block")}
    try need(canonicalHash==blockHash,"reorged receipt")
    let timestamp=try quantity(block["timestamp"]);let now=UInt64(Date().timeIntervalSince1970)
    try need(timestamp<=now+5 && now<timestamp+60,"stale peer check-in")
    let latest=try quantity(rpc("eth_blockNumber",[]));try need(latest>=quantity(blockNumber),"future receipt")
    let topic=hex(keccak(Data("Checked(bytes32,bytes32,address,bytes32,bytes32)".utf8)))
    let found=logs.filter{($0["address"] as? String)?.lowercased()==demoRegistry.lowercased() && ($0["topics"] as? [String])?.first==topic}
    try need(found.count==1,"ambiguous peer check-in")
    let log=found[0];guard let topics=log["topics"] as? [String],topics.count==4,let raw=log["data"] as? String else {throw DemoError.invalid("check-in log")}
    let data=try unhex(raw);try need(data.count==64,"check-in encoding")
    return try CheckedPeer(member:bytes32(topics[1]),category:bytes32(topics[2]),context:data.prefix(32),session:data.suffix(32),logs:logs)
}
func validateRelease(_ tx:String,_ parcel:Data,_ scope:Data) throws {
    let peer=try checkedPeer(tx);try eligible(peer.member,peer.category,scope)
    try need(peer.session==keccak(parcel.prefix(65)),"sender session")
    let topic=hex(keccak(Data("KeyReceipt(bytes32,bytes32,bytes32,bytes32)".utf8)))
    let matches=peer.logs.filter{log in
        guard (log["address"] as? String)?.lowercased()==demoRegistry.lowercased(),let topics=log["topics"] as? [String],topics.count==3 else {return false}
        return topics[0]==topic && topics[1]==hex(scope) && topics[2]==hex(peer.member)
    }
    try need(matches.count==1,"missing release commitment")
    guard let encoded=matches[0]["data"] as? String else {throw DemoError.invalid("release data")}
    let data=try unhex(encoded);try need(data==keccak(parcel)+peer.context,"release digest/context")
}
