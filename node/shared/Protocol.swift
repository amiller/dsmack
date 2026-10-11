import Foundation
import CryptoKit

func keccak(_ data: Data) -> Data {
    let rc: [UInt64] = [0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
    let rotations = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14]
    func rol(_ x: UInt64,_ n: Int) -> UInt64 { n == 0 ? x : (x << n) | (x >> (64-n)) }
    var bytes = [UInt8](data); bytes.append(1)
    while bytes.count % 136 != 0 { bytes.append(0) }; bytes[bytes.count-1] |= 128
    var a = [UInt64](repeating: 0, count: 25)
    for offset in stride(from: 0, to: bytes.count, by: 136) {
        for i in 0..<136 { a[i/8] ^= UInt64(bytes[offset+i]) << ((i%8)*8) }
        for constant in rc {
            var c = [UInt64](repeating:0,count:5)
            for x in 0..<5 { for y in 0..<5 { c[x] ^= a[x+5*y] } }
            for x in 0..<5 { let d = c[(x+4)%5] ^ rol(c[(x+1)%5],1); for y in 0..<5 { a[x+5*y] ^= d } }
            var b = [UInt64](repeating:0,count:25)
            for x in 0..<5 { for y in 0..<5 { b[y+5*((2*x+3*y)%5)] = rol(a[x+5*y],rotations[x+5*y]) } }
            for x in 0..<5 { for y in 0..<5 { a[x+5*y] = b[x+5*y] ^ ((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y]) } }
            a[0] ^= constant
        }
    }
    return Data((0..<32).map { UInt8(truncatingIfNeeded:a[$0/8] >> (($0%8)*8)) })
}
enum DemoError: Error, LocalizedError {
    case invalid(String)
    var errorDescription:String? {switch self {case .invalid(let message):return message}}
}
func need(_ condition: Bool,_ message: String) throws { if !condition { throw DemoError.invalid(message) } }
func unhex(_ value: String) throws -> Data {
    let s = value.hasPrefix("0x") ? String(value.dropFirst(2)) : value
    try need(s.count%2 == 0 && s.count<=65536,"hex size")
    let chars = Array(s); var bytes = [UInt8]()
    for i in stride(from:0,to:chars.count,by:2) {
        guard let b=UInt8(String(chars[i...i+1]),radix:16) else { throw DemoError.invalid("hex digit") }; bytes.append(b)
    }; return Data(bytes)
}
func hex(_ data: Data) -> String { "0x" + data.map { String(format:"%02x",$0) }.joined() }
func word(_ number: UInt64) -> Data { var n=number.bigEndian; return Data(repeating:0,count:24)+withUnsafeBytes(of:&n) { Data($0) } }
func addressWord(_ address: String) throws -> Data { let d=try unhex(address);try need(d.count==20,"address width");return Data(repeating:0,count:12)+d }
func bytes32(_ value: String) throws -> Data { let d=try unhex(value);try need(d.count==32,"bytes32 width");return d }
struct RawDigest: Digest {
    let data: Data
    static var byteCount: Int { 32 }
    func withUnsafeBytes<R>(_ body:(UnsafeRawBufferPointer)throws->R) rethrows -> R { try data.withUnsafeBytes(body) }
    func makeIterator() -> Array<UInt8>.Iterator { Array(data).makeIterator() }
}
struct Request: Codable {
    let action: UInt64;let category: Data;let owner: String;let session: Data
    let nonce: UInt64;let deadline: UInt64;let scope: Data;let x: Data;let y: Data;let envelope: Data
    func words() throws -> Data {
        try need(action<=3 && [category,session,scope,x,y,envelope].allSatisfy{$0.count==32},"request field widths")
        let ownerWord = try addressWord(owner)
        let parts = [word(action),category,ownerWord,ownerWord,session,word(nonce),word(deadline),scope,x,y,envelope]
        return parts.reduce(Data(),+)
    }
    func context(registry: String,chainId: UInt64,protocolVersion: Int=1,keyEpoch: UInt64=0) throws -> Data {
        try need(protocolVersion==1 || protocolVersion==2,"unsupported protocol version")
        try need(protocolVersion==2 || keyEpoch==0,"v1 has no key epochs")
        let name=Data((protocolVersion==2 ? "TEE_INTEROP_DEMO_V2":"TEE_INTEROP_DEMO_V1").utf8)
        var parts = [word(UInt64(protocolVersion==2 ? 15*32:14*32)),word(chainId),try addressWord(registry)]
        if protocolVersion==2 {parts.append(word(keyEpoch))}
        parts += [try words(),word(UInt64(name.count)),name,Data(repeating:0,count:(32-name.count%32)%32)]
        return keccak(parts.reduce(Data(),+))
    }
    var json: [String:Any] { ["action":action,"category":hex(category),"owner":owner,"memberSigner":owner,"sessionKeyHash":hex(session),"nonce":nonce,"validUntil":deadline,"scope":hex(scope),"keyX":hex(x),"keyY":hex(y),"envelopeDigest":hex(envelope)] }
}
func http(_ url: URL,_ body: Any?=nil) throws -> Any {
    var request=URLRequest(url:url);request.timeoutInterval=120
    if let body {
        request.httpMethod="POST";request.setValue("application/json",forHTTPHeaderField:"Content-Type")
        request.httpBody=try JSONSerialization.data(withJSONObject:body)
    }
    let wait=DispatchSemaphore(value:0);var out:Data?;var failure:Error?;var status=0
    URLSession.shared.dataTask(with:request){d,r,e in out=d;failure=e;status=(r as? HTTPURLResponse)?.statusCode ?? 0;wait.signal()}.resume()
    wait.wait()
    if let failure {throw failure}
    guard let out else {throw DemoError.invalid("empty HTTP body")}
    try need(status==200,"HTTP \(status) \(url.path): \(String(decoding:out,as:UTF8.self))")
    return try JSONSerialization.jsonObject(with:out)
}

struct BadgeClaim {
    let recipient:String; let keyId:Data; let level:UInt64; let parent:UInt64; let deadline:UInt64
    func words() throws -> Data {
        try need(keyId.count==32 && (level==1 || level==2),"badge claim fields")
        return try addressWord(recipient)+keyId+word(level)+word(parent)+word(deadline)
    }
    func digest(chainId:UInt64,badges:String) throws -> Data {
        let domain=Data("ATTEST_RESEARCH_BADGE_V1".utf8)
        return try keccak(word(8*32)+word(chainId)+addressWord(badges)+words()+word(UInt64(domain.count))+domain+Data(repeating:0,count:(32-domain.count%32)%32))
    }
    var json:[String:Any] { ["recipient":recipient,"keyId":hex(keyId),"level":level,"parent":parent,"deadline":deadline] }
}
