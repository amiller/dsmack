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
enum DemoError: Error { case invalid(String) }
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
struct Request {
    let action: UInt64;let category: Data;let owner: String;let session: Data
    let nonce: UInt64;let deadline: UInt64;let scope: Data;let x: Data;let y: Data;let envelope: Data
    func words() throws -> Data {
        let ownerWord = try addressWord(owner)
        let parts = [word(action),category,ownerWord,ownerWord,session,word(nonce),word(deadline),scope,x,y,envelope]
        return parts.reduce(Data(),+)
    }
    func context(registry: String) throws -> Data {
        let name=Data("TEE_INTEROP_DEMO_V1".utf8)
        let parts = [word(14*32),word(84532),try addressWord(registry),try words(),word(UInt64(name.count)),name,Data(repeating:0,count:(32-name.count%32)%32)]
        return keccak(parts.reduce(Data(),+))
    }
    var json: [String:Any] { ["action":action,"category":hex(category),"owner":owner,"memberSigner":owner,"sessionKeyHash":hex(session),"nonce":nonce,"validUntil":deadline,"scope":hex(scope),"keyX":hex(x),"keyY":hex(y),"envelopeDigest":hex(envelope)] }
}
