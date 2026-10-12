import Foundation
import CryptoKit
import Security

/// Signer-independent code measurement M (open-admission design §2). Same definition as
/// contracts/src/Measurement.sol and scripts/release/measure.py; vectors in node/tests/MeasureVectors.swift.
struct CodeMeasurement {
    let cd: [UInt8], page0: [UInt8], ent: [UInt8], L: Int, S: Int
    static let identityKeys: Set<[UInt8]> = Set(["application-identifier","com.apple.application-identifier",
        "com.apple.developer.team-identifier","keychain-access-groups"].map{Array($0.utf8)})

    /// The running executable. kSecCodeInfoCdHashesFull describes the file on disk, not the running
    /// code (measured on macOS 27), so SecCodeCheckValidity first requires disk == running
    /// (errSecCSStaticCodeChanged otherwise); any replacement between the steps fails one of the checks.
    static func ofSelf() throws -> CodeMeasurement {
        guard let url=Bundle.main.executableURL else {throw DemoError.invalid("executable URL")}
        let x=try of(executable:url)
        var code:SecCode?,staticCode:SecStaticCode?,info:CFDictionary?
        try need(SecCodeCopySelf([],&code)==errSecSuccess,"SecCodeCopySelf")
        let valid=SecCodeCheckValidity(code!,[],nil)
        try need(valid==errSecSuccess,"running code does not match its executable (\(valid))")
        try need(SecCodeCopyStaticCode(code!,[],&staticCode)==errSecSuccess,"SecCodeCopyStaticCode")
        try need(SecCodeCopySigningInformation(staticCode!,SecCSFlags(rawValue:kSecCSSigningInformation),&info)==errSecSuccess,"signing information")
        // kSecCodeInfoCdHashesFull ("cdhashes-full", SecCodePriv.h) keyed by kSecCodeSignatureHashSHA256 (2).
        let cdhash=((info as? [String:Any])?["cdhashes-full"] as? NSDictionary)?[NSNumber(value:2)] as? Data
        try need(cdhash==Data(SHA256.hash(data:x.cd)),"executable CodeDirectory differs from the running code")
        return x
    }

    /// Sent with the enroll request (about 17 KB) for MeasurementRegistry.register.
    var enrollFields: [String:Any] {["cd":Data(cd).base64EncodedString(),"page0":Data(page0).base64EncodedString(),"ent":Data(ent).base64EncodedString(),"L":L,"S":S]}

    static func of(executable url: URL) throws -> CodeMeasurement {
        let b=[UInt8](try Data(contentsOf:url))
        try need(b.count>=32 && le32(b,0)==0xfeedfacf && le32(b,4)==0x0100000c,"arm64 Mach-O")
        var p=32,L:Int?,S:Int?
        for _ in 0..<le32(b,16) {
            let cmd=le32(b,p),size=le32(b,p+4)
            if cmd==0x19 && Array(b[p+8..<p+24])==linkedit {L=p}
            if cmd==0x1d {S=p}
            p+=size
        }
        guard let L,let S else {throw DemoError.invalid("load commands")}
        let sb=Array(b[le32(b,S+8)..<le32(b,S+8)+le32(b,S+12)])
        try need(be32(sb,0)==0xfade0cc0,"superblob")
        var blobs:[Int:[UInt8]]=[:]
        for i in 0..<be32(sb,8) {let o=be32(sb,16+8*i);blobs[be32(sb,12+8*i)]=Array(sb[o..<o+be32(sb,o+4)])}
        guard let cd=blobs[0],let e=blobs[7],be32(e,0)==0xfade7172 else {throw DemoError.invalid("CodeDirectory/DER entitlements")}
        return CodeMeasurement(cd:cd,page0:Array(b[0..<16384]),ent:Array(e[8...]),L:L,S:S)
    }

    func value() throws -> Data {
        try need(cd.count>=0x60 && Self.be32(cd,0)==0xfade0c02 && Self.be32(cd,4)==cd.count && Self.be32(cd,8)==0x20500,"blob")
        try need(cd[0x24]==32 && cd[0x25]==2 && cd[0x27]==14 && Self.be32(cd,0x2c)==0 && Self.be32(cd,0x18)==7,"layout")
        let off=Self.be32(cd,0x10),end=off+32*Self.be32(cd,0x1c)
        try need(off>=224 && end<=cd.count && end>off,"bounds")
        try need(cd[off-128..<off-96].allSatisfy{$0==0} && cd[off-192..<off-160].allSatisfy{$0==0},"slots -4/-6")
        try need(page0.count==16384 && Self.sha(page0)==Array(cd[off..<off+32]),"page0 hash")
        try need(Self.sha(Self.be(0xfade7172)+Self.be(ent.count+8)+ent)==Array(cd[off-224..<off-192]),"entitlements slot")
        try need(L>=0 && L<=16384-56 && S>=0 && S<=16384-16 && Self.le32(page0,L)==0x19 && Array(page0[L+8..<L+24])==Self.linkedit
            && Self.le32(page0,S)==0x1d,"load commands")
        var masked=page0
        for r in [L+32..<L+40,L+48..<L+56,S+12..<S+16] {masked.replaceSubrange(r,with:[UInt8](repeating:0,count:r.count))}
        var c=Array("dsmack.measure.v1".utf8)
        c+=cd[8..<16];c+=cd[0x1c..<0x30];c+=cd[0x34..<0x60];c+=Self.be(L)+Self.be(S)+Self.sha(masked);c+=cd[off+32..<end];c+=try shape()
        return Data(Self.sha(c))
    }

    /// Each dictionary pair as 0x01 || DER(pair), identity keys as 0x00 || DER(key), in blob order.
    func shape() throws -> [UInt8] {
        let outer=try Self.der(ent,0,ent.count,0x70),version=try Self.der(ent,outer.body,outer.end,0x02)
        try need(outer.end==ent.count && version.end==version.body+1 && ent[version.body]==1,"entitlements")
        let dict=try Self.der(ent,version.end,outer.end,0xb0)
        try need(dict.end==outer.end,"entitlements")
        var e:[UInt8]=[],p=dict.body
        while p<dict.end {
            let pair=try Self.der(ent,p,dict.end,0x30),key=try Self.der(ent,pair.body,pair.end,0x0c)
            try need(try Self.der(ent,key.end,pair.end,nil).end==pair.end,"entitlements")
            e+=Self.identityKeys.contains(Array(ent[key.body..<key.end])) ? [0]+ent[key.start..<key.end] : [1]+ent[pair.start..<pair.end]
            p=pair.end
        }
        return e
    }

    /// Mirrors StrictDER.node.
    static func der(_ b:[UInt8],_ at:Int,_ limit:Int,_ tag:UInt8?) throws -> (start:Int,body:Int,end:Int) {
        try need(limit<=b.count && at+2<=limit,"DER bounds")
        try need(b[at]&31 != 31,"DER long tag")
        var n=Int(b[at+1]),body=at+2
        if n>=128 {
            let count=n&127;try need(count>0 && count<=2 && body+count<=limit,"DER length")
            try need(b[body] != 0,"DER leading length zero")
            n=b[body..<body+count].reduce(0){$0<<8|Int($1)};body+=count
            try need(n>=128,"DER nonminimal length")
        }
        try need(body+n<=limit,"DER truncated")
        try need(tag==nil || b[at]==tag,"DER tag")
        return (at,body,body+n)
    }
    static let linkedit=Array("__LINKEDIT".utf8)+[UInt8](repeating:0,count:6)
    static func sha(_ b:[UInt8]) -> [UInt8] {Array(SHA256.hash(data:b))}
    static func be(_ v:Int) -> [UInt8] {[24,16,8,0].map{UInt8(truncatingIfNeeded:v>>$0)}}
    static func be32(_ b:[UInt8],_ o:Int) -> Int {b[o..<o+4].reduce(0){$0<<8|Int($1)}}
    static func le32(_ b:[UInt8],_ o:Int) -> Int {b[o..<o+4].reversed().reduce(0){$0<<8|Int($1)}}
}
