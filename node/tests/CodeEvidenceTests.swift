import Foundation

@main struct CodeEvidenceTests {
    static func main() throws {
        let original = try Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[1]))
        let valid = try CodeEvidence.extract(original)
        if CommandLine.arguments.count>2 {try JSONEncoder().encode(valid).write(to:URL(fileURLWithPath:CommandLine.arguments[2]))}
        var checks = 1
        func reject(_ label:String,_ data:Data) throws {
            do {_ = try CodeEvidence.extract(data)} catch {checks+=1;return}
            throw CodeEvidence.Failure.invalid("Accepted invalid fixture: "+label)
        }
        func u32(_ data:Data,_ offset:Int,_ big:Bool=false) -> Int {
            let bytes=Array(data[offset..<offset+4]);return (big ? bytes:Array(bytes.reversed())).reduce(0) {($0<<8)|Int($1)}
        }
        func patch(_ data:Data,_ offset:Int,_ value:UInt32,_ big:Bool=false) -> Data {
            var result=data
            let bytes=(0..<4).map {UInt8((value >> (8*$0)) & 255)}
            result.replaceSubrange(offset..<offset+4,with:big ? Array(bytes.reversed()):bytes)
            return result
        }
        try reject("truncated file",original.prefix(12))
        try reject("wrong magic",patch(original,0,0))
        try reject("wrong architecture",patch(original,4,0))
        try reject("command count",patch(original,16,0xffffffff))
        try reject("command extent",patch(original,20,0xffffffff))
        try reject("zero command length",patch(original,36,0))
        try reject("missing signature",patch(original,valid.codeSigCmd,0))
        try reject("signature out of bounds",patch(original,valid.codeSigCmd+8,0xffffffff))
        let signature=u32(original,valid.codeSigCmd+8)
        try reject("signature magic",patch(original,signature,0))
        try reject("index count",patch(original,signature+8,0xffffffff,true))
        var modified=original;modified[16383] ^= 1
        try reject("unsealed first page",modified)
        let slots=u32(original,signature+8,true)
        for i in 0..<slots {
            let kind=u32(original,signature+12+8*i,true)
            let start=signature+u32(original,signature+16+8*i,true)
            if kind==0 && original[start+37]==2 {
                try reject("hash table offset",patch(original,start+16,0xffffffff,true))
                try reject("page size",patch(original,start+36,0x2002000c,true))
            }
            if kind==7 {
                var altered=original;altered[start+8] ^= 1
                try reject("unsealed entitlements",altered)
                try reject("blob extent",patch(original,start+4,0xffffffff,true))
            }
        }
        print("CodeEvidence: \(checks) checks passed against signed executable and malformed variants; no hardware attestation")
    }
}
