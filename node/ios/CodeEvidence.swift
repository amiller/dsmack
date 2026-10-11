import Foundation
import CryptoKit

/// Public CodeDirectory inputs only. No CMS signature, provisioning profile,
/// enrollment state or private key is exported. This is not an attestation.
struct CodeEvidence:Codable {
    let cdhash:String
    let cd:String
    let page0:String
    let ent:String
    let linkeditCmd:Int
    let codeSigCmd:Int

    enum Failure:LocalizedError {
        case invalid(String)
        var errorDescription:String? {if case .invalid(let message) = self {return message};return nil}
    }
    private static func require(_ condition:Bool,_ message:String) throws {
        if !condition {throw Failure.invalid(message)}
    }
    private static func bytes(_ data:Data,_ offset:Int,_ length:Int) throws -> Data {
        try require(offset>=0 && length>=0 && offset<=data.count && length<=data.count-offset,"Code evidence has an invalid byte range")
        return data.subdata(in:offset..<offset+length)
    }
    private static func u32(_ data:Data,_ offset:Int,big:Bool=false) throws -> Int {
        let b = try bytes(data,offset,4)
        return (big ? Array(b):Array(b.reversed())).reduce(0) {($0<<8)|Int($1)}
    }
    private static func hex(_ data:Data) -> String {"0x"+data.map {String(format:"%02x",$0)}.joined()}

    static func extract(_ input:Data) throws -> CodeEvidence {
        let file = Data(input)
        try require(file.count>=16384 && file.count<=32*1024*1024,"Unsupported executable size")
        try require(try u32(file,0)==0xfeedfacf && u32(file,4)==0x0100000c,"Expected a thin arm64 executable")
        let count = try u32(file,16),commandsSize = try u32(file,20)
        try require(count>0 && count<=1024 && commandsSize<=file.count-32,"Invalid Mach-O commands")
        var offset = 32
        var linkedit:Int?,signatureCommand:Int?,signatureOffset:Int?,signatureSize:Int?
        for _ in 0..<count {
            let command = try u32(file,offset),length = try u32(file,offset+4)
            try require(length>=8 && length%8==0 && offset+length<=32+commandsSize,"Invalid Mach-O command length")
            if try command==0x19 && length>=72 && bytes(file,offset+8,16)==Data("__LINKEDIT".utf8)+Data(repeating:0,count:6) {
                try require(linkedit==nil,"Duplicate LINKEDIT segment");linkedit=offset
            }
            if command==0x1d {
                try require(signatureCommand==nil && length==16,"Invalid code-signature command")
                signatureCommand=offset;signatureOffset=try u32(file,offset+8);signatureSize=try u32(file,offset+12)
            }
            offset+=length
        }
        try require(offset==32+commandsSize,"Mach-O command size mismatch")
        guard let linkedit,let signatureCommand,let signatureOffset,let signatureSize else {throw Failure.invalid("No embedded code signature")}
        try require(linkedit+72<=16384 && signatureCommand+16<=16384,"Load commands exceed the first code page")
        try require(signatureOffset>=16384 && signatureSize<=1024*1024,"Unsupported signature size or location")
        let signature = try bytes(file,signatureOffset,signatureSize)
        try require(try u32(signature,0,big:true)==0xfade0cc0,"Invalid signature container")
        let total = try u32(signature,4,big:true),slots = try u32(signature,8,big:true)
        try require(total>=12 && total<=signature.count && slots<=1024 && 12+8*slots<=total,"Invalid signature index")
        var directories=[Data](),der:Data?
        for i in 0..<slots {
            let kind = try u32(signature,12+8*i,big:true),start = try u32(signature,16+8*i,big:true)
            try require(start>=12+8*slots && start<=total-8,"Invalid signature blob offset")
            let magic = try u32(signature,start,big:true),length = try u32(signature,start+4,big:true)
            try require(length>=8 && length<=total-start,"Invalid signature blob length")
            if kind==0 || (0x1000...0x1005).contains(kind) {
                let candidate = try bytes(signature,start,length)
                try require(magic==0xfade0c02 && length>=44,"Invalid CodeDirectory")
                if candidate[36]==32 && candidate[37]==2 {directories.append(candidate)}
            }
            if kind==7 {
                try require(der==nil && magic==0xfade7172,"Invalid DER entitlements")
                der=try bytes(signature,start+8,length-8)
            }
        }
        try require(directories.count==1,"Expected one SHA-256 CodeDirectory")
        guard let der else {throw Failure.invalid("No sealed DER entitlements; export requires a signed device build")}
        let directory=directories[0],page=try bytes(file,0,16384)
        let hashOffset=try u32(directory,16,big:true),special=try u32(directory,24,big:true),codeSlots=try u32(directory,28,big:true)
        try require(directory[39]==14 && special>=7 && codeSlots>0 && codeSlots<=2048,"Unsupported code-page layout")
        try require(hashOffset>=7*32 && hashOffset+codeSlots*32<=directory.count,"Invalid CodeDirectory hash table")
        try require(try bytes(directory,hashOffset,32)==Data(SHA256.hash(data:page)),"Executable first page does not match its CodeDirectory")
        var entBlob=Data([0xfa,0xde,0x71,0x72]);let length=UInt32(der.count+8)
        entBlob.append(contentsOf:[UInt8((length>>24)&255),UInt8((length>>16)&255),UInt8((length>>8)&255),UInt8(length&255)]);entBlob.append(der)
        try require(try bytes(directory,hashOffset-7*32,32)==Data(SHA256.hash(data:entBlob)),"Entitlements do not match their CodeDirectory seal")
        return CodeEvidence(cdhash:hex(Data(SHA256.hash(data:directory))),cd:hex(directory),page0:hex(page),ent:hex(der),linkeditCmd:linkedit,codeSigCmd:signatureCommand)
    }
}
