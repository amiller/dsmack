import Foundation

// Enroll payload and directory heartbeat encoding; compile with every node/shared source.
// MeasuredEnrollTests [fixtures dir]  |  MeasuredEnrollTests --self (run signed: the payload of this executable)
@main struct MeasuredEnrollTests {
    static func main() throws {
        var checks=0
        func check(_ ok:Bool,_ label:String) throws {try need(ok,label);checks+=1}
        let a=CommandLine.arguments
        let cfg=try Config(["rpc":"http://127.0.0.1:1","registry":"0xd4b33c83576a6049d29c6b849ec73491e52781a0","chainId":84532,
                            "category":"0x"+String(repeating:"22",count:32),"relay":"http://127.0.0.1:1","name":"test","protocolVersion":2])
        if a.count==2 && a[1]=="--self" {
            let node=Node(cfg,log:{_,_ in})
            guard let own=try node.ownMeasurement() else {throw DemoError.invalid("no measurement on macOS")}
            let x=try CodeMeasurement.ofSelf()
            try check(own.value==(try x.value()) && own.value.count==32,"own M")
            try payload(own.fields,x,check)
            print("MeasuredEnrollTests --self passed: \(checks) checks, M \(hex(own.value)), payload \(try JSONSerialization.data(withJSONObject:own.fields).count) bytes")
            return
        }
        if a.count==2 && a[1]=="--unsigned" {
            do {_=try Node(cfg,log:{_,_ in}).ownMeasurement();throw DemoError.invalid("unsigned executable measured")}
            catch DemoError.invalid(let m) {try check(m.hasPrefix("cannot measure this executable;"),"fail closed: \(m)")}
            print("MeasuredEnrollTests --unsigned passed: enrollment refused without a measurement");return
        }
        let d=URL(fileURLWithPath:a.count>1 ? a[1] : "contracts/fixtures/resign")
        let v=try JSONSerialization.jsonObject(with:Data(contentsOf:d.appendingPathComponent("measure-vectors.json"))) as! [String:Any]
        let o=try JSONSerialization.jsonObject(with:Data(contentsOf:d.appendingPathComponent("node-honest.json"))) as! [String:Any]
        let h={(k:String) in [UInt8](try unhex(o[k] as! String))}
        let x=CodeMeasurement(cd:try h("cd"),page0:try h("page0"),ent:try h("ent"),L:o["linkeditCmd"] as! Int,S:o["codeSigCmd"] as! Int)
        try check(hex(try x.value())==v["node"] as! String,"fixture M")
        try payload(x.enrollFields,x,check)

        // Same vector as node/relay-hosted/directory_test.ts (recordContext).
        let kid=Data(repeating:7,count:32),category=Data(repeating:0x22,count:32),member=keccak(category+kid)
        let session=Data([4])+Data(repeating:0x11,count:64),receipt=Data(repeating:0x77,count:32)
        func context(_ v2:(measurement:Data,label:String)?) throws -> String {
            hex(try NativeDirectoryEncoding.context(chainId:84532,registry:"0xd4b33c83576a6049d29c6b849ec73491e52781a0",category:category,member:member,session:session,
                issuedAt:1800000000,version:"0.3.0",build:12,scope:zero32,epoch:2,receipt:receipt,account:"0x"+String(repeating:"0",count:40),generation:0,v2:v2))
        }
        let m=Data(repeating:0x99,count:32)
        try check(try context((m,"mini-mesh"))=="0xf67b2597d4f39b6c878f6398e041a8134ac7a3a5ab1ecff073fa25dac96ab447","v2 context vector")
        try check(try context(nil)=="0x266bd99ec0d58414898fd2df13a2fd299c6813194a0a1d8f438a42d5ce778fbe","v1 context vector unchanged")
        try check(try context((m,"other")) != (try context((m,"mini-mesh"))),"label bound")
        try check(try context((Data(repeating:0x98,count:32),"mini-mesh")) != (try context((m,"mini-mesh"))),"measurement bound")

        try check(cfg.publicDirectory && cfg.label=="","public node lists by default, no label")
        var off=["rpc":"http://127.0.0.1:1","registry":"0xd4b33c83576a6049d29c6b849ec73491e52781a0","chainId":84532,"category":"0x"+String(repeating:"22",count:32),
                 "relay":"http://127.0.0.1:1","name":"seed","publicDirectory":false,"label":"mini mesh-1"] as [String:Any]
        let quiet=try Config(off)
        try check(!quiet.publicDirectory && quiet.label=="mini mesh-1","opt-out flag and label")
        try check(Node(cfg,log:{_,_ in}).directoryOptIn && !Node(quiet,log:{_,_ in}).directoryOptIn,"node starts with the configured listing state")
        for bad in ["<b>",String(repeating:"x",count:33)] {
            off["label"]=bad
            do {_=try Config(off);throw DemoError.invalid("label \(bad) accepted")} catch DemoError.invalid(let m) {try check(m.hasPrefix("label:"),m)}
        }
        print("MeasuredEnrollTests passed: \(checks) checks")
    }

    /// The enroll body carries {cd,page0,ent,L,S} next to the App Attest fields and fits the relay's 64 KiB limit.
    static func payload(_ fields:[String:Any],_ x:CodeMeasurement,_ check:(Bool,String) throws -> Void) throws {
        let body=Node.enrollBody(category:Data(repeating:0x22,count:32),attestation:Data(repeating:1,count:5600),clientData:Data(repeating:3,count:32),measurement:fields)
        try check(body.keys.sorted()==["L","S","attestation","category","cd","clientData","ent","page0"],"enroll keys \(body.keys.sorted())")
        let b64={(k:String) in [UInt8](Data(base64Encoded:body[k] as! String)!)}
        try check(b64("cd")==x.cd && b64("page0")==x.page0 && b64("ent")==x.ent && body["L"] as! Int==x.L && body["S"] as! Int==x.S,"blobs round trip")
        try check(x.page0.count==16384 && x.cd.count+x.ent.count+x.page0.count<24000,"about 17 KB of blobs")
        try check(try JSONSerialization.data(withJSONObject:body).count<65536,"enroll request under the relay limit")
    }
}
