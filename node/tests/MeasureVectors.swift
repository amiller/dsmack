import Foundation

// Shared vectors with tests/test_measure.py and contracts/test/CodeMeasurement.t.sol.
// MeasureVectors [fixtures dir]  |  MeasureVectors --file <Mach-O>  |  MeasureVectors --self (measures after a stdin line)
@main struct MeasureVectors {
    static func main() throws {
        let a=CommandLine.arguments
        if a.count==3 && a[1]=="--file" {return try show(CodeMeasurement.of(executable:URL(fileURLWithPath:a[2])))}
        if a.count==2 && a[1]=="--self" {_=readLine();return try show(CodeMeasurement.ofSelf())}
        let d=URL(fileURLWithPath:a.count>1 ? a[1] : "contracts/fixtures/resign")
        let v=try JSONSerialization.jsonObject(with:Data(contentsOf:d.appendingPathComponent("measure-vectors.json"))) as! [String:Any]
        func load(_ n:String) throws -> CodeMeasurement {
            let j=d.appendingPathComponent(n+".json")
            if FileManager.default.fileExists(atPath:j.path) {
                let o=try JSONSerialization.jsonObject(with:Data(contentsOf:j)) as! [String:Any]
                let h={(k:String) in [UInt8](try unhex(o[k] as! String))}
                return CodeMeasurement(cd:try h("cd"),page0:try h("page0"),ent:try h("ent"),L:o["linkeditCmd"] as! Int,S:o["codeSigCmd"] as! Int)
            }
            let f={(e:String) in [UInt8](try Data(contentsOf:d.appendingPathComponent(n+e)))}
            return CodeMeasurement(cd:try f(".cd"),page0:try f(".page0"),ent:try f(".ent"),L:v["L"] as! Int,S:v["S"] as! Int)
        }
        for (names,key) in [("probeSame","probe"),("nodeSame","node")] {
            for n in v[names] as! [String] {try need(hex(try load(n).value())==v[key] as! String,"vector \(n)")}
        }
        try need(hex(try load("M-modified").value())==v["probeModified"] as! String,"vector M-modified")
        try need(hex(try load("node-modified").value())==v["nodeModified"] as! String,"vector node-modified")
        try need(v["node"] as! String != v["nodeModified"] as! String,"modified must differ")
        for (n,reason) in v["rejected"] as! [String:String] {
            do {_=try load(n).value();fatalError("\(n) must be rejected")}
            catch DemoError.invalid(let m) {try need(m==reason,"\(n): \(m) != \(reason)")}
        }
        print("CodeMeasurement vectors passed: probe \(v["probe"]!), node \(v["node"]!), modified differ, \((v["rejected"] as! [String:String]).count) rejected")
    }
    static func show(_ x:CodeMeasurement) throws {
        print(String(decoding:try JSONSerialization.data(withJSONObject:["cdhash":hex(Data(CodeMeasurement.sha(x.cd))),"M":hex(try x.value()),"L":x.L,"S":x.S],options:[.sortedKeys]),as:UTF8.self))
    }
}
