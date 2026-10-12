import Foundation

// Usage: native-update-measured DIR RPC REGISTRY OWNER
// DIR holds honest-a/honest-b/modified .zip and .json from tests/native_update_measured.sh.
// RPC is a dev chain (anvil) with OWNER unlocked and MeasurementRegistry at REGISTRY.
@main struct MeasuredUpdateTests {
    static var checks=0
    static func refuses(_ name:String,_ reason:String,_ block:()throws->Void) {
        do {try block();fatalError("installed: \(name)")}
        catch {
            let text=error.localizedDescription
            precondition(text.contains(reason),"\(name): expected \"\(reason)\", got \"\(text)\"")
            print("refused  \(name): \(text)");checks+=1
        }
    }
    static func main()throws {
        let a=CommandLine.arguments,dir=URL(fileURLWithPath:a[1]),rpc=URL(string:a[2])!,registry=a[3],owner=a[4]
        let probe=Chain(rpcURL:rpc,registry:registry,chainId:0)
        let chain=Chain(rpcURL:rpc,registry:registry,chainId:try quantity(probe.rpc("eth_chainId",[])))
        let admission=MeasurementAdmission(chain:chain)
        let root=dir.appendingPathComponent("releases",isDirectory:true)
        func feed(_ n:String,_ edit:(inout [String:Any])->Void={_ in})throws->NodeUpdateFeed {
            var d=try JSONSerialization.jsonObject(with:Data(contentsOf:dir.appendingPathComponent(n+".json"))) as! [String:Any];edit(&d)
            return try NodeUpdateFeed(data:JSONSerialization.data(withJSONObject:d))
        }
        func zip(_ n:String)->URL {dir.appendingPathComponent(n+".zip")}
        func send(_ signature:String,_ words:Data)throws {
            _=try chain.rpc("eth_sendTransaction",[["from":owner,"to":registry,"data":hex(keccak(Data(signature.utf8)).prefix(4)+words)]])
        }
        func install(_ n:String,_ f:NodeUpdateFeed)throws->UpdateVerdict {try NativeUpdater.install(zip:zip(n),feed:f,admission:admission,root:root).1}
        let honest=try feed("honest-a"),M=honest.M
        let mb=try feed("honest-b").M,mm=try feed("modified").M
        precondition(mb==M && mm != M,"fixture measurements")

        refuses("admitted build before its window opens","Build not admitted"){_=try install("honest-a",honest)}
        try send("admit(bytes32,uint64,uint64)",M+word(0)+word(UInt64(Int64.max)))
        let va=try install("honest-a",honest)
        print("installs honest-a: team \(va.team) \(va.identifier) M \(hex(va.M)) block \(va.block)");checks+=1
        let vb=try install("honest-b",try feed("honest-b"))
        precondition(vb.M==va.M && vb.team != va.team && vb.cdhash != va.cdhash,"second team, same M, different CDHash")
        print("installs honest-b: team \(vb.team) \(vb.identifier) M \(hex(vb.M))");checks+=1
        let app=root.appendingPathComponent("\(honest.tag)-\(honest.sha256.prefix(12))/unpacked/Node.app/Contents/MacOS/node")
        precondition(FileManager.default.fileExists(atPath:app.path),"installed under root");checks+=1
        let again=try install("honest-a",honest)
        precondition(again.cdhash==va.cdhash,"reinstall re-verifies the staged copy");checks+=1

        refuses("modified build, its own M","Build not admitted"){_=try install("modified",try feed("modified"))}
        refuses("modified build under the admitted M's feed","not the"){_=try install("modified",try feed("modified"){$0["M"]=hex(M)})}
        refuses("sha256 mismatch","SHA-256 differs"){_=try install("honest-a",try feed("honest-a"){$0["sha256"]=String(repeating:"0",count:64)})}
        refuses("feed for the other team's zip","SHA-256 differs"){_=try install("honest-a",try feed("honest-b"))}
        refuses("registry unreachable","Cannot read the measurement registry"){
            _=try NativeUpdater.install(zip:zip("honest-b"),feed:try feed("honest-b"),admission:MeasurementAdmission(chain:Chain(rpcURL:URL(string:"http://127.0.0.1:9")!,registry:registry,chainId:chain.chainId)),root:dir.appendingPathComponent("unreachable"))
        }
        refuses("RPC on another chain","not \(chain.chainId+1)"){
            _=try NativeUpdater.install(zip:zip("honest-b"),feed:try feed("honest-b"),admission:MeasurementAdmission(chain:Chain(rpcURL:rpc,registry:registry,chainId:chain.chainId+1)),root:dir.appendingPathComponent("wrong-chain"))
        }
        let block=try quantity(chain.rpc("eth_blockNumber",[]))
        try send("admit(bytes32,uint64,uint64)",M+word(0)+word(block+100))
        refuses("window closes within a day","closes within"){_=try install("honest-a",honest)}
        try send("revoke(bytes32)",M)
        refuses("revoked measurement","Build not admitted"){_=try install("honest-a",honest)}
        print("PASS \(checks) measured update checks")
    }
}
