import Foundation

@main struct UpdateTests {
    static var checks=0
    static func check(_ condition:Bool,_ name:String) {precondition(condition,name);checks+=1}
    static func rejects(_ name:String,_ block:()throws->Void) {do {try block();fatalError("accepted: \(name)")}catch{checks+=1}}
    static func main()throws {
        let directory=URL(fileURLWithPath:CommandLine.arguments[1])
        let base:[String:Any]=["version":"0.2.1","tag":"node-v0.2.1","url":"https://github.com/amiller/dsmack/releases/download/node-v0.2.1/Dsmack-Node-0.2.1.zip","sha256":String(repeating:"a",count:64),"M":"0x"+String(repeating:"b",count:64),"notes":"Fixes."]
        func parse(_ d:[String:Any])throws->NodeUpdateFeed {try NodeUpdateFeed(data:JSONSerialization.data(withJSONObject:d))}
        let feed=try parse(base)
        check(feed.M.count==32 && feed.newer(than:"0.2.0") && feed.newer(than:"0.1.10") && !feed.newer(than:"0.2.1") && !feed.newer(than:"0.10.0"),"feed parses and orders versions")
        for (key,value) in [("version","0.2" as Any),("version","0.2.1-rc.1" as Any),("tag","node-v0.2.2" as Any),("tag","native-v0.2.1" as Any),("sha256","../bad" as Any),("sha256",String(repeating:"A",count:64) as Any),("M",String(repeating:"b",count:64) as Any),("M","0x1234" as Any),("notes",1 as Any),("notes",String(repeating:"x",count:4001) as Any)] {
            var d=base;d[key]=value;rejects("bad \(key)"){_=try parse(d)}
        }
        for url in ["http://github.com/amiller/dsmack/releases/download/node-v0.2.1/N.zip","https://example.com/N.zip","https://github.com/other/dsmack/releases/download/node-v0.2.1/N.zip","https://github.com/amiller/dsmack/releases/download/node-v0.2.0/N.zip","https://github.com/amiller/dsmack/releases/download/node-v0.2.1/sub/N.zip","https://user:pw@github.com/amiller/dsmack/releases/download/node-v0.2.1/N.zip","https://github.com/amiller/dsmack/releases/download/node-v0.2.1/N.zip?x=1","https://github.com/amiller/dsmack/releases/download/node-v0.2.1/N.tar"] {
            var d=base;d["url"]=url;rejects("untrusted url \(url)"){_=try parse(d)}
        }
        var extra=base;extra["build"]=7;rejects("unknown field"){_=try parse(extra)}
        var missing=base;missing.removeValue(forKey:"M");rejects("missing M"){_=try parse(missing)}
        for file in try FileManager.default.contentsOfDirectory(at:directory,includingPropertiesForKeys:nil) where file.pathExtension=="zip" {
            if file.lastPathComponent=="valid.zip" {try NativeUpdateArchive.validate(file);checks+=1}
            else {rejects(file.lastPathComponent){try NativeUpdateArchive.validate(file)}}
        }
        #if GUI
        check(!UpdateDownload.allowed(URL(string:"http://github.com/a")!),"HTTP redirect refused")
        check(!UpdateDownload.allowed(URL(string:"https://untrusted.example/a")!),"untrusted redirect refused")
        check(!UpdateDownload.allowed(URL(string:"https://user:secret@github.com/a")!),"credential redirect refused")
        check(UpdateDownload.allowed(URL(string:"https://release-assets.githubusercontent.com/a?sig=public")!),"GitHub release CDN accepted")
        check(UpdateDownload.allowed(NodeUpdateFeed.latest),"feed URL is an allowed host")
        let fake=directory.appendingPathComponent("fake.app");try FileManager.default.createDirectory(at:fake,withIntermediateDirectories:true)
        let admission=MeasurementAdmission(chain:Chain(rpcURL:URL(string:"http://127.0.0.1:9")!,registry:"0x"+String(repeating:"0",count:40),chainId:1))
        rejects("unsigned application"){_=try NativeUpdater.verify(fake,feed:feed,admission:admission)}
        // Until W7 adds measurementRegistry to NetworkConfig, every update is refused.
        if ReleaseNetwork.settings?["measurementRegistry"]==nil {
            do {_=try MeasurementAdmission.configured();fatalError("admission without a registry")}
            catch {check(error.localizedDescription.contains("no measurement registry configured"),"no registry refusal: \(error.localizedDescription)")}
        } else {check((try? MeasurementAdmission.configured()) != nil,"configured registry")}
        #endif
        print("PASS \(checks) native update feed/archive/refusal checks; no network action")
    }
}
