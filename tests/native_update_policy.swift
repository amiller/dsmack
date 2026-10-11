import Foundation

@main struct UpdateTests {
    static var checks=0
    static func check(_ condition:Bool,_ name:String) {precondition(condition,name);checks+=1}
    static func rejects(_ name:String,_ block:()throws->Void) {do {try block();fatalError("accepted: \(name)")}catch{checks+=1}}
    static func main()throws {
        let directory=URL(fileURLWithPath:CommandLine.arguments[1]),now=Date(timeIntervalSince1970:1_800_000_000)
        let network=Dictionary(uniqueKeysWithValues:NativeUpdateRecommendation.networkKeys.map{($0,$0)})
        var base:[String:Any]=["format":1,"tag":"native-v1.2.3","version":"1.2.3","build":5,"archive":"https://github.com/amiller/dsmack/releases/download/native-v1.2.3/Node.zip","sha256":String(repeating:"a",count:64),"bytes":2048,"expires":ISO8601DateFormatter().string(from:now.addingTimeInterval(3600)),"network":network,"previousBuilds":[4],"rollbackBuilds":[4],"qualification":"release-owner-qualified","evidence":"https://github.com/amiller/dsmack/releases/tag/native-v1.2.3"]
        func parse(_ d:[String:Any],highest:Int=4)throws->NativeUpdateRecommendation {try NativeUpdateRecommendation(data:JSONSerialization.data(withJSONObject:d),currentBuild:4,highestBuild:highest,network:network,now:now)}
        check(try parse(base).build==5,"valid owner recommendation")
        let current=try NativeUpdateRecommendation(data:JSONSerialization.data(withJSONObject:base),currentBuild:5,highestBuild:5,network:network,now:now,allowCurrent:true)
        check(current.build==5,"current recommendation has explicit up-to-date path")
        for (key,value) in [("build",4 as Any),("build",3 as Any),("build",true as Any),("build",5.5 as Any),("bytes",250_000_001 as Any),("sha256","../bad" as Any),("qualification","chain-verified" as Any),("previousBuilds",[3] as Any),("previousBuilds",[4,4] as Any),("previousBuilds",[true] as Any),("network",["chainId":"other"] as Any),("expires",ISO8601DateFormatter().string(from:now.addingTimeInterval(-1)) as Any),("expires",ISO8601DateFormatter().string(from:now.addingTimeInterval(8*86400)) as Any),("tag","../escape" as Any)] {
            var d=base;d[key]=value;rejects("bad \(key)"){_=try parse(d)}
        }
        for url in ["http://github.com/amiller/dsmack/releases/download/native-v1.2.3/Node.zip","https://example.com/Node.zip","https://github.com/other/repo/releases/download/native-v1.2.3/Node.zip","https://github.com/amiller/dsmack/releases/download/native-v1.2.2/Node.zip","https://github.com/amiller/dsmack/releases/download/native-v1.2.3/sub/Node.zip","https://user:password@github.com/amiller/dsmack/releases/download/native-v1.2.3/Node.zip","https://github.com/amiller/dsmack/releases/download/native-v1.2.3/Node.zip?redirect=1"] {
            var d=base;d["archive"]=url;rejects("untrusted archive"){_=try parse(d)}
        }
        rejects("replay below highest verified build"){_=try parse(base,highest:6)}
        base["unknown"]=true;rejects("unknown recommendation field"){_=try parse(base)}
        for file in try FileManager.default.contentsOfDirectory(at:directory,includingPropertiesForKeys:nil) where file.pathExtension=="zip" {
            let size=try Data(contentsOf:file).count
            if file.lastPathComponent=="valid.zip" {try NativeUpdateArchive.validate(file,expectedBytes:size);checks+=1;rejects("short download"){try NativeUpdateArchive.validate(file,expectedBytes:size+1)}}
            else {rejects(file.lastPathComponent){try NativeUpdateArchive.validate(file,expectedBytes:size)}}
        }
        #if GUI
        check(!UpdateDownload.allowed(URL(string:"http://github.com/a")!),"HTTP redirect refused")
        check(!UpdateDownload.allowed(URL(string:"https://untrusted.example/a")!),"untrusted redirect refused")
        check(!UpdateDownload.allowed(URL(string:"https://user:secret@github.com/a")!),"credential redirect refused")
        check(UpdateDownload.allowed(URL(string:"https://release-assets.githubusercontent.com/a?sig=public")!),"GitHub release CDN accepted")
        func assessment(_ override:String?=nil,_ verdict:Bool=true,_ source:String="Notarized Developer ID")throws->Data {
            var authority:[String:Any]=["assessment:authority:source":source]
            if let override {authority["assessment:authority:override"]=override}
            return try PropertyListSerialization.data(fromPropertyList:["assessment:verdict":verdict,"assessment:authority":authority],format:.xml,options:0)
        }
        check(try NativeUpdater.acceptsAssessment(assessment()),"enforced notarized authority")
        check(try !NativeUpdater.acceptsAssessment(assessment("security disabled")),"disabled security never qualifies")
        check(try !NativeUpdater.acceptsAssessment(assessment(nil,false)),"negative assessment refused")
        check(try !NativeUpdater.acceptsAssessment(assessment(nil,true,"Developer ID")),"unnotarized authority refused")
        check(!NativeUpdater.acceptsAssessment(Data("not a plist".utf8)),"malformed assessment refused")
        let fake=directory.appendingPathComponent("fake.app");try FileManager.default.createDirectory(at:fake,withIntermediateDirectories:true)
        var valid=base;valid.removeValue(forKey:"unknown")
        rejects("unsigned application"){try NativeUpdater.verify(fake,relativeTo:fake,recommendation:parse(valid))}
        #endif
        print("PASS \(checks) native update policy/archive/refusal checks; no update launch or network action")
    }
}
