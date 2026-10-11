#if GUI
import AppKit
import CryptoKit
import Security
import Darwin

final class UpdateDownload: NSObject, URLSessionDataDelegate {
    let destination:URL, limit:Int
    let done=DispatchSemaphore(value:0)
    var file:FileHandle?, received=0, failure:Error?, status=0
    init(_ destination:URL,limit:Int) {self.destination=destination;self.limit=limit}
    static func allowed(_ url:URL)->Bool {
        url.scheme=="https" && url.user==nil && url.password==nil && url.fragment==nil && ["api.github.com","github.com","release-assets.githubusercontent.com","objects.githubusercontent.com"].contains(url.host ?? "")
    }
    func urlSession(_ session:URLSession,task:URLSessionTask,willPerformHTTPRedirection response:HTTPURLResponse,newRequest request:URLRequest,completionHandler:@escaping(URLRequest?)->Void) {
        guard let url=request.url,Self.allowed(url) else {failure=NativeUpdateError("The update redirected outside its trusted download hosts.");completionHandler(nil);return}
        completionHandler(request)
    }
    func urlSession(_ session:URLSession,dataTask:URLSessionDataTask,didReceive response:URLResponse,completionHandler:@escaping(URLSession.ResponseDisposition)->Void) {
        status=(response as? HTTPURLResponse)?.statusCode ?? 0
        guard status==200,response.expectedContentLength<=Int64(limit) else {failure=NativeUpdateError(status==404 ? "No recommended update is published yet.":"The update server refused the request or exceeded the size limit.");completionHandler(.cancel);return}
        completionHandler(.allow)
    }
    func urlSession(_ session:URLSession,dataTask:URLSessionDataTask,didReceive data:Data) {
        received+=data.count
        guard received<=limit else {failure=NativeUpdateError("The update exceeds the download size limit.");dataTask.cancel();return}
        do {try file?.write(contentsOf:data)}catch{failure=error;dataTask.cancel()}
    }
    func urlSession(_ session:URLSession,task:URLSessionTask,didCompleteWithError error:Error?) {if failure==nil {failure=error};try? file?.close();done.signal()}
    static func fetch(_ url:URL,to destination:URL,limit:Int,seconds:Double) throws {
        #if UPDATE_REHEARSAL
        // Compile-only artifact selection; never included in a public release.
        try NativeUpdateRehearsal.select(url,to:destination,limit:limit)
        return
        #else
        guard allowed(url) else {throw NativeUpdateError("Untrusted update URL.")}
        let worker=UpdateDownload(destination,limit:limit)
        guard FileManager.default.createFile(atPath:destination.path,contents:nil,attributes:[.posixPermissions:0o600]) else {throw NativeUpdateError("Cannot create the update download.")}
        worker.file=try FileHandle(forWritingTo:destination)
        let configuration=URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest=min(seconds,30);configuration.timeoutIntervalForResource=seconds
        configuration.httpCookieStorage=nil;configuration.urlCache=nil;configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let queue=OperationQueue();queue.maxConcurrentOperationCount=1
        let session=URLSession(configuration:configuration,delegate:worker,delegateQueue:queue)
        var request=URLRequest(url:url);request.setValue("Dsmack-updater/1",forHTTPHeaderField:"User-Agent");request.setValue("application/json, application/octet-stream",forHTTPHeaderField:"Accept")
        let task=session.dataTask(with:request);task.resume()
        if worker.done.wait(timeout:.now()+seconds+2) == .timedOut {task.cancel();session.invalidateAndCancel();throw NativeUpdateError("Update download timed out. Your installed app is unchanged.")}
        session.finishTasksAndInvalidate()
        if let failure=worker.failure {throw failure}
        #endif
    }
}

struct NativeInstalledRelease {
    let build:Int, version:String, network:[String:String]
    static func read(_ app:URL) throws -> Self {
        let info=try PropertyListSerialization.propertyList(from:Data(contentsOf:app.appendingPathComponent("Contents/Info.plist")),format:nil) as? [String:Any]
        let data=try Data(contentsOf:app.appendingPathComponent("Contents/Resources/dsmack-release.json"))
        guard data.count<=65536,let d=try JSONSerialization.jsonObject(with:data) as? [String:Any] else {throw NativeUpdateError("Signed release metadata is missing.")}
        try NativeUpdateRecommendation.exactKeys(d,["format","profile","build","version","network","sourceCommit"])
        guard NativeUpdateRecommendation.integer(d["format"])==1,d["profile"] as? String=="native-v2",
              let build=NativeUpdateRecommendation.integer(d["build"]),let version=d["version"] as? String,
              info?["CFBundleVersion"] as? String==String(build),info?["CFBundleShortVersionString"] as? String==version,
              let network=d["network"] as? [String:String],Set(network.keys)==Set(NativeUpdateRecommendation.networkKeys),
              let source=d["sourceCommit"] as? String,source.range(of:"^[0-9a-f]{40}$",options:.regularExpression) != nil else {throw NativeUpdateError("Signed release metadata does not match the application.")}
        return Self(build:build,version:version,network:network)
    }
}

final class NativeUpdater {
    static let shared=NativeUpdater()
    private let fm=FileManager.default
    private(set) var busy=false
    private var prepared:URL?
    private var recommendation:NativeUpdateRecommendation?
    private var recommendationData:Data?
    private var current:URL {Bundle.main.bundleURL.resolvingSymlinksInPath()}
    private var root:URL {
        #if UPDATE_REHEARSAL
        return NativeUpdateRehearsal.root.appendingPathComponent("releases",isDirectory:true)
        #else
        return fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Dsmack Releases",isDirectory:true)
        #endif
    }
    private var defaults:UserDefaults {
        #if UPDATE_REHEARSAL
        return NativeUpdateRehearsal.defaults
        #else
        return UserDefaults.standard
        #endif
    }
    static func sha256(_ url:URL)throws->String {
        let handle=try FileHandle(forReadingFrom:url);defer{try? handle.close()};var digest=SHA256()
        while let data=try handle.read(upToCount:1024*1024),!data.isEmpty {digest.update(data:data)}
        return digest.finalize().map{String(format:"%02x",$0)}.joined()
    }
    private static func command(_ executable:String,_ arguments:[String],seconds:Double=30)throws {
        let process=Process();process.executableURL=URL(fileURLWithPath:executable);process.arguments=arguments
        process.standardOutput=FileHandle.nullDevice;process.standardError=FileHandle.nullDevice
        let finished=DispatchSemaphore(value:0);process.terminationHandler={_ in finished.signal()};try process.run()
        if finished.wait(timeout:.now()+seconds) == .timedOut {process.terminate();throw NativeUpdateError("Application verification timed out.")}
        guard process.terminationStatus==0 else {throw NativeUpdateError("Application verification or installation was refused.")}
    }
    private static func code(_ app:URL)throws->SecStaticCode {
        var code:SecStaticCode?
        guard SecStaticCodeCreateWithPath(app as CFURL,[],&code)==errSecSuccess,let code else {throw NativeUpdateError("Cannot inspect the application signature.")}
        return code
    }
    private static func signing(_ code:SecStaticCode)throws->[String:Any] {
        var info:CFDictionary?
        guard SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&info)==errSecSuccess,let result=info as? [String:Any] else {throw NativeUpdateError("Cannot inspect signing identity.")}
        return result
    }
    static func acceptsAssessment(_ assessment:Data)->Bool {
        guard assessment.count<=65536,
              let verdict=(try? PropertyListSerialization.propertyList(from:assessment,format:nil)) as? [String:Any],
              verdict["assessment:verdict"] as? Bool==true,
              let authority=verdict["assessment:authority"] as? [String:Any],authority["assessment:authority:override"]==nil,
              authority["assessment:authority:source"] as? String=="Notarized Developer ID" else {return false}
        return true
    }
    static func verify(_ app:URL,relativeTo old:URL,recommendation r:NativeUpdateRecommendation)throws {
        let candidate=try code(app),original=try code(old)
        let flags=SecCSFlags(rawValue:kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode)
        guard SecStaticCodeCheckValidity(original,flags,nil)==errSecSuccess else {throw NativeUpdateError("Your current application signature is invalid.")}
        var requirement:SecRequirement?
        guard SecCodeCopyDesignatedRequirement(original,[],&requirement)==errSecSuccess,let requirement,
              SecStaticCodeCheckValidity(candidate,flags,requirement)==errSecSuccess else {throw NativeUpdateError("The update does not match this application's signing requirement.")}
        let a=try signing(original),b=try signing(candidate)
        guard let team=a[kSecCodeInfoTeamIdentifier as String] as? String,!team.isEmpty,team==b[kSecCodeInfoTeamIdentifier as String] as? String,
              let identifier=a[kSecCodeInfoIdentifier as String] as? String,identifier==b[kSecCodeInfoIdentifier as String] as? String,
              let ae=a[kSecCodeInfoEntitlementsDict as String] as? NSDictionary,let be=b[kSecCodeInfoEntitlementsDict as String] as? NSDictionary,ae==be,
              (be["com.apple.security.get-task-allow"] as? Bool) != true else {throw NativeUpdateError("The update changes signing identity or identity-access permissions.")}
        // System assessment requires no developer tools. A disabled assessment does
        // not count as notarization evidence: require the specific notarized authority.
        let process=Process(),pipe=Pipe()
        process.executableURL=URL(fileURLWithPath:"/usr/sbin/spctl")
        process.arguments=["--assess","--type","execute","--raw","--enforce-assessment",app.path]
        process.standardOutput=pipe;process.standardError=FileHandle.nullDevice
        let done=DispatchSemaphore(value:0);process.terminationHandler={_ in done.signal()}
        try process.run()
        guard done.wait(timeout:.now()+30) == .success else {process.terminate();throw NativeUpdateError("Notarization assessment timed out.")}
        let assessment=pipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus==0,acceptsAssessment(assessment) else {throw NativeUpdateError("The update does not have an enforced notarized Developer ID assessment without overrides.")}
        let release=try NativeInstalledRelease.read(app)
        guard release.build==r.build,release.version==r.version,release.network==r.network else {throw NativeUpdateError("Signed app version, build or network differs from the recommendation.")}
    }
    private func protectedRoot()throws {
        try fm.createDirectory(at:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        guard root.standardizedFileURL==root.resolvingSymlinksInPath() else {throw NativeUpdateError("The update directory must not be a symbolic link.")}
    }
    func check(completion:@escaping(Result<NativeUpdateRecommendation?,Error>)->Void) {
        guard !busy else {completion(.failure(NativeUpdateError("An update is already in progress.")));return};busy=true
        DispatchQueue.global(qos:.utility).async {
            let result=Result<NativeUpdateRecommendation?,Error> {
                let installed=try NativeInstalledRelease.read(self.current)
                guard let settings=ReleaseNetwork.settings,try NativeUpdateRecommendation.network(settings)==installed.network else {throw NativeUpdateError("This build's signed network metadata is inconsistent.")}
                try self.protectedRoot()
                let work=self.root.appendingPathComponent(".check-"+UUID().uuidString,isDirectory:true)
                try self.fm.createDirectory(at:work,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer{try? self.fm.removeItem(at:work)}
                let release=work.appendingPathComponent("release.json")
                try UpdateDownload.fetch(NativeUpdateRecommendation.discovery,to:release,limit:65536,seconds:20)
                guard let d=try JSONSerialization.jsonObject(with:Data(contentsOf:release)) as? [String:Any],d["draft"] as? Bool==false,d["tag_name"] as? String=="native-recommended",let assets=d["assets"] as? [[String:Any]] else {throw NativeUpdateError("No trusted recommendation is published.")}
                let manifests=assets.filter{$0["name"] as? String=="dsmack-update.json"}
                guard manifests.count==1,let raw=manifests[0]["browser_download_url"] as? String,raw=="https://github.com/\(NativeUpdateRecommendation.repository)/releases/download/native-recommended/dsmack-update.json",let url=URL(string:raw) else {throw NativeUpdateError("The recommendation asset is missing or ambiguous.")}
                let path=work.appendingPathComponent("recommendation.json")
                try UpdateDownload.fetch(url,to:path,limit:65536,seconds:20)
                let bytes=try Data(contentsOf:path)
                let r=try NativeUpdateRecommendation(data:bytes,currentBuild:installed.build,highestBuild:self.defaults.integer(forKey:"DsmackHighestOfferedBuild"),network:installed.network,allowCurrent:true)
                if r.build==installed.build {
                    guard r.version==installed.version else {throw NativeUpdateError("The current build has conflicting version metadata.")}
                    self.recommendation=nil;self.recommendationData=nil;return nil
                }
                self.recommendationData=bytes;self.recommendation=r
                return r
            }
            DispatchQueue.main.async {self.busy=false;completion(result)}
        }
    }
    func stage(completion:@escaping(Result<URL,Error>)->Void) {
        guard !busy,let r=recommendation,let bytes=recommendationData else {completion(.failure(NativeUpdateError("Check for an update first.")));return};busy=true
        DispatchQueue.global(qos:.utility).async {
            let result=Result<URL,Error> {
                guard r.expires>Date() else {throw NativeUpdateError("The release recommendation expired. Check again." )}
                try self.protectedRoot()
                let destination=self.root.appendingPathComponent("Build-\(r.build)-"+r.sha256.prefix(12),isDirectory:true)
                if self.fm.fileExists(atPath:destination.path) {
                    let existing=destination.appendingPathComponent("unpacked/Node.app",isDirectory:true)
                    try Self.verify(existing,relativeTo:self.current,recommendation:r)
                    try bytes.write(to:destination.appendingPathComponent("recommendation.json"),options:.atomic)
                    self.prepared=existing;return existing
                }
                let work=self.root.appendingPathComponent(".incoming-"+UUID().uuidString,isDirectory:true)
                try self.fm.createDirectory(at:work,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
                var retained=false;defer{if !retained {try? self.fm.removeItem(at:work)}}
                let zip=work.appendingPathComponent("release.zip")
                try UpdateDownload.fetch(r.archive,to:zip,limit:r.bytes,seconds:180)
                guard try Self.sha256(zip)==r.sha256 else {throw NativeUpdateError("The update checksum does not match. Your app is unchanged.")}
                try NativeUpdateArchive.validate(zip,expectedBytes:r.bytes)
                let unpack=work.appendingPathComponent("unpacked",isDirectory:true)
                try self.fm.createDirectory(at:unpack,withIntermediateDirectories:false)
                try Self.command("/usr/bin/ditto",["-x","-k",zip.path,unpack.path],seconds:60)
                let app=unpack.appendingPathComponent("Node.app",isDirectory:true)
                try Self.verify(app,relativeTo:self.current,recommendation:r)
                guard !self.fm.fileExists(atPath:destination.path) else {throw NativeUpdateError("This update is already staged. Use the retained installation or contact your release coordinator.")}
                try bytes.write(to:work.appendingPathComponent("recommendation.json"),options:.atomic)
                try self.fm.removeItem(at:zip)
                try self.fm.moveItem(at:work,to:destination);retained=true
                let installed=destination.appendingPathComponent("unpacked/Node.app",isDirectory:true)
                self.defaults.set(r.build,forKey:"DsmackHighestOfferedBuild")
                self.prepared=installed
                return installed
            }
            DispatchQueue.main.async {self.busy=false;completion(result)}
        }
    }
    func installAndRestart()throws {
        guard !busy,let app=prepared,let r=recommendation else {throw NativeUpdateError("No verified update is staged.")}
        guard r.expires.timeIntervalSinceNow>180 else {throw NativeUpdateError("The recommendation is expiring. Check for updates again before restarting.")}
        try Self.verify(app,relativeTo:current,recommendation:r)
        guard r.expires.timeIntervalSinceNow>150 else {throw NativeUpdateError("The recommendation expired during verification. Your peer remains running.")}
        let journal=app.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("handoff.json")
        let d:[String:Any]=["format":1,"oldApp":current.path,"newApp":app.path,"oldPID":Int(getpid()),"created":Date().timeIntervalSince1970,"oldExecutableSHA256":try Self.sha256(current.appendingPathComponent("Contents/MacOS/node")),"newExecutableSHA256":try Self.sha256(app.appendingPathComponent("Contents/MacOS/node"))]
        try JSONSerialization.data(withJSONObject:d,options:[.sortedKeys]).write(to:journal,options:.atomic)
        try fm.setAttributes([.posixPermissions:0o600],ofItemAtPath:journal.path)
        let helper=Process();helper.executableURL=current.appendingPathComponent("Contents/MacOS/node");helper.arguments=["--dsmack-finish-update",journal.path]
        helper.standardOutput=FileHandle.nullDevice;helper.standardError=FileHandle.nullDevice;try helper.run()
        // The helper runs no node protocol and waits for this process to release its lock.
        NSApp.terminate(nil)
    }
    static func finishHandoff(_ path:String)->Never {
        let updater=NativeUpdater.shared
        do {
            let journal=URL(fileURLWithPath:path).standardizedFileURL
            try updater.protectedRoot()
            guard journal.path.hasPrefix(updater.root.path+"/Build-"),journal.lastPathComponent=="handoff.json",journal==journal.resolvingSymlinksInPath() else {throw NativeUpdateError("Invalid update handoff.")}
            let raw=try Data(contentsOf:journal);guard raw.count<=16384,let d=try JSONSerialization.jsonObject(with:raw) as? [String:Any] else {throw NativeUpdateError("Invalid update handoff.")}
            try NativeUpdateRecommendation.exactKeys(d,["format","oldApp","newApp","oldPID","created","oldExecutableSHA256","newExecutableSHA256"])
            guard NativeUpdateRecommendation.integer(d["format"])==1,let oldPath=d["oldApp"] as? String,let newPath=d["newApp"] as? String,
                  let pid=NativeUpdateRecommendation.integer(d["oldPID"]),pid>1,let created=d["created"] as? Double,Date().timeIntervalSince1970-created>=0,Date().timeIntervalSince1970-created<120 else {throw NativeUpdateError("Expired update handoff.")}
            let old=URL(fileURLWithPath:oldPath).resolvingSymlinksInPath(),app=URL(fileURLWithPath:newPath).resolvingSymlinksInPath()
            guard old==Bundle.main.bundleURL.resolvingSymlinksInPath(),app==journal.deletingLastPathComponent().appendingPathComponent("unpacked/Node.app"),
                  try sha256(old.appendingPathComponent("Contents/MacOS/node"))==d["oldExecutableSHA256"] as? String,
                  try sha256(app.appendingPathComponent("Contents/MacOS/node"))==d["newExecutableSHA256"] as? String else {throw NativeUpdateError("Update applications changed during handoff.")}
            let installed=try NativeInstalledRelease.read(old)
            let r=try NativeUpdateRecommendation(data:Data(contentsOf:journal.deletingLastPathComponent().appendingPathComponent("recommendation.json")),currentBuild:installed.build,highestBuild:installed.build,network:installed.network)
            let deadline=Date().addingTimeInterval(90)
            while kill(pid_t(pid),0)==0 && Date()<deadline {Thread.sleep(forTimeInterval:0.2)}
            guard kill(pid_t(pid),0) != 0 else {throw NativeUpdateError("The previous peer did not quit; no replacement was launched.")}
            try verify(app,relativeTo:old,recommendation:r)
            // Never automatically launch the old build: its policy admission may have changed.
            try command("/usr/bin/open",["-n",app.path])
            let receipt:[String:Any]=["oldApp":old.path,"newApp":app.path,"oldExecutableSHA256":d["oldExecutableSHA256"]!,"rollbackOwnerQualified":r.rollbackBuilds.contains(installed.build),"openedAt":Date().timeIntervalSince1970,"networkAcceptance":"not-yet-qualified"]
            let saved=updater.root.appendingPathComponent("last-update.json")
            try JSONSerialization.data(withJSONObject:receipt,options:[.sortedKeys]).write(to:saved,options:.atomic)
            exit(0)
        } catch {
            // A helper spawned with Process is not activated by Launch Services.
            // Bring its recovery instructions forward after an OS launch refusal.
            let application=NSApplication.shared
            application.setActivationPolicy(.regular)
            application.activate(ignoringOtherApps:true)
            let alert=NSAlert();alert.messageText="Dsmack update could not finish";alert.informativeText="Your earlier app and identity data were retained. Open the earlier app only if your release coordinator confirms it is still admitted. \(error.localizedDescription)";alert.runModal();exit(1)
        }
    }
    func showRecovery() {
        let alert=NSAlert();alert.messageText="Recover a previous Dsmack version"
        alert.informativeText="Updates retain the previous signed app and never delete Application Support or Keychain data. A previous version can reconnect only if the release coordinator confirms it is still admitted. Do not reset your identity to retry. Show the retained releases and contact your coordinator if connection fails."
        alert.addButton(withTitle:"Show retained releases");alert.addButton(withTitle:"Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            let receipt=root.appendingPathComponent("last-update.json")
            if let data=try? Data(contentsOf:receipt),data.count<=16384,
               let d=try? JSONSerialization.jsonObject(with:data) as? [String:Any],
               let oldPath=d["oldApp"] as? String,let expected=d["oldExecutableSHA256"] as? String {
                let old=URL(fileURLWithPath:oldPath)
                if (try? Self.sha256(old.appendingPathComponent("Contents/MacOS/node")))==expected {
                    NSWorkspace.shared.activateFileViewerSelecting([old]);return
                }
            }
            NSWorkspace.shared.open(root)
        }
    }
}
#endif
