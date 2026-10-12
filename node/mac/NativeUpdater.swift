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
        guard status==200,response.expectedContentLength<=Int64(limit) else {failure=NativeUpdateError(status==404 ? "The latest release has no updates.json.":"The update server refused the request or exceeded the size limit.");completionHandler(.cancel);return}
        completionHandler(.allow)
    }
    func urlSession(_ session:URLSession,dataTask:URLSessionDataTask,didReceive data:Data) {
        received+=data.count
        guard received<=limit else {failure=NativeUpdateError("The update exceeds the download size limit.");dataTask.cancel();return}
        do {try file?.write(contentsOf:data)}catch{failure=error;dataTask.cancel()}
    }
    func urlSession(_ session:URLSession,task:URLSessionTask,didCompleteWithError error:Error?) {if failure==nil {failure=error};try? file?.close();done.signal()}
    static func fetch(_ url:URL,to destination:URL,limit:Int,seconds:Double) throws {
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
    }
}


/// What verification established about a candidate app.
struct UpdateVerdict {
    let M:Data, cdhash:Data, team:String, identifier:String, version:String, block:UInt64
}
struct UpdateCheck {
    let feed:NodeUpdateFeed, installed:String, admission:Result<UInt64,Error>
    var newer:Bool {feed.newer(than:installed)}
}

final class NativeUpdater {
    static let shared=NativeUpdater()
    static let root=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Dsmack Releases",isDirectory:true)
    private let fm=FileManager.default
    private(set) var busy=false
    private(set) var offered:NodeUpdateFeed?
    private(set) var prepared:(app:URL,feed:NodeUpdateFeed,verdict:UpdateVerdict)?
    private var current:URL {Bundle.main.bundleURL.resolvingSymlinksInPath()}

    static func sha256(_ url:URL)throws->String {
        let handle=try FileHandle(forReadingFrom:url);defer{try? handle.close()};var digest=SHA256()
        while let data=try handle.read(upToCount:1024*1024),!data.isEmpty {digest.update(data:data)}
        return digest.finalize().map{String(format:"%02x",$0)}.joined()
    }
    static func version(_ app:URL)throws->String {
        let info=try PropertyListSerialization.propertyList(from:Data(contentsOf:app.appendingPathComponent("Contents/Info.plist")),format:nil) as? [String:Any]
        guard let version=info?["CFBundleShortVersionString"] as? String else {throw NativeUpdateError("The application has no version.")}
        return version
    }
    static func cdhash(_ app:URL)throws->Data {Data(CodeMeasurement.sha(try CodeMeasurement.of(executable:app.appendingPathComponent("Contents/MacOS/node")).cd))}
    private static func command(_ executable:String,_ arguments:[String],seconds:Double=30)throws {
        let process=Process();process.executableURL=URL(fileURLWithPath:executable);process.arguments=arguments
        process.standardOutput=FileHandle.nullDevice;process.standardError=FileHandle.nullDevice
        let finished=DispatchSemaphore(value:0);process.terminationHandler={_ in finished.signal()};try process.run()
        if finished.wait(timeout:.now()+seconds) == .timedOut {process.terminate();throw NativeUpdateError("\(executable) timed out.")}
        guard process.terminationStatus==0 else {throw NativeUpdateError("\(executable) failed (\(process.terminationStatus)).")}
    }

    /// Any team's valid signature is enough to launch; MeasurementRegistry decides on the code.
    static func verify(_ app:URL,feed:NodeUpdateFeed,admission:MeasurementAdmission)throws->UpdateVerdict {
        var code:SecStaticCode?,info:CFDictionary?
        guard SecStaticCodeCreateWithPath(app as CFURL,[],&code)==errSecSuccess,let code else {throw NativeUpdateError("Cannot read the update's code signature.")}
        let status=SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode),nil)
        guard status==errSecSuccess else {throw NativeUpdateError("The update's code signature is invalid (\(status)).")}
        guard SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&info)==errSecSuccess,let d=info as? [String:Any],
              let validated=(d["cdhashes-full"] as? NSDictionary)?[NSNumber(value:2)] as? Data else {throw NativeUpdateError("Cannot read the update's CDHash.")}
        let x=try CodeMeasurement.of(executable:app.appendingPathComponent("Contents/MacOS/node"))
        guard Data(CodeMeasurement.sha(x.cd))==validated else {throw NativeUpdateError("The executable's CodeDirectory is not the one macOS validated.")}
        let m=try x.value()
        guard m==feed.M else {throw NativeUpdateError("The download measures \(hex(m)), not the \(hex(feed.M)) in updates.json.")}
        let v=try Self.version(app)
        guard v==feed.version else {throw NativeUpdateError("The app says version \(v), updates.json says \(feed.version).")}
        let block=try admission.check(m)
        return UpdateVerdict(M:m,cdhash:validated,team:d[kSecCodeInfoTeamIdentifier as String] as? String ?? "none",
                             identifier:d[kSecCodeInfoIdentifier as String] as? String ?? "none",version:v,block:block)
    }

    /// Checks a downloaded ZIP and installs its app under root/<tag>-<sha>/; launches nothing.
    static func install(zip:URL,feed:NodeUpdateFeed,admission:MeasurementAdmission,root:URL)throws->(URL,UpdateVerdict) {
        let fm=FileManager.default
        guard try sha256(zip)==feed.sha256 else {throw NativeUpdateError("The download's SHA-256 differs from updates.json.")}
        try NativeUpdateArchive.validate(zip)
        try fm.createDirectory(at:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        guard root.standardizedFileURL==root.resolvingSymlinksInPath() else {throw NativeUpdateError("The releases directory must not be a symbolic link.")}
        let destination=root.appendingPathComponent("\(feed.tag)-\(feed.sha256.prefix(12))",isDirectory:true)
        if fm.fileExists(atPath:destination.path) {
            let app=destination.appendingPathComponent("unpacked/Node.app")
            return (app,try verify(app,feed:feed,admission:admission))
        }
        let work=root.appendingPathComponent(".incoming-"+UUID().uuidString,isDirectory:true)
        try fm.createDirectory(at:work,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        var kept=false;defer{if !kept {try? fm.removeItem(at:work)}}
        try command("/usr/bin/ditto",["-x","-k",zip.path,work.appendingPathComponent("unpacked").path],seconds:60)
        let verdict=try verify(work.appendingPathComponent("unpacked/Node.app"),feed:feed,admission:admission)
        try feed.raw.write(to:work.appendingPathComponent("updates.json"))
        try fm.moveItem(at:work,to:destination);kept=true
        return (destination.appendingPathComponent("unpacked/Node.app"),verdict)
    }

    private func background<T>(_ body:@escaping()throws->T,_ completion:@escaping(Result<T,Error>)->Void) {
        guard !busy else {completion(.failure(NativeUpdateError("An update check is already running.")));return};busy=true
        DispatchQueue.global(qos:.utility).async {
            let result=Result(catching:body)
            DispatchQueue.main.async {self.busy=false;completion(result)}
        }
    }
    /// Reads the latest updates.json and asks the registry about its M.
    func check(completion:@escaping(Result<UpdateCheck,Error>)->Void) {
        background({
            let work=self.fm.temporaryDirectory.appendingPathComponent("dsmack-feed-"+UUID().uuidString)
            defer{try? self.fm.removeItem(at:work)}
            try UpdateDownload.fetch(NodeUpdateFeed.latest,to:work,limit:65536,seconds:20)
            let feed=try NodeUpdateFeed(data:Data(contentsOf:work))
            let result=UpdateCheck(feed:feed,installed:try Self.version(self.current),admission:Result{try MeasurementAdmission.configured().check(feed.M)})
            self.offered=result.newer ? feed:nil
            return result
        },completion)
    }
    func stage(completion:@escaping(Result<UpdateVerdict,Error>)->Void) {
        guard let feed=offered else {completion(.failure(NativeUpdateError("Check for updates first.")));return}
        background({
            let work=self.fm.temporaryDirectory.appendingPathComponent("dsmack-download-"+UUID().uuidString)
            defer{try? self.fm.removeItem(at:work)}
            try UpdateDownload.fetch(feed.url,to:work,limit:250_000_000,seconds:180)
            let (app,verdict)=try Self.install(zip:work,feed:feed,admission:MeasurementAdmission.configured(),root:Self.root)
            self.prepared=(app,feed,verdict)
            return verdict
        },completion)
    }
    /// Identity carries over only for the same team and bundle id (same Keychain group and App Attest key).
    func identityCarriesOver(_ v:UpdateVerdict)->Bool {
        var code:SecStaticCode?,info:CFDictionary?
        guard SecStaticCodeCreateWithPath(current as CFURL,[],&code)==errSecSuccess,let code,
              SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&info)==errSecSuccess,let d=info as? [String:Any] else {return false}
        return d[kSecCodeInfoTeamIdentifier as String] as? String==v.team && d[kSecCodeInfoIdentifier as String] as? String==v.identifier
    }
    /// The user's "Install and restart" is the consent; it is appended to Application Support/AttestNode/updates.json.
    func installAndRestart()throws {
        guard !busy,let p=prepared else {throw NativeUpdateError("No verified update is staged.")}
        let app=p.app,feed=p.feed
        let verdict=try Self.verify(app,feed:feed,admission:MeasurementAdmission.configured())
        let support=try fm.url(for:.applicationSupportDirectory,in:.userDomainMask,appropriateFor:nil,create:true).appendingPathComponent("AttestNode",isDirectory:true)
        try fm.createDirectory(at:support,withIntermediateDirectories:true)
        let log=support.appendingPathComponent("updates.json")
        var entries=(try? JSONSerialization.jsonObject(with:Data(contentsOf:log)) as? [[String:Any]]) ?? []
        entries.append(["time":Date().timeIntervalSince1970,"fromCdhash":hex(try Self.cdhash(current)),"toCdhash":hex(verdict.cdhash),"M":hex(verdict.M),"team":verdict.team,"feed":feed.url.absoluteString])
        try JSONSerialization.data(withJSONObject:entries,options:[.sortedKeys,.prettyPrinted]).write(to:log,options:.atomic)
        let journal=app.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("handoff.json")
        let d:[String:Any]=["format":2,"oldApp":current.path,"newApp":app.path,"oldPID":Int(getpid()),"created":Date().timeIntervalSince1970,"oldExecutableSHA256":try Self.sha256(current.appendingPathComponent("Contents/MacOS/node")),"newExecutableSHA256":try Self.sha256(app.appendingPathComponent("Contents/MacOS/node"))]
        try JSONSerialization.data(withJSONObject:d,options:[.sortedKeys]).write(to:journal,options:.atomic)
        try fm.setAttributes([.posixPermissions:0o600],ofItemAtPath:journal.path)
        let helper=Process();helper.executableURL=current.appendingPathComponent("Contents/MacOS/node");helper.arguments=["--dsmack-finish-update",journal.path]
        helper.standardOutput=FileHandle.nullDevice;helper.standardError=FileHandle.nullDevice;try helper.run()
        // The helper runs no node protocol and waits for this process to release its lock.
        NSApp.terminate(nil)
    }
    static func finishHandoff(_ path:String)->Never {
        do {
            let journal=URL(fileURLWithPath:path).standardizedFileURL,stage=journal.deletingLastPathComponent()
            guard stage.deletingLastPathComponent().path==root.standardizedFileURL.path,stage.lastPathComponent.hasPrefix("node-v"),journal.lastPathComponent=="handoff.json",journal==journal.resolvingSymlinksInPath() else {throw NativeUpdateError("Invalid update handoff.")}
            let raw=try Data(contentsOf:journal);guard raw.count<=16384,let d=try JSONSerialization.jsonObject(with:raw) as? [String:Any] else {throw NativeUpdateError("Invalid update handoff.")}
            guard d["format"] as? Int==2,let oldPath=d["oldApp"] as? String,let newPath=d["newApp"] as? String,let pid=d["oldPID"] as? Int,pid>1,
                  let created=d["created"] as? Double,Date().timeIntervalSince1970-created>=0,Date().timeIntervalSince1970-created<120 else {throw NativeUpdateError("Expired or invalid update handoff.")}
            let old=URL(fileURLWithPath:oldPath).resolvingSymlinksInPath(),app=URL(fileURLWithPath:newPath).resolvingSymlinksInPath()
            guard old==Bundle.main.bundleURL.resolvingSymlinksInPath(),app==stage.appendingPathComponent("unpacked/Node.app"),
                  try sha256(old.appendingPathComponent("Contents/MacOS/node"))==d["oldExecutableSHA256"] as? String,
                  try sha256(app.appendingPathComponent("Contents/MacOS/node"))==d["newExecutableSHA256"] as? String else {throw NativeUpdateError("Update applications changed during handoff.")}
            let feed=try NodeUpdateFeed(data:Data(contentsOf:stage.appendingPathComponent("updates.json")))
            let deadline=Date().addingTimeInterval(90)
            while kill(pid_t(pid),0)==0 && Date()<deadline {Thread.sleep(forTimeInterval:0.2)}
            guard kill(pid_t(pid),0) != 0 else {throw NativeUpdateError("The previous peer did not quit; no replacement was launched.")}
            _=try verify(app,feed:feed,admission:MeasurementAdmission.configured())
            // Never automatically launch the old build: its window may have closed.
            try command("/usr/bin/open",["-n",app.path])
            let receipt:[String:Any]=["oldApp":old.path,"newApp":app.path,"oldExecutableSHA256":d["oldExecutableSHA256"]!,"openedAt":Date().timeIntervalSince1970]
            try JSONSerialization.data(withJSONObject:receipt,options:[.sortedKeys]).write(to:root.appendingPathComponent("last-update.json"),options:.atomic)
            exit(0)
        } catch {
            // A helper spawned with Process is not activated by Launch Services.
            let application=NSApplication.shared
            application.setActivationPolicy(.regular)
            application.finishLaunching()
            DispatchQueue.main.async {
                application.activate(ignoringOtherApps:true)
                let alert=NSAlert();alert.messageText="Dsmack Node update could not finish";alert.informativeText="Your earlier app and identity data were kept. Open the earlier app only if its build is still admitted. \(error.localizedDescription)"
                alert.window.makeKeyAndOrderFront(nil)
                alert.runModal();exit(1)
            }
            application.run()
            exit(1)
        }
    }
    func showRecovery() {
        let alert=NSAlert();alert.messageText="Recover a previous Dsmack Node version"
        alert.informativeText="Updates keep the previous signed app and never delete Application Support or Keychain data. A previous version can reconnect only while its measurement is still admitted. Do not reset your identity to retry."
        alert.addButton(withTitle:"Show kept releases");alert.addButton(withTitle:"Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            let receipt=Self.root.appendingPathComponent("last-update.json")
            if let data=try? Data(contentsOf:receipt),data.count<=16384,
               let d=try? JSONSerialization.jsonObject(with:data) as? [String:Any],
               let oldPath=d["oldApp"] as? String,let expected=d["oldExecutableSHA256"] as? String {
                let old=URL(fileURLWithPath:oldPath)
                if (try? Self.sha256(old.appendingPathComponent("Contents/MacOS/node")))==expected {
                    NSWorkspace.shared.activateFileViewerSelecting([old]);return
                }
            }
            NSWorkspace.shared.open(Self.root)
        }
    }
}
#endif
