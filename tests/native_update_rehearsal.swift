// Explicit private qualification build only. build_mac.py never includes this file
// or defines UPDATE_REHEARSAL. No public discovery/admission claim is possible.
#if GUI && UPDATE_REHEARSAL
import Foundation

enum NativeUpdateRehearsal {
    static let root=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("agent-drop/dsmack-updater-20261011/rehearsal",isDirectory:true)
    static let defaults=UserDefaults(suiteName:"dev.dsmack.update-rehearsal.20261011")!
    // An operator may create this marker only after qualifying the sealed isolated
    // network. It cannot substitute a network URL or alter the signed network pins.
    static var participationEnabled:Bool {
        guard let settings=ReleaseNetwork.settings,
              (settings["chainId"] as? NSNumber)?.intValue==31337,
              settings["registry"] as? String != "0x0000000000000000000000000000000000000000",
              let name=settings["name"] as? String,name.hasPrefix("update-rehearsal-") else {return false}
        return FileManager.default.fileExists(atPath:root.appendingPathComponent("enable-isolated-participation").path)
    }
    static func select(_ url:URL,to destination:URL,limit:Int)throws {
        guard UpdateDownload.allowed(url) else {throw NativeUpdateError("Untrusted artifact-selection URL.")}
        let source:URL
        if url==NativeUpdateRecommendation.discovery {source=root.appendingPathComponent("release.json")}
        else if url.absoluteString=="https://github.com/\(NativeUpdateRecommendation.repository)/releases/download/native-recommended/dsmack-update.json" {source=root.appendingPathComponent("recommendation.json")}
        else {source=root.appendingPathComponent("candidate.zip")}
        let attributes=try FileManager.default.attributesOfItem(atPath:source.path)
        guard let size=attributes[.size] as? NSNumber,size.intValue<=limit else {throw NativeUpdateError("Selected artifact exceeds the size limit.")}
        let bytes=try Data(contentsOf:source)
        guard bytes.count<=limit else {throw NativeUpdateError("Selected artifact exceeds the size limit.")}
        try bytes.write(to:destination,options:.atomic)
    }
}
#endif
