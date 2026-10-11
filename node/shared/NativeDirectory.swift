import Foundation
import CryptoKit

/// Public sharing is explicit and starts off. This state contains no group key.
final class NativeDirectoryState {
    private let lock=NSLock()
    private var enabled=false
    private var context:Data?
    var optedIn:Bool {lock.lock();defer{lock.unlock()};return enabled}
    func setEnabled(_ value:Bool){lock.lock();enabled=value;lock.unlock()}
    func setContext(_ value:Data){lock.lock();context=value;lock.unlock()}
    func leaveContext()->Data?{lock.lock();defer{lock.unlock()};let value=context;context=nil;return value}
}

enum NativeDirectoryEncoding {
    static func context(chainId:UInt64,registry:String,category:Data,member:Data,session:Data,issuedAt:UInt64,version:String,build:UInt64,scope:Data,epoch:UInt64,receipt:Data,account:String,generation:UInt64)throws->Data {
        try need([category,member,scope,receipt].allSatisfy{$0.count==32}&&session.count==65,"directory field widths")
        let parts:[Data]=[keccak(Data("DSMACK_NATIVE_DIRECTORY_CHECK_IN_V1".utf8)),word(chainId),try addressWord(registry),category,member,keccak(session),word(issuedAt),word(issuedAt+90),keccak(Data(version.utf8)),word(build),scope,word(epoch),receipt,try addressWord(account),word(generation)]
        let payload=parts.reduce(Data(),+)
        return keccak(payload)
    }
    static func accountPayload(chainId:UInt64,registry:String,member:Data,session:Data,account:String,generation:UInt64,context:Data)throws->Data {
        let parts:[Data]=[keccak(Data("DSMACK_DIRECTORY_ACCOUNT_CONSENT_V1".utf8)),word(chainId),try addressWord(registry),member,keccak(session),try addressWord(account),word(generation),context]
        return parts.reduce(Data(),+)
    }
    static func leavePayload(chainId:UInt64,registry:String,member:Data,session:Data,context:Data,at:UInt64)throws->Data {
        let parts:[Data]=[keccak(Data("DSMACK_NATIVE_DIRECTORY_LEAVE_V1".utf8)),word(chainId),try addressWord(registry),member,keccak(session),context,word(at)]
        return parts.reduce(Data(),+)
    }
}

extension Node {
    var directoryOptIn:Bool {directoryState.optedIn}
    /// Invoke through enqueueOperation from GUI; unrelated account operations stay serialized.
    func setDirectoryOptIn(_ enabled:Bool) {
        directoryState.setEnabled(enabled);nextDirectoryAttempt=Date.distantPast
        log("directory sharing changed",["enabled":enabled])
        if !enabled {requestDirectoryLeave({})}
    }
    func attemptDirectoryCheckIn() {
        guard directoryOptIn,Date()>=nextDirectoryAttempt,!keyID.isEmpty,me.count==32,cfg.protocolVersion==2 else {return}
        nextDirectoryAttempt=Date().addingTimeInterval(30)
        do {try directoryCheckIn()}
        catch {nextDirectoryAttempt=Date().addingTimeInterval(60);log("directory unavailable",["reasonCode":"CHECK_IN_FAILED"])}
    }
    func directoryCheckIn() throws {
        let version=Bundle.main.object(forInfoDictionaryKey:"CFBundleShortVersionString") as? String ?? "0"
        let buildText=Bundle.main.object(forInfoDictionaryKey:"CFBundleVersion") as? String ?? "0"
        try need(version.range(of:"^[0-9][A-Za-z0-9._-]{0,63}$",options:.regularExpression) != nil,"directory version")
        guard let build=UInt64(buildText),build<=2147483647,String(build)==buildText else {throw DemoError.invalid("directory build number")}
        let issued=UInt64(Date().timeIntervalSince1970)
        let epoch=try chain.keyEpoch(zero32,protocolVersion:cfg.protocolVersion)
        let receipt=directoryReceipt
        var personal:PersonalAccountKey?;var account:String?;var generation:UInt64=0
        // Lookups only: an absent key/account remains unbound, with no creation or mint.
        if let factory=cfg.accountFactory {
            personal=try PersonalAccountKey.loadExisting(chainId:cfg.chainId,factory:factory)
            if let personal {
                let candidate=try linkedAccount(personal)?.account ?? defaultPersonalAccount(personal)
                if try smallWord(chain.call("isAccount(address)",addressWord(candidate),to:factory))==1 {
                    try checkControl(candidate,key:personal);account=candidate.lowercased()
                    generation=try smallWord(chain.call("generation()",to:candidate))
                }
            }
        }
        let context=try NativeDirectoryEncoding.context(chainId:cfg.chainId,registry:cfg.registry,category:cfg.category,member:me,session:sessionPublic,issuedAt:issued,version:version,build:build,scope:zero32,epoch:epoch,receipt:receipt.map{try bytes32($0)} ?? zero32,account:account ?? "0x"+String(repeating:"0",count:40),generation:generation)
        var consent:Data?
        if let personal,let account {consent=try personal.directoryConsent(NativeDirectoryEncoding.accountPayload(chainId:cfg.chainId,registry:cfg.registry,member:me,session:sessionPublic,account:account,generation:generation,context:context))}
        let assertion=try appAttest(enroll:false,context)
        let body:[String:Any]=["member":hex(me),"keyId":keyID,"sessionPublic":hex(sessionPublic),"issuedAt":issued,"expiresAt":issued+90,
            "selfReported":version,"buildNumber":buildText,"scope":hex(zero32),"keyEpoch":String(epoch),"receiptTransaction":receipt as Any? ?? NSNull(),
            "account":account as Any? ?? NSNull(),"accountGeneration":String(generation),"accountSignature":consent.map{hex($0)} as Any? ?? NSNull(),"assertion":assertion.base64EncodedString()]
        try need(directoryOptIn,"directory sharing is off")
        let response=try directoryHTTP("directory/check-in",body,timeout:15)
        try need(response["accepted"] as? Bool == true && response["context"] as? String == hex(context),"directory response")
        directoryState.setContext(context)
        if !directoryOptIn {requestDirectoryLeave({});return}
        let publicID=try keccak(word(cfg.chainId)+addressWord(cfg.registry)+me)
        log("directory checked in",["member":hex(me),"id":hex(publicID),"expiresAt":response["expiresAt"] ?? "","account":response["account"] ?? NSNull(),"admittedCodeHash":response["admittedCodeHash"] ?? "","syncStatus":response["syncStatus"] ?? "unverified"])
    }
    /// Fast best-effort leave: no Apple assertion, chain write, membership revocation or account deletion.
    /// Safe for global app termination, including updater/system quit; completion fires within four seconds.
    func requestDirectoryLeave(_ completion:@escaping ()->Void) {
        directoryState.setEnabled(false)
        guard let context=directoryState.leaveContext(),me.count==32 else {completion();return}
        let member=me,point=sessionPublic,raw=session.rawRepresentation,chainId=cfg.chainId,registry=cfg.registry,endpoint=cfg.relay.appendingPathComponent("directory/leave")
        DispatchQueue.global().async {
            defer{completion()}
            do {
                let at=UInt64(Date().timeIntervalSince1970)
                let payload=try NativeDirectoryEncoding.leavePayload(chainId:chainId,registry:registry,member:member,session:point,context:context,at:at)
                let signer=try P256.Signing.PrivateKey(rawRepresentation:raw)
                let signature=try signer.signature(for:RawDigest(data:Data(SHA256.hash(data:payload)))).rawRepresentation
                _=try Self.directoryRequest(endpoint,["member":hex(member),"context":hex(context),"at":at,"signature":hex(signature)],timeout:3)
            } catch { /* Interruption expires the existing public entry; no identity changes. */ }
        }
    }
    private func directoryHTTP(_ path:String,_ body:[String:Any],timeout:Double)throws->[String:Any] {
        try Self.directoryRequest(cfg.relay.appendingPathComponent(path),body,timeout:timeout)
    }
    private static func directoryRequest(_ endpoint:URL,_ body:[String:Any],timeout:Double)throws->[String:Any] {
        var request=URLRequest(url:endpoint);request.httpMethod="POST";request.timeoutInterval=timeout
        request.setValue("application/json",forHTTPHeaderField:"Content-Type");request.httpBody=try JSONSerialization.data(withJSONObject:body)
        try need(request.httpBody!.count<=16384,"directory request size")
        let done=DispatchSemaphore(value:0);var result:Data?;var status=0
        let configuration=URLSessionConfiguration.ephemeral;configuration.timeoutIntervalForRequest=timeout;configuration.timeoutIntervalForResource=timeout
        configuration.httpCookieStorage=nil;configuration.urlCredentialStorage=nil;configuration.httpShouldSetCookies=false
        let session=URLSession(configuration:configuration)
        let task=session.dataTask(with:request){data,response,_ in result=data;status=(response as? HTTPURLResponse)?.statusCode ?? 0;done.signal()};task.resume()
        guard done.wait(timeout:.now()+timeout+0.5) == .success else {task.cancel();session.invalidateAndCancel();throw DemoError.invalid("directory timeout")}
        defer{session.finishTasksAndInvalidate()}
        guard status==200,let result,result.count<=4096,let object=try JSONSerialization.jsonObject(with:result) as? [String:Any] else {throw DemoError.invalid("directory unavailable")}
        return object
    }
}
