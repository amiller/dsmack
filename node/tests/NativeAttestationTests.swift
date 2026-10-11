import Foundation

@main struct NativeAttestationTests {
    static func main() throws {
        var checks = 0
        func check(_ value:Bool,_ label:String) {precondition(value,label);checks += 1}
        let bridge = NativeAttestation()
        let value:String = try bridge.call(stage:"generateKey") {$0("test-key",nil)}
        check(value == "test-key","success")
        for code in 0...4 {
            do {
                let _:String = try bridge.call(stage:"attestKey") {$0(nil,NSError(domain:"com.apple.devicecheck.error",code:code))}
                fatalError("error swallowed")
            } catch {
                check((error as NSError).code == code,"Apple code preserved")
                check(NativeAttestation.mustStop(error) == (code != 4),"retry classification")
            }
        }
        do {let _:Data = try bridge.call(stage:"generateAssertion") {$0(nil,nil)};fatalError("missing result accepted")}
        catch {check(NativeAttestation.mustStop(error),"missing result terminal")}
        let delayed:String = try bridge.call(stage:"generateKey",timeout:1) {done in
            DispatchQueue.global().async {done("async-key",nil)}
        }
        check(delayed == "async-key","async completion")
        let twice:String = try bridge.call(stage:"attestKey") {done in done("first",nil);done("second",nil)}
        check(twice == "first","duplicate callback ignored")
        let stuck = NativeAttestation()
        var late:((String?,Error?)->Void)?
        do {let _:String = try stuck.call(stage:"attestKey",timeout:0.01) {late = $0};fatalError("timeout accepted")}
        catch {check((error as NSError).code == 1,"timeout classified")}
        late?("too-late",nil)
        var called = false
        do {let _:String = try stuck.call(stage:"generateKey") {called = true;$0("bad",nil)};fatalError("reused poisoned bridge")}
        catch {check(!called && (error as NSError).code == 2,"late callback cannot permit another operation")}
        let nested = NativeAttestation()
        let _:String = try nested.call(stage:"attestKey") {done in
            do {let _:String = try nested.call(stage:"generateKey") {$0("bad",nil)};fatalError("overlap allowed")}
            catch {check((error as NSError).code == 2,"overlap blocked")}
            done("ok",nil)
        }
        var error = NSError(domain:"CryptoTokenKit",code:-3,userInfo:["private":"DO NOT EXPORT"])
        for n in 0..<10 {error = NSError(domain:"layer",code:n,userInfo:[NSUnderlyingErrorKey:error,"private":"DO NOT EXPORT"])}
        let chain = NativeAttestation.errorChain(error)
        check(chain.count == 5,"bounded error chain")
        let encoded = String(decoding:try JSONSerialization.data(withJSONObject:chain),as:UTF8.self)
        check(!encoded.contains("DO NOT EXPORT"),"userInfo excluded")
        print("NativeAttestation: \(checks) checks passed (injected callbacks; no hardware attestation)")
    }
}
