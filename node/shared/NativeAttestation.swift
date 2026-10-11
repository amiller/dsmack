import Foundation

/// Serial callback bridge. A timeout poisons this instance: Apple's operation
/// cannot be cancelled, so retrying could overlap an operation still in flight.
final class NativeAttestation {
    private let gate = NSLock()
    private var busy = false
    private var timedOut = false
    private final class Reply<T> {
        let lock = NSLock()
        var completed = false
        var value:T?
        var error:Error?
    }
    static let domain = "AttestNode.NativeAttestation"
    static func errorChain(_ error:Error) -> [[String:Any]] {
        var result = [[String:Any]]();var current:NSError? = error as NSError
        var seen = Set<ObjectIdentifier>()
        while let e = current,result.count < 5,seen.insert(ObjectIdentifier(e)).inserted {
            result.append(["domain":e.domain,"code":e.code])
            current = e.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return result
    }
    static func mustStop(_ error:Error) -> Bool {
        let e = error as NSError
        return e.domain == domain || (e.domain == "com.apple.devicecheck.error" && e.code != 4)
    }
    func call<T>(stage:String,timeout:TimeInterval = 90,operation: (@escaping (T?,Error?)->Void)->Void) throws -> T {
        gate.lock()
        if busy || timedOut {
            gate.unlock()
            throw NSError(domain:Self.domain,code:2,userInfo:[NSLocalizedDescriptionKey:"\(stage): prior Apple operation is unfinished; restart required"])
        }
        busy = true;gate.unlock()
        let wait = DispatchSemaphore(value:0),reply = Reply<T>()
        operation {value,error in
            reply.lock.lock();defer {reply.lock.unlock()}
            guard !reply.completed else {return}
            reply.completed = true;reply.value = value;reply.error = error;wait.signal()
        }
        let finished = wait.wait(timeout:.now()+timeout) == .success
        gate.lock();busy = false;if !finished {timedOut = true};gate.unlock()
        guard finished else {throw NSError(domain:Self.domain,code:1,userInfo:[NSLocalizedDescriptionKey:"\(stage): Apple operation timed out; restart required"])}
        reply.lock.lock();defer {reply.lock.unlock()}
        if let error = reply.error {throw error}
        guard let value = reply.value else {throw NSError(domain:Self.domain,code:3,userInfo:[NSLocalizedDescriptionKey:"\(stage): Apple returned no result"])}
        return value
    }
}
