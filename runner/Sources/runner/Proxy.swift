import CryptoKit
import Foundation
import NIOCore
import NIOExtras
import NIOHTTP1
import NIOPosix

struct Refusal: Error { let status: Int; let reason: String }

// Guest-facing plaintext HTTP over the relayed unix socket; upstream TLS is originated here.
final class Proxy: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    let policy: EgressPolicy, anchors: [SecCertificate], key: String, chain: Chain
    let guest: Guest, quoteHelper: QuoteHelper?, tasks: Tasks?
    let lock = NSLock()
    var requests = 0, tokensUsed = 0
    var quotes: [String: Task<Quote, Error>] = [:], spkiPins: [String: Set<String>] = [:]
    var session: URLSession!

    init(policy: EgressPolicy, anchors: [SecCertificate], key: String, chain: Chain, guest: Guest, quoteHelper: QuoteHelper?, tasks: Tasks?) {
        (self.policy, self.anchors, self.key, self.chain) = (policy, anchors, key, chain)
        (self.guest, self.quoteHelper, self.tasks) = (guest, quoteHelper, tasks)
        super.init()
        let c = URLSessionConfiguration.ephemeral
        c.connectionProxyDictionary = [:]
        c.httpCookieStorage = nil
        c.urlCache = nil
        c.urlCredentialStorage = nil
        session = URLSession(configuration: c, delegate: self, delegateQueue: nil)
    }

    func urlSession(_: URLSession, didReceive ch: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard ch.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = ch.protectionSpace.serverTrust else {
            return (.cancelAuthenticationChallenge, nil)
        }
        SecTrustSetAnchorCertificates(trust, anchors as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var err: CFError?
        guard SecTrustEvaluateWithError(trust, &err) else {
            log("TLS pin refused \(ch.protectionSpace.host): \(err.map { String(describing: $0) } ?? "")")
            return (.cancelAuthenticationChallenge, nil)
        }
        // A provider_quote host must also present a TLS key its verified quote attests.
        let host = ch.protectionSpace.host
        if policy.allow.contains(where: { $0.provider_quote != nil && hostname($0.host) == host }) {
            let leaf = SecCertificateCopyData((SecTrustCopyCertificateChain(trust) as! [SecCertificate])[0]) as Data
            let spki = spkiSHA256(leaf), pins = lock.withLock { spkiPins[host] }
            guard let pins, pins.contains(spki) else {
                log("attested SPKI pin refused \(host): leaf spki_sha256 \(spki) not in \(pins.map { $0.sorted() } ?? [])")
                return (.cancelAuthenticationChallenge, nil)
            }
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    func urlSession(_: URLSession, task _: URLSessionTask, willPerformHTTPRedirection _: HTTPURLResponse, newRequest _: URLRequest) async -> URLRequest? { nil }

    func handle(_ head: HTTPRequestHead, _ body: Data) async -> (Int, [(String, String)], Data) {
        do {
            if head.headers["host"].first == "runner.local" {
                let c = URLComponents(string: head.uri)
                if let c, c.path.hasPrefix("/task/") {
                    guard let tasks else { throw Refusal(status: 403, reason: "this compose declares no tasks") }
                    return try await tasks.handle(head.method.rawValue, c, body)
                }
                if head.method == .GET, let c, c.path == "/provider-quote" {
                    guard let host = c.queryItems?.first(where: { $0.name == "host" })?.value else { throw Refusal(status: 400, reason: "need ?host=") }
                    guard let t = lock.withLock({ quotes[host] }) else { throw Refusal(status: 404, reason: "no provider quote fetched for \(host) yet") }
                    do { return (200, [("content-type", "application/json")], try await t.value.report) } catch { throw Refusal(status: 502, reason: "provider quote for \(host) not verified: \(error)") }
                }
                return (200, [("content-type", "application/json")], try await guest.handle(head.method.rawValue, head.uri, body))
            }
            return try await forward(head, body)
        } catch let r as Refusal {
            log("refused \(head.method) \(head.headers["host"].first ?? "") \(head.uri): \(r.reason)")
            return (r.status, [("content-type", "text/plain")], Data("runner refused: \(r.reason)\n".utf8))
        } catch {
            log("upstream error \(head.method) \(head.headers["host"].first ?? "") \(head.uri): \(error)")
            return (502, [("content-type", "text/plain")], Data("runner upstream error: \(error.localizedDescription)\n".utf8))
        }
    }

    func forward(_ head: HTTPRequestHead, _ body: Data) async throws -> (Int, [(String, String)], Data) {
        guard let host = head.headers["host"].first else { throw Refusal(status: 400, reason: "no Host header") }
        guard head.uri.hasPrefix("/"), let comps = URLComponents(string: "https://\(host)\(head.uri)"),
              (comps.host ?? "") + (comps.port.map { ":\($0)" } ?? "") == host, comps.user == nil, let url = comps.url else {
            throw Refusal(status: 400, reason: "bad request target")
        }
        let path = comps.percentEncodedPath, method = head.method.rawValue
        guard !path.contains(".."), path.range(of: "%2e", options: .caseInsensitive) == nil else { throw Refusal(status: 403, reason: "dot segments refused") }
        guard let rule = policy.allow.first(where: { $0.host == host && $0.method == method && path.hasPrefix($0.path_prefix) }) else {
            throw Refusal(status: 403, reason: "not allowlisted: \(method) \(host)\(path)")
        }
        var quote: Quote?
        if let pq = rule.provider_quote { quote = try await providerQuote(pq, hostname(rule.host)) }
        let tokens = (try? JSONSerialization.jsonObject(with: body) as? [String: Any]).flatMap { ($0["max_tokens"] ?? $0["max_completion_tokens"]) as? Int }
        if rule.metered == true && tokens == nil { throw Refusal(status: 400, reason: "metered endpoint requires an integer max_tokens in a JSON body") }
        try lock.withLock {
            guard requests < policy.max_requests else { throw Refusal(status: 429, reason: "per-boot request cap \(policy.max_requests) reached") }
            guard (tokens ?? 0) <= policy.max_tokens - tokensUsed else {
                throw Refusal(status: 402, reason: "max_tokens \(tokens!) exceeds remaining per-boot budget \(policy.max_tokens - tokensUsed)")
            }
            requests += 1
            tokensUsed += tokens ?? 0
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.httpBody = body.isEmpty ? nil : body
        let drop: Set = ["host", "authorization", "proxy-authorization", "x-api-key", "cookie", "connection", "content-length",
                         "transfer-encoding", "keep-alive", "upgrade", "te", "trailer", "proxy-connection"]
        for (n, v) in head.headers where !drop.contains(n.lowercased()) { req.addValue(v, forHTTPHeaderField: n) }
        if let h = rule.auth_header { req.setValue((rule.auth_prefix ?? "") + key, forHTTPHeaderField: h) }
        let (raw, resp) = try await session.data(for: req)
        let http = resp as! HTTPURLResponse
        // An upstream that reflects request headers would hand the key to the guest; replace any literal copy.
        let data = raw.replacing(Data(key.utf8), with: Data("[REDACTED-API-KEY]".utf8))
        if data != raw { log("redacted API key reflected by \(host)\(path)") }
        var fields: [String: Any] = ["method": method, "url": url.absoluteString, "status": http.statusCode,
                                     "req_sha256": sha256hex(Data("\(method) \(url.absoluteString)\n".utf8) + body), "resp_sha256": sha256hex(data)]
        if let quote { fields["provider_quote_sha256"] = quote.sha256; fields["onchain"] = quote.onchain }
        if rule.metered == true {
            // Settle the max_tokens reservation to actual usage: OpenAI total_tokens, Anthropic input_tokens + output_tokens.
            // A JSON body carries usage at the top level; an SSE stream (stream_options.include_usage) in its last usage chunk.
            let objects = (try? JSONSerialization.jsonObject(with: raw)).map { [$0] } ?? String(decoding: raw, as: UTF8.self)
                .split(whereSeparator: \.isNewline).filter { $0.hasPrefix("data:") && !$0.contains("[DONE]") }
                .compactMap { try? JSONSerialization.jsonObject(with: Data($0.dropFirst(5).utf8)) }
            let u = objects.compactMap { ($0 as? [String: Any])?["usage"] as? [String: Any] }.last
            guard let used = (u?["total_tokens"] as? Int) ?? (u?["input_tokens"] as? Int).flatMap({ i in (u?["output_tokens"] as? Int).map { i + $0 } }) else {
                throw Refusal(status: 502, reason: "metered upstream \(http.statusCode) response has no usage; reservation of \(tokens!) stays charged")
            }
            lock.withLock { tokensUsed += used - tokens! }
            fields["tokens_reserved"] = tokens!
            fields["tokens_charged"] = used
        }
        try chain.sign(fields)
        // Only Content-Type plus the rule's response_headers allowlist (covered by compose_hash) reach the guest.
        let names = ["Content-Type"] + (rule.response_headers ?? [])
        return (http.statusCode, names.compactMap { n in http.value(forHTTPHeaderField: n).map { (n, $0.replacingOccurrences(of: key, with: "[REDACTED-API-KEY]")) } }, data)
    }

    // Verified once per host, before its first upstream request; a failure refuses every request to that host.
    func providerQuote(_ pq: ProviderQuote, _ host: String) async throws -> Quote {
        let t = lock.withLock {
            if let t = quotes[host] { return t }
            let t = Task { [self] in
                let q = try await quoteHelper!.run(pq, host: host, key: key)
                lock.withLock { spkiPins[host, default: []].formUnion(q.spki) }
                return q
            }
            quotes[host] = t
            return t
        }
        do { return try await t.value } catch { throw Refusal(status: 502, reason: "provider quote not verified, no upstream contact: \(error)") }
    }

    func serve(unixSocket path: String) async throws -> Channel {
        try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton).childChannelInitializer { ch in
            ch.eventLoop.makeCompletedFuture {
                try ch.pipeline.syncOperations.addHandler(ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)), name: "dec")
                try ch.pipeline.syncOperations.addHandler(HTTPResponseEncoder(), name: "enc")
                try ch.pipeline.syncOperations.addHandler(IdleStateHandler(allTimeout: .seconds(120)), name: "idle")
                try ch.pipeline.syncOperations.addHandler(Handler(proxy: self))
            }
        }.bind(unixDomainSocketPath: path).get()
    }
}

func hostname(_ host: String) -> String { String(host.split(separator: ":")[0]) }

// A receipt chain (domain mac-compose-receipt/1) in receipts.jsonl: one for the boot's proxy, one per task guest.
final class Chain: @unchecked Sendable {
    let signer: P256.Signing.PrivateKey, composeHash: String, file: FileHandle, lock = NSLock()
    var seq = 0, prev = String(repeating: "0", count: 64)

    init(signer: P256.Signing.PrivateKey, composeHash: String, file: URL) throws {
        FileManager.default.createFile(atPath: file.path, contents: nil)
        (self.signer, self.composeHash, self.file) = (signer, composeHash, try FileHandle(forWritingTo: file))
    }

    func sign(_ fields: [String: Any]) throws {
        try lock.withLock {
            seq += 1
            let body = try JSONSerialization.data(withJSONObject: fields.merging([
                "domain": "mac-compose-receipt/1", "compose_hash": composeHash, "seq": seq, "prev": prev,
            ]) { a, _ in a }, options: [.sortedKeys, .withoutEscapingSlashes])
            let line = try JSONSerialization.data(withJSONObject: ["body": String(decoding: body, as: UTF8.self),
                                                                   "sig": hex(try signer.signature(for: body).derRepresentation)],
                                                  options: [.sortedKeys, .withoutEscapingSlashes])
            try file.write(contentsOf: line + Data("\n".utf8))
            prev = sha256hex(body)
        }
    }
}

let silentConnectionSeconds = 2

// HTTP/1.1 with keep-alive when the client asks for it (requests on a connection are answered in order; clients
// don't pipeline). CONNECT host:port to an `egress.tcp` entry turns the connection into a raw TCP tunnel.
final class Handler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    let proxy: Proxy
    var head: HTTPRequestHead?, body = ByteBuffer(), firstHead: Scheduled<Void>?
    init(proxy: Proxy) { self.proxy = proxy }

    // Containerization's guest relay (vminitd VsockProxy) can stall a new connection while another VM starts, and then
    // every later connection from that guest waits behind it until the host closes the stalled one. A connection that
    // sends no request head in silentConnectionSeconds is closed so the rest resume; the client sees the close and may
    // retry. A real guest client sends its head within milliseconds.
    func channelActive(context: ChannelHandlerContext) {
        let ch = context.channel
        firstHead = context.eventLoop.scheduleTask(in: .seconds(Int64(silentConnectionSeconds))) {
            log("closed a guest connection that sent no request in \(silentConnectionSeconds) s")
            ch.close(promise: nil)
        }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h): head = h; body.clear(); firstHead?.cancel(); firstHead = nil
        case .body(var b): body.writeBuffer(&b)
        case .end:
            let head = head!, channel = context.channel
            if head.method == .CONNECT { return connect(context, head.uri) }
            let limit = head.method == .POST && head.uri == "/task/start" && head.headers["host"].first == "runner.local" ? 28 : 1
            guard body.readableBytes <= limit << 20 else { return respond(channel, 413, [("content-type", "text/plain")], Data("runner refused: body over \(limit) MiB\n".utf8)) }
            let body = Data(body.readableBytesView), keep = head.isKeepAlive
            Task { let (status, headers, data) = await proxy.handle(head, body); respond(channel, status, headers, data, close: !keep) }
        }
    }

    func respond(_ channel: Channel, _ status: Int, _ headers: [(String, String)], _ body: Data, close: Bool = true) {
        let h = HTTPHeaders([("content-length", "\(body.count)"), ("connection", close ? "close" : "keep-alive")] + headers)
        channel.write(HTTPServerResponsePart.head(.init(version: .http1_1, status: .init(statusCode: status), headers: h)), promise: nil)
        channel.write(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: body))), promise: nil)
        // Never close after a response: the guest socket relay can drop bytes still in flight when the host side
        // closes, truncating large bodies. The client closes (connection: close); IdleStateHandler reaps the rest.
        channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) { log("guest connection error: \(error)"); context.close(promise: nil) }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is IdleStateHandler.IdleStateEvent { context.close(promise: nil) } else { context.fireUserInboundEventTriggered(event) }
    }

    func connect(_ context: ChannelHandlerContext, _ target: String) {
        let channel = context.channel, parts = target.split(separator: ":")
        if target.hasPrefix("task-") && target.hasSuffix(".runner.local:1") { return attach(context, String(target.dropFirst(5).dropLast(15))) }
        guard parts.count == 2, let port = Int(parts[1]), proxy.policy.tcp?.contains(TCPTarget(host: String(parts[0]), port: port)) == true else {
            log("refused CONNECT \(target): not in egress.tcp")
            return respond(channel, 403, [("content-type", "text/plain")], Data("runner refused: CONNECT \(target) not in egress.tcp\n".utf8))
        }
        ClientBootstrap(group: context.eventLoop).connect(host: String(parts[0]), port: port).whenComplete { [self] result in
            switch result {
            case .failure(let e):
                log("CONNECT \(target) failed: \(e)")
                respond(channel, 502, [("content-type", "text/plain")], Data("runner upstream error: \(e)\n".utf8))
            case .success(let peer):
                log("CONNECT \(target) tunnel open")
                let (a, b) = Glue.pair()
                // The 200 goes out raw: HTTPResponseEncoder would frame a body-less 200 as chunked.
                _ = peer.pipeline.addHandler(b).flatMap { channel.pipeline.removeHandler(name: "enc") }
                    .flatMap { channel.pipeline.removeHandler(name: "idle") }  // tunnels (libp2p relay) idle legitimately
                    .flatMap { channel.pipeline.removeHandler(self) }
                    .flatMap { channel.writeAndFlush(ByteBuffer(string: "HTTP/1.1 200 Connection Established\r\n\r\n")) }
                    .flatMap { channel.pipeline.addHandler(a) }
                    .flatMap { channel.pipeline.removeHandler(name: "dec") }  // forwards any bytes read past the CONNECT head
                    .always { if case .failure(let e) = $0 { log("CONNECT \(target) setup failed: \(e)"); channel.close(promise: nil); peer.close(promise: nil) } }
            }
        }
    }
}

// CONNECT task-<id>.runner.local:1: the connection becomes the task entrypoint's stdin/stdout.
extension Handler {
    func attach(_ context: ChannelHandlerContext, _ id: String) {
        let channel = context.channel, run: TaskRun
        do {
            guard let tasks = proxy.tasks else { throw Refusal(status: 403, reason: "this compose declares no tasks") }
            run = try tasks.claim(id)
        } catch {
            let r = error as? Refusal ?? Refusal(status: 500, reason: "\(error)")
            log("refused CONNECT task-\(id): \(r.reason)")
            return respond(channel, r.status, [("content-type", "text/plain")], Data("runner refused: \(r.reason)\n".utf8))
        }
        channel.pipeline.removeHandler(name: "enc")
            .flatMap { channel.pipeline.removeHandler(name: "idle") }
            .flatMap { channel.pipeline.removeHandler(self) }
            .flatMap { channel.writeAndFlush(ByteBuffer(string: "HTTP/1.1 200 Connection Established\r\n\r\n")) }
            .flatMap { channel.pipeline.addHandler(TaskStream(run: run)) }
            .flatMap { channel.pipeline.removeHandler(name: "dec") }
            .whenComplete { result in
                do { try result.get(); try run.activate(channel) } catch {
                    log("attach task-\(id) failed: \(error)")
                    run.release()
                    channel.close(promise: nil)
                }
            }
    }
}

final class TaskStream: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let run: TaskRun
    init(run: TaskRun) { self.run = run }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) { run.stdinInput.yield(Data(unwrapInboundIn(data).readableBytesView)) }
    func channelInactive(context: ChannelHandlerContext) {
        do { try run.detach(context.channel) } catch { log("task-\(run.id) detach receipt failed: \(error)"); exit(1) }
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }
}

// Byte relay between the guest connection and the upstream TCP connection; closing either side closes both.
final class Glue: ChannelDuplexHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = NIOAny
    typealias OutboundIn = NIOAny
    var partner: Glue?, ctx: ChannelHandlerContext?
    static func pair() -> (Glue, Glue) { let a = Glue(), b = Glue(); a.partner = b; b.partner = a; return (a, b) }
    func handlerAdded(context: ChannelHandlerContext) { ctx = context }
    func handlerRemoved(context: ChannelHandlerContext) { ctx = nil; partner = nil }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) { partner?.ctx?.write(data, promise: nil) }
    func channelReadComplete(context: ChannelHandlerContext) { partner?.ctx?.flush() }
    func channelInactive(context: ChannelHandlerContext) { partner?.ctx?.close(promise: nil) }
    func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }
}
