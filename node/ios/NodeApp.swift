import SwiftUI
import DeviceCheck
import UniformTypeIdentifiers

@main struct NodeApp: App {
    var body: some Scene {WindowGroup {NodeView()}}
}

/// One participant worker per process. SwiftUI view recreation must not generate
/// another enrollment or start a second network loop.
final class ParticipantModel: ObservableObject {
    @Published var title = "Connecting to the testnet…"
    @Published var detail = "Keep this app open while it verifies your device and joins."
    @Published var badge = "Your participant NFT will be claimed automatically."
    @Published var receiptURL: URL?
    @Published var lines = [String]()
    @Published var simulatorScenario = false
    @Published var codeEvidenceURL:URL?
    @Published var codeEvidenceError:String?
    @Published var preparingCodeEvidence = false
    @Published var connected = false
    @Published var participantClaimed = false
    @Published var upgradeBusy = false
    @Published var upgradeNotice:String?
    @Published var exportDocument:UpgradeDocument?
    @Published var exportName = "AttestNode-upgrade-invitation.json"
    @Published var showingExport = false
    @Published var approval:UpgradeRequest?
    @Published var approvalTeam = ""
    private var exportedRequest:UpgradeRequest?
    private var node:Node?
    private var started = false

    func start() {
        guard !started else {return};started = true
        emit("app launched",["os":ProcessInfo.processInfo.operatingSystemVersionString,
            "appVersion":Bundle.main.object(forInfoDictionaryKey:"CFBundleShortVersionString") ?? "unknown",
            "appBuild":Bundle.main.object(forInfoDictionaryKey:"CFBundleVersion") ?? "unknown"])
        #if targetEnvironment(simulator)
        if let scenario = ProcessInfo.processInfo.environment["ATTESTNODE_UI_SCENARIO"] {
            simulatorScenario = true
            emit("simulator scenario",["scenario":scenario])
            emit("configured",["chainId":84532,"participant":"SIMULATED"])
            switch scenario {
            case "claimed", "upgrade-export":emit("participating",[:]);emit("badge claimed",["badgeToken":42])
            case "upgrade-approval":
                emit("participating",[:]);emit("badge claimed",["badgeToken":42])
                // Deliberately invalid fixture: UI consent only, no Node or signer.
                let invitation = UpgradeInvitation(version:2,chainId:84532,badges:"SIMULATED",factory:"SIMULATED",account:"SIMULATED-ACCOUNT",participantToken:42,bundleId:"SIMULATED")
                let receipt = Request(action:3,category:zero32,owner:"SIMULATED",session:zero32,nonce:0,deadline:0,scope:zero32,x:zero32,y:zero32,envelope:zero32)
                DispatchQueue.main.async {
                    self.approvalTeam = "SIMULATED-TEAM"
                    self.approval = UpgradeRequest(invitation:invitation,newPoint:Data([4])+Data(repeating:0,count:64),generation:0,deadline:0,newSignature:Data(),newKeyId:zero32,receiptRequest:receipt,receiptTransaction:"SIMULATED")
                }
            case "upgrade-invalid-file", "upgrade-oversize-file":
                emit("participating",[:])
                DispatchQueue.main.async {
                    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString+".json")
                    defer {try? FileManager.default.removeItem(at:url)}
                    do {
                        try Data(repeating:65,count:scenario == "upgrade-oversize-file" ? 65537:8).write(to:url)
                        self.importUpgrade(url)
                    } catch {self.upgradeNotice = String(describing:error)}
                }
            case "retry":emit("retrying",["retryAfterSeconds":4,"error":"Injected network outage"])
            case "apple-failure":
                emit("apple operation failed",["stage":"attestKey","errorChain":[["domain":"com.apple.devicecheck.error","code":0],["domain":"CryptoTokenKit","code":-3]]])
                emit("stopped",["error":"Injected Apple failure"])
            default:emit("attesting",[:])
            }
            return
        }
        #endif
        DispatchQueue.global(qos:.userInitiated).async {self.run()}
    }
    private func run() {
        do {
            guard var settings = ReleaseNetwork.settings else {throw DemoError.invalid("Release network is unavailable")}
            let defaults = UserDefaults.standard
            let name = defaults.string(forKey:"participantName") ?? UUID().uuidString.lowercased()
            defaults.set(name,forKey:"participantName")
            settings["name"] = name;settings["persistentIdentity"] = true
            let config = try Config(settings)
            try need(!config.peer.isEmpty,"missing faucet peer")
            emit("configured",["chainId":config.chainId,"registry":config.registry,"participant":name])
            guard DCAppAttestService.shared.isSupported else {
                emit("stopped",["error":"App Attest unsupported on this device","appAttestSupported":false]);return
            }
            let node = Node(config,log:emit)
            DispatchQueue.main.async {self.node = node}
            var delay:Double = 2
            while true {
                do {try node.participate();return}
                catch {
                    let e = error as NSError
                    // Only Apple's service-unavailable error is retried here.
                    // Invalid keys and unknown native errors need diagnosis;
                    // repeating them indefinitely conceals a failed enrollment.
                    let terminalApple = NativeAttestation.mustStop(error)
                    let message = String(describing:error)
                    if terminalApple || message.contains("unsupported") || message.contains("timeout") || message.contains("identity already running") {
                        emit("stopped",["error":message,"errorDomain":e.domain,"errorCode":e.code]);return
                    }
                    emit("retrying",["error":message,"retryAfterSeconds":delay])
                    Thread.sleep(forTimeInterval:delay);delay = min(delay*2,60)
                }
            }
        } catch {emit("stopped",["error":String(describing:error)])}
    }
    func prepareCodeEvidence() {
        guard !preparingCodeEvidence else {return}
        preparingCodeEvidence = true;codeEvidenceURL = nil;codeEvidenceError = nil
        DispatchQueue.global(qos:.userInitiated).async {
            do {
                #if targetEnvironment(simulator)
                throw CodeEvidence.Failure.invalid("Code admission evidence requires the installed iPhone app. Simulator evidence cannot admit a device build.")
                #else
                guard let executable = Bundle.main.executableURL else {throw CodeEvidence.Failure.invalid("Executable unavailable")}
                let evidence = try CodeEvidence.extract(Data(contentsOf:executable))
                var report = try JSONSerialization.jsonObject(with:JSONEncoder().encode(evidence)) as! [String:Any]
                report["schema"] = 1;report["source"] = "installed-app-bundle"
                report["bundleId"] = Bundle.main.bundleIdentifier ?? "unknown"
                report["appVersion"] = Bundle.main.object(forInfoDictionaryKey:"CFBundleShortVersionString") ?? "unknown"
                report["appBuild"] = Bundle.main.object(forInfoDictionaryKey:"CFBundleVersion") ?? "unknown"
                report["scope"] = "Local code evidence; not Apple attestation or proof of provenance. No profile, enrollment state or private keys included."
                let url = FileManager.default.temporaryDirectory.appendingPathComponent("AttestNode-code-evidence.json")
                try JSONSerialization.data(withJSONObject:report,options:[.sortedKeys]).write(to:url,options:.atomic)
                self.emit("code evidence prepared",["cdhash":evidence.cdhash])
                DispatchQueue.main.async {self.preparingCodeEvidence = false;self.codeEvidenceURL = url}
                #endif
            } catch {
                self.emit("code evidence unavailable",["error":error.localizedDescription])
                DispatchQueue.main.async {self.preparingCodeEvidence = false;self.codeEvidenceError = error.localizedDescription}
            }
        }
    }
    private func perform<T>(_ operation:@escaping (Node)throws->T,done:@escaping(T)->Void) {
        guard !upgradeBusy,connected,let node else {upgradeNotice = "Connect to the network before continuing the upgrade.";return}
        upgradeBusy = true
        node.enqueueOperation {n in
            do {
                let value = try operation(n)
                DispatchQueue.main.async {self.upgradeBusy = false;done(value)}
            } catch {
                DispatchQueue.main.async {self.upgradeBusy = false;self.upgradeNotice = String(describing:error)}
            }
        }
    }
    private func presentInvitation(_ invitation:UpgradeInvitation) {
        do {
            exportDocument = UpgradeDocument(data:try JSONEncoder().encode(invitation))
            exportName = "AttestNode-upgrade-invitation.json";exportedRequest = nil;showingExport = true
        } catch {upgradeNotice = error.localizedDescription}
    }
    func saveInvitation() {
        #if targetEnvironment(simulator)
        if ProcessInfo.processInfo.environment["ATTESTNODE_UI_SCENARIO"] == "upgrade-export" {
            presentInvitation(UpgradeInvitation(version:2,chainId:84532,badges:"SIMULATED",factory:"SIMULATED",account:"SIMULATED-ACCOUNT",participantToken:42,bundleId:"SIMULATED"))
            return
        }
        #endif
        perform({try $0.exportUpgradeInvitation()},done:presentInvitation)
    }
    func importUpgrade(_ url:URL) {
        guard !upgradeBusy else {return}
        let access = url.startAccessingSecurityScopedResource();defer {if access {url.stopAccessingSecurityScopedResource()}}
        do {
            let size = try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0
            try need(size>0 && size<=65536,"Upgrade file must be at most 64 KiB")
            let data = try Data(contentsOf:url);try need(data.count<=65536,"Upgrade file size")
            if let request = try? JSONDecoder().decode(UpgradeRequest.self,from:data) {
                perform({try $0.validateUpgrade(request)}) {team in
                    self.approvalTeam = hex(team.prefix(8));self.approval = request
                }
            } else {
                guard let invitation = try? JSONDecoder().decode(UpgradeInvitation.self,from:data) else {
                    throw DemoError.invalid("This is not an AttestNode upgrade invitation or request.")
                }
                perform({try $0.prepareUpgrade(invitation)}) {request in
                    do {
                        self.exportDocument = UpgradeDocument(data:try JSONEncoder().encode(request))
                        self.exportedRequest = request;self.exportName = "AttestNode-upgrade-request.json";self.showingExport = true
                    } catch {self.upgradeNotice = String(describing:error)}
                }
            }
        } catch {upgradeNotice = error.localizedDescription}
    }
    func exportFinished(_ result:Result<URL,Error>) {
        defer {exportDocument = nil;exportedRequest = nil}
        switch result {
        case .failure(let error):upgradeNotice = String(describing:error)
        case .success(let url):
            #if targetEnvironment(simulator)
            if ProcessInfo.processInfo.environment["ATTESTNODE_UI_SCENARIO"] == "upgrade-export" {
                let access = url.startAccessingSecurityScopedResource()
                defer {if access {url.stopAccessingSecurityScopedResource()}}
                do {
                    let data = try Data(contentsOf:url)
                    try need(data == exportDocument?.data,"Exported file differs from the invitation")
                    let invitation = try JSONDecoder().decode(UpgradeInvitation.self,from:data)
                    try need(invitation.account == "SIMULATED-ACCOUNT","Wrong simulated invitation")
                    upgradeNotice = "SIMULATED invitation saved and read back successfully. No account transfer occurred."
                } catch {upgradeNotice = error.localizedDescription}
                return
            }
            #endif
            if let request = exportedRequest {
                perform({try $0.trackUpgrade(request)}) {_ in
                    self.upgradeNotice = "Import this request in your original app. Compare the new-key fingerprint, then approve the handoff. New key: \(hex(keccak(request.newPoint).prefix(8)))"
                }
            } else {upgradeNotice = "Invitation saved. Build and sign your iPhone copy with your own Apple Developer team and the bundle identifier in that file."}
        }
    }
    func approveHandoff(_ request:UpgradeRequest) {
        approval = nil
        // Revalidates immediately before signing; displaying a confirmation is
        // never itself authorization for an expired or replaced request.
        perform({try $0.approveUpgrade(request)}) {_ in
            self.participantClaimed = false
            self.upgradeNotice = "Account handoff confirmed. Continue in your independently signed copy to claim the builder NFT."
        }
    }
    private func emit(_ event:String,_ fields:[String:Any]) {
        // Reports contain public receipts and bounded diagnostic metadata, never
        // enrollment blobs, private keys, or peer exchange payloads.
        let allowed:Set<String> = ["appAttestSupported","cdhash","scenario","os","appVersion","appBuild","stage","errorChain","chainId","registry","participant","error","errorDomain","errorCode","retryAfterSeconds","badgeToken","badgeLevel","badgeContract","personalAccount","tx","receipt","keyEpoch"]
        var entry = fields.filter {allowed.contains($0.key)}
        entry["event"] = event;entry["t"] = Date().timeIntervalSince1970
        guard let data = try? JSONSerialization.data(withJSONObject:entry,options:[.sortedKeys]) else {return}
        let line = String(decoding:data,as:UTF8.self)
        print(line);fflush(stdout)
        DispatchQueue.main.async {
            self.lines.append(line);self.lines = Array(self.lines.suffix(200))
            if let directory = FileManager.default.urls(for:.documentDirectory,in:.userDomainMask).first {
                try? self.lines.joined(separator:"\n").write(to:directory.appendingPathComponent("diagnostics.jsonl"),atomically:true,encoding:.utf8)
            }
            switch event {
            case "connecting":self.title = "Connecting to the testnet…"
            case "attesting":self.title = "Verifying this app…";self.detail = "Apple attestation checks this app before the network admits it."
            case "getting key":self.title = "Joining the network…";self.detail = "Waiting for a verified peer to share the testnet key."
            case "participating":self.connected = true;self.title = "You’re connected";self.detail = "The shared testnet key is verified. This iPhone participates while the app is open."
            case "badge preparing":self.badge = "Preparing your personal NFT account…"
            case "badge claiming":self.badge = "Claiming your participant NFT…"
            case "badge retrying":self.badge = "NFT claim pending; retrying automatically."
            case "badge claimed":
                self.participantClaimed = (fields["badgeLevel"] as? NSNumber)?.intValue != 2
                self.badge = "\((fields["badgeLevel"] as? NSNumber)?.intValue == 2 ? "Independent-builder" : "Participant") NFT #\(fields["badgeToken"] ?? "") confirmed"
                if let contract = fields["badgeContract"] as? String,let token = fields["badgeToken"],(fields["chainId"] as? NSNumber)?.uint64Value == 84532 {
                    self.receiptURL = URL(string:"https://sepolia.basescan.org/token/\(contract)?a=\(token)")
                }
            case "account handed off":self.participantClaimed = false;self.badge = "Account handed off. Continue in your independently signed copy."
            case "upgrade awaiting approval":self.badge = "Waiting for your original app to approve the handoff…"
            case "builder claiming":self.badge = "Claiming your independent-builder NFT…"
            case "retrying":self.connected = false;self.title = "Waiting to reconnect…";self.detail = "Retrying in \(fields["retryAfterSeconds"] ?? 0) seconds."
            case "stopped":self.connected = false;self.title = "Couldn’t join the network";self.detail = "No further automatic attempts will run. Share the diagnostic report so we can investigate.";if self.receiptURL == nil {self.badge = "NFT claim has not completed."}
            default:break
            }
        }
    }
}

struct UpgradeDocument:FileDocument {
    static var readableContentTypes:[UTType] {[.json]}
    var data:Data
    init(data:Data) {self.data = data}
    init(configuration:ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents,data.count<=65536 else {throw DemoError.invalid("Upgrade file size")}
        self.data = data
    }
    func fileWrapper(configuration:WriteConfiguration) throws -> FileWrapper {FileWrapper(regularFileWithContents:data)}
}

struct NodeView: View {
    @State private var showingImport = false
    @StateObject private var participant = ParticipantModel()
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment:.leading,spacing:24) {
                    Image(systemName:"network").font(.system(size:44)).foregroundStyle(.tint).accessibilityHidden(true)
                    Text(participant.title).font(.largeTitle.bold())
                    Text(participant.detail).foregroundStyle(.secondary)
                    Divider()
                    Text(participant.badge).font(.headline)
                    if let url = participant.receiptURL {Link("View NFT receipt",destination:url)}
                    Text("Research testnet · Base Sepolia\nNo payment or wallet setup required.").font(.footnote).foregroundStyle(.secondary)
                    if participant.connected {
                        DisclosureGroup("Developer upgrade") {
                            VStack(alignment:.leading,spacing:12) {
                                Text("Save an invitation, then import it in your admitted iPhone copy signed by your own Apple Developer team. Bring its request back here to approve the account handoff.").font(.footnote)
                                Button("Save invitation") {participant.saveInvitation()}.disabled(!participant.participantClaimed)
                                Button("Import upgrade file") {showingImport = true}
                                if participant.upgradeBusy {ProgressView("Checking upgrade…")}
                            }.disabled(participant.upgradeBusy)
                        }
                    }
                    ShareLink(item:participant.lines.joined(separator:"\n")) {Label("Share diagnostic report",systemImage:"square.and.arrow.up")}
                    DisclosureGroup("Technical details") {
                        VStack(alignment:.leading,spacing:12) {
                            Text("For the release coordinator: export this installed app’s code evidence without its provisioning profile or private keys.").font(.footnote)
                            Button("Prepare code evidence") {participant.prepareCodeEvidence()}.disabled(participant.preparingCodeEvidence)
                            if participant.preparingCodeEvidence {ProgressView("Reading installed app…")}
                            if let url = participant.codeEvidenceURL {ShareLink("Share code evidence",item:url)}
                            if let error = participant.codeEvidenceError {Text(error).font(.footnote)}
                        }
                        Text(participant.lines.joined(separator:"\n")).font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)
                    }
                }.padding(24)
            }.navigationTitle("Apple peer testnet").navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge:.top) {
                if participant.simulatorScenario {
                    Text("SIMULATOR SCENARIO — no hardware attestation or NFT transaction")
                        .font(.caption.bold()).foregroundStyle(.orange).padding().frame(maxWidth:.infinity).background(.background)
                }
            }
        }.onAppear {participant.start()}
        .fileImporter(isPresented:$showingImport,allowedContentTypes:[.json]) {result in
            switch result {case .success(let url):participant.importUpgrade(url);case .failure(let error):participant.upgradeNotice = String(describing:error)}
        }
        .fileExporter(isPresented:$participant.showingExport,document:participant.exportDocument,contentType:.json,defaultFilename:participant.exportName,onCompletion:participant.exportFinished)
        .alert("Developer upgrade",isPresented:Binding(get:{participant.upgradeNotice != nil},set:{if !$0 {participant.upgradeNotice = nil}})) {
            Button("OK",role:.cancel) {participant.upgradeNotice = nil}
        } message: {Text(participant.upgradeNotice ?? "")}
        .alert("Transfer NFT account control?",isPresented:Binding(get:{participant.approval != nil},set:{if !$0 {participant.approval = nil}}),presenting:participant.approval) {request in
            // Use the presented snapshot: SwiftUI may clear the binding before
            // invoking the action. Node still revalidates before any signature.
            Button("Approve handoff",role:.destructive) {participant.approveHandoff(request)}
            Button("Cancel",role:.cancel) {participant.approval = nil}
        } message: {request in
                Text("Account: \(request.invitation.account)\nNew key: \(hex(keccak(request.newPoint).prefix(8)))\nTeam proof: \(participant.approvalTeam)\n\nCompare this fingerprint with your own signed copy. That copy will control the account; this copy will no longer control it.")
        }
    }
}
