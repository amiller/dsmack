#if GUI
import AppKit

private enum AssemblyPalette {
    static let paper=NSColor(calibratedRed:0.96,green:0.95,blue:0.91,alpha:1)
    static let ink=NSColor(calibratedRed:0.08,green:0.08,blue:0.08,alpha:1)
    static let red=NSColor(calibratedRed:0.90,green:0.20,blue:0.10,alpha:1)
    static let blue=NSColor(calibratedRed:0.15,green:0.25,blue:0.82,alpha:1)
}
final class StatusContentView: NSView {
    override var isOpaque:Bool {true}
    override func draw(_ dirtyRect:NSRect) {AssemblyPalette.paper.setFill();dirtyRect.fill()}
}
final class FoldStageView: NSView {
    var image:NSImage? {didSet {needsDisplay=true}}
    var token:String? {didSet {needsDisplay=true}}
    override var isOpaque:Bool {true}
    override func draw(_ dirtyRect:NSRect) {
        AssemblyPalette.blue.setFill();bounds.fill()
        let inset:CGFloat=26
        if let image {
            let side=min(bounds.width-32,bounds.height-150)
            image.draw(in:NSRect(x:(bounds.width-side)/2,y:(bounds.height-side)/2,width:side,height:side),from:.zero,operation:.sourceOver,fraction:1)
        } else {
            let center=NSPoint(x:bounds.midX,y:bounds.midY)
            let radius=min(bounds.width,bounds.height)*0.28
            for i in 0..<5 {
                let path=NSBezierPath();let angle=CGFloat(i)*0.42
                path.move(to:NSPoint(x:center.x-radius+CGFloat(i)*18,y:center.y-radius))
                path.line(to:NSPoint(x:center.x+radius*cos(angle),y:center.y+radius))
                path.line(to:NSPoint(x:center.x+radius,y:center.y-radius+CGFloat(i)*22))
                path.lineWidth=14
                (i % 2 == 0 ? AssemblyPalette.paper:AssemblyPalette.red).setStroke();path.stroke()
            }
        }
        let label=image == nil ? (token == nil ? "ASSEMBLY / ATTESTNODE":"YOUR RECEIPT / "+token!):"YOUR FOLD / "+(token ?? "")
        (label as NSString).draw(at:NSPoint(x:inset,y:bounds.height-48),withAttributes:[.font:NSFont.monospacedSystemFont(ofSize:13,weight:.bold),.foregroundColor:AssemblyPalette.paper])
        let footer=image == nil ? (token == nil ? "VERIFY. CONNECT. PARTICIPATE.":"ARTWORK NOT LOADED"):"PORCELAIN / VERMILION"
        (footer as NSString).draw(at:NSPoint(x:inset,y:24),withAttributes:[.font:NSFont.monospacedSystemFont(ofSize:11,weight:.medium),.foregroundColor:AssemblyPalette.paper])
    }
}

final class AssemblyButton: NSButton {
    var primary=false
    override var intrinsicContentSize:NSSize {NSSize(width:super.intrinsicContentSize.width+24,height:44)}
    override func draw(_ dirtyRect:NSRect) {
        let shape=NSBezierPath(roundedRect:bounds.insetBy(dx:1,dy:1),xRadius:5,yRadius:5)
        let foreground=isEnabled ? (primary ? NSColor.white:AssemblyPalette.ink):NSColor.secondaryLabelColor
        (primary && isEnabled ? AssemblyPalette.ink:AssemblyPalette.paper).setFill();shape.fill()
        (isEnabled ? AssemblyPalette.ink:NSColor.tertiaryLabelColor).setStroke();shape.lineWidth=1;shape.stroke()
        if isHighlighted {NSColor(calibratedWhite:0.5,alpha:0.16).setFill();shape.fill()}
        let attributes:[NSAttributedString.Key:Any]=[.font:font ?? NSFont.systemFont(ofSize:14,weight:.semibold),.foregroundColor:foreground]
        let size=(title as NSString).size(withAttributes:attributes)
        (title as NSString).draw(at:NSPoint(x:(bounds.width-size.width)/2,y:(bounds.height-size.height)/2),withAttributes:attributes)
        if window?.firstResponder === self {
            AssemblyPalette.blue.setStroke();let focus=NSBezierPath(roundedRect:bounds.insetBy(dx:3,dy:3),xRadius:3,yRadius:3)
            focus.lineWidth=2;focus.stroke()
        }
    }
}

final class ParticipantApp: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private let foldStage=FoldStageView()
    private let stateLabel=NSTextField(labelWithString:"01 / CONNECTING")
    private let participationCaption=NSTextField(wrappingLabelWithString:"RESEARCH TESTNET / NO MONETARY VALUE\nStarting automatically. Keep the app open to connect.")
    private var menuItem: NSStatusItem!
    private let titleLabel=NSTextField(wrappingLabelWithString:"Connecting.")
    private let detailLabel=NSTextField(wrappingLabelWithString:"Starting automatically. You can close this window and keep participating from the menu bar.")
    private let receiptLabel=NSTextField(wrappingLabelWithString:"No verified key receipt yet")
    private let badgeLabel=NSTextField(wrappingLabelWithString:"Participant NFT: waiting for a connection")
    private let badgeReceiptButton=AssemblyButton(title:"View your NFT ↗",target:nil,action:nil)
    private let upgradeButton=AssemblyButton(title:"Become an independent builder…",target:nil,action:nil)
    private let diagnosticScroll=NSScrollView()
    private let shareReportButton=AssemblyButton(title:"Save diagnostic report…",target:nil,action:nil)
    private let detailsButton=AssemblyButton(title:"Show technical details",target:nil,action:nil)
    private let diagnostics=NSTextView()
    private var status=[String:Any]()
    private var eventLines=[String]()
    private var peerNames=Set<String>()
    private var node: Node?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        window=NSWindow(contentRect:NSRect(x:0,y:0,width:1100,height:700),styleMask:[.titled,.closable,.miniaturizable,.resizable],backing:.buffered,defer:false)
        window.minSize=NSSize(width:1000,height:680)
        window.contentView=StatusContentView(frame:window.contentView!.frame)
        window.title="AttestNode / Assembly";window.delegate=self;window.isReleasedWhenClosed=false
        window.appearance=NSAppearance(named:.aqua)
        titleLabel.font = .systemFont(ofSize:48,weight:.heavy);titleLabel.maximumNumberOfLines=3
        titleLabel.lineBreakMode = .byWordWrapping;titleLabel.textColor=AssemblyPalette.ink
        detailLabel.font = .systemFont(ofSize:16);detailLabel.textColor=AssemblyPalette.ink
        stateLabel.font = .monospacedSystemFont(ofSize:12,weight:.bold);stateLabel.textColor=AssemblyPalette.blue
        receiptLabel.font = .systemFont(ofSize:12,weight:.medium);receiptLabel.textColor = .secondaryLabelColor
        badgeLabel.font = .systemFont(ofSize:17,weight:.semibold);badgeLabel.textColor=AssemblyPalette.ink
        upgradeButton.target=self;upgradeButton.action=#selector(developerUpgrade);upgradeButton.isEnabled=false
        receiptLabel.isSelectable=true;badgeLabel.isSelectable=true
        badgeReceiptButton.target=self;badgeReceiptButton.action=#selector(openBadgeReceipt);badgeReceiptButton.isEnabled=false
        for button in [badgeReceiptButton,upgradeButton,detailsButton,shareReportButton] {
            button.bezelStyle = .regularSquare;button.isBordered=false;button.controlSize = .large
            button.font = .systemFont(ofSize:14,weight:.semibold)
        }
        badgeReceiptButton.primary=true
        if ReleaseNetwork.settings?["badges"] == nil {badgeLabel.stringValue="NFT claims are not enabled in this preview."}
        diagnostics.isEditable=false;diagnostics.font = .monospacedSystemFont(ofSize:11,weight:.regular)
        detailsButton.target=self;detailsButton.action=#selector(toggleDetails)
        shareReportButton.target=self;shareReportButton.action=#selector(saveDiagnosticReport)
        let scroll=diagnosticScroll;scroll.isHidden=true;scroll.documentView=diagnostics;scroll.hasVerticalScroller=true
        let caption=participationCaption
        caption.font = .systemFont(ofSize:11);caption.textColor = .secondaryLabelColor
        let stack=NSStackView(views:[stateLabel,titleLabel,detailLabel,receiptLabel,badgeLabel,badgeReceiptButton,upgradeButton,caption,detailsButton,shareReportButton])
        stack.orientation = .vertical;stack.alignment = .leading;stack.spacing=16;stack.translatesAutoresizingMaskIntoConstraints=false
        let content=window.contentView!;content.addSubview(foldStage);content.addSubview(stack);content.addSubview(scroll)
        foldStage.translatesAutoresizingMaskIntoConstraints=false;scroll.translatesAutoresizingMaskIntoConstraints=false
        NSLayoutConstraint.activate([
            foldStage.leadingAnchor.constraint(equalTo:content.leadingAnchor),foldStage.topAnchor.constraint(equalTo:content.topAnchor),
            foldStage.bottomAnchor.constraint(equalTo:content.bottomAnchor),foldStage.widthAnchor.constraint(equalTo:content.widthAnchor,multiplier:0.44),
            stack.leadingAnchor.constraint(equalTo:foldStage.trailingAnchor,constant:42),stack.trailingAnchor.constraint(equalTo:content.trailingAnchor,constant:-42),
            stack.topAnchor.constraint(equalTo:content.topAnchor,constant:42),stack.bottomAnchor.constraint(lessThanOrEqualTo:content.bottomAnchor,constant:-30),
            scroll.leadingAnchor.constraint(equalTo:stack.leadingAnchor),scroll.trailingAnchor.constraint(equalTo:stack.trailingAnchor),
            scroll.topAnchor.constraint(equalTo:stack.bottomAnchor,constant:16),scroll.heightAnchor.constraint(equalToConstant:160),
            titleLabel.widthAnchor.constraint(equalTo:stack.widthAnchor),detailLabel.widthAnchor.constraint(equalTo:stack.widthAnchor),
            receiptLabel.widthAnchor.constraint(equalTo:stack.widthAnchor),badgeLabel.widthAnchor.constraint(equalTo:stack.widthAnchor),caption.widthAnchor.constraint(equalTo:stack.widthAnchor)
        ])
        let menu=NSMenu()
        menu.addItem(withTitle:"Show testnet status",action:#selector(showWindow),keyEquivalent:"").target=self
        menu.addItem(withTitle:"Save status image…",action:#selector(saveStatusImage),keyEquivalent:"").target=self
        menu.addItem(.separator())
        menu.addItem(withTitle:"Quit peer",action:#selector(quit),keyEquivalent:"q").target=self
        menuItem=NSStatusBar.system.statusItem(withLength:NSStatusItem.variableLength)
        menuItem.button?.title="◌ Testnet";menuItem.menu=menu
        let mainMenu=NSMenu();let appItem=NSMenuItem();mainMenu.addItem(appItem);appItem.submenu=menu.copy() as? NSMenu;NSApp.mainMenu=mainMenu
        window.center();showWindow()
        #if ASSEMBLY_PREVIEW
        if startAssemblyPreview(self) {return}
        #endif
        #if ASSEMBLY_CAPTURE
        startAssemblyCapture(self)
        #endif
        DispatchQueue.global(qos:.utility).async {self.runParticipant()}
    }
    #if ASSEMBLY_PREVIEW || ASSEMBLY_CAPTURE
    func previewCapture(to url:URL) throws {try captureStatus(to:url)}
    func previewCaptureWindows(to directory:URL) throws {
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true)
        for (index,visibleWindow) in NSApp.windows.filter({$0.isVisible}).enumerated() {
            guard let content=visibleWindow.contentView else {continue}
            content.layoutSubtreeIfNeeded();visibleWindow.displayIfNeeded()
            guard let bitmap=content.bitmapImageRepForCachingDisplay(in:content.bounds) else {continue}
            content.cacheDisplay(in:content.bounds,to:bitmap)
            if let png=bitmap.representation(using:.png,properties:[:]) {
                try png.write(to:directory.appendingPathComponent("window-\(index).png"),options:.atomic)
            }
        }
    }
    #endif
    #if ASSEMBLY_PREVIEW
    func previewEvent(_ event:String,_ fields:[String:Any]) {emit(event,fields)}
    func previewMark() {
        window.title="SIMULATED JOURNEY / AttestNode Assembly"
        stateLabel.stringValue="SIMULATION / "+stateLabel.stringValue.replacingOccurrences(of:"SIMULATION / ",with:"")
    }
    #endif
    private func diagnosticReport()->String {
        let entries=eventLines.compactMap {line -> [String:Any]? in
            guard let data=line.data(using:.utf8) else {return nil}
            return (try? JSONSerialization.jsonObject(with:data)) as? [String:Any]
        }
        var replacements=[String:String]()
        func sensitive(_ name:String)->Bool {
            let key=name.lowercased().replacingOccurrences(of:"_",with:"").replacingOccurrences(of:"-",with:"")
            return key.contains("privatekey") || key.contains("password") || key.contains("secret") || ["mnemonic","seed","seedphrase"].contains(key)
        }
        func collect(_ value:Any) {
            if let dict=value as? [String:Any] {
                for (key,value) in dict {
                    if sensitive(key),let text=value as? String,!text.isEmpty {replacements[text]="[redacted]"}
                    collect(value)
                }
            } else if let array=value as? [Any] {array.forEach(collect)}
        }
        for entry in entries {
            collect(entry)
            // An RPC failure can echo its credential-bearing URL or path.
            if let rpc=entry["rpc"] as? String,let url=URLComponents(string:rpc) {
                var origin=URLComponents();origin.scheme=url.scheme;origin.host=url.host;origin.port=url.port
                replacements[rpc]=origin.string ?? "[endpoint omitted]"
                let privateParts=[url.user,url.password,url.path == "/" ? nil:url.path]+(url.queryItems ?? []).map {$0.value}
                for part in privateParts.compactMap({$0}) where !part.isEmpty {replacements[part]="[redacted]"}
            }
        }
        let ordered=replacements.keys.sorted {$0.count>$1.count}
        func redact(_ value:Any)->Any {
            if let text=value as? String {return ordered.reduce(text) {$0.replacingOccurrences(of:$1,with:replacements[$1]!)}}
            if let dict=value as? [String:Any] {return dict.mapValues(redact).filter {!sensitive($0.key)}}
            if let array=value as? [Any] {return array.map(redact)}
            return value
        }
        return entries.compactMap {entry in
            guard let encoded=try? JSONSerialization.data(withJSONObject:redact(entry),options:[.sortedKeys]) else {return nil}
            return String(decoding:encoded,as:UTF8.self)
        }.joined(separator:"\n")+"\n"
    }
    @objc private func saveDiagnosticReport() {
        let panel=NSSavePanel();panel.nameFieldStringValue="AttestNode-diagnostics.jsonl"
        panel.message="Review this report before sharing. It includes public account identifiers and recent events; no private keys."
        if panel.runModal() == .OK,let url=panel.url {
            do {try diagnosticReport().write(to:url,atomically:true,encoding:.utf8)}
            catch {NSAlert(error:error).runModal()}
        }
    }
    @objc private func showWindow() {window.makeKeyAndOrderFront(nil);NSApp.activate(ignoringOtherApps:true)}
    private func runUpgradeOperation<T>(_ work:@escaping (Node)throws->T,done:@escaping (T)->Void) {
        guard let node else {return}
        upgradeButton.isEnabled=false
        node.enqueueOperation {participant in
            do {
                let result=try work(participant)
                DispatchQueue.main.async {self.upgradeButton.isEnabled=true;done(result)}
            } catch {
                DispatchQueue.main.async {self.upgradeButton.isEnabled=true;NSAlert(error:error).runModal()}
            }
        }
    }
    private func saveUpgradeFile<T:Encodable>(_ value:T,name:String,afterSave:@escaping ()->Void = {}) {
        let panel=NSSavePanel();panel.nameFieldStringValue=name
        if panel.runModal() == .OK,let url=panel.url {
            do {let encoder=JSONEncoder();encoder.outputFormatting=[.prettyPrinted,.sortedKeys];try encoder.encode(value).write(to:url,options:.atomic);afterSave()}
            catch {NSAlert(error:error).runModal()}
        }
    }
    @objc private func developerUpgrade() {
        let alert=NSAlert();alert.messageText="Earn the independent-builder NFT"
        alert.informativeText="Save an invitation from this app. Build and sign an admitted copy using your own Apple Developer team, then import the invitation in that copy. Bring its request back here to approve the account handoff. Your private key is never exported."
        for title in ["Save invitation…","Import upgrade file…","Open build guide","Cancel"] {alert.addButton(withTitle:title)}
        switch alert.runModal().rawValue {
        case 1000:
            runUpgradeOperation({try $0.exportUpgradeInvitation()}) {invitation in
                self.saveUpgradeFile(invitation,name:"AttestNode-upgrade-invitation.json") {
                    let notice=NSAlert();notice.messageText="Use this builder bundle identifier"
                    notice.informativeText="Create an explicit App ID and signing profile for this identifier under your own developer team. It is also saved in the invitation."
                    let identifier=NSTextField(labelWithString:invitation.bundleId);identifier.isSelectable=true;identifier.frame=NSRect(x:0,y:0,width:580,height:24)
                    notice.accessoryView=identifier;notice.runModal()
                }
            }
        case 1001:importUpgradeFile()
        case 1002:
            NSWorkspace.shared.open(URL(string:"https://github.com/amiller/apple-attest-p2p/blob/main/release/builder-guide.md")!)
        default:break
        }
    }
    private func importUpgradeFile() {
        let panel=NSOpenPanel();panel.canChooseDirectories=false;panel.allowsMultipleSelection=false
        guard panel.runModal() == .OK,let url=panel.url else {return}
        do {
            let size=try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0
            try need(size>0 && size<=65536,"Upgrade file must be at most 64 KiB")
            let data=try Data(contentsOf:url);try need(data.count<=65536,"Upgrade file size")
            if let request=try? JSONDecoder().decode(UpgradeRequest.self,from:data) {
                runUpgradeOperation({try $0.validateUpgrade(request)}) {team in
                    let alert=NSAlert();alert.messageText="Transfer NFT account control to your new app?"
                    alert.informativeText="The request proves an admitted app under an independent signing team. Confirm that this is the request you created in your own signed copy.\n\nNew key: \(hex(keccak(request.newPoint).prefix(8)))\nTeam proof: \(hex(team.prefix(8)))\n\nThe new copy will control this account and claim the builder NFT. This copy will no longer control it."
                    alert.addButton(withTitle:"Approve handoff");alert.addButton(withTitle:"Cancel")
                    if alert.runModal() == .alertFirstButtonReturn {
                        self.runUpgradeOperation({try $0.approveUpgrade(request)}) {_ in
                            self.upgradeButton.isEnabled=false
                            let done=NSAlert();done.messageText="Account handoff confirmed";done.informativeText="Return to your independently signed app. It will claim the builder NFT automatically.";done.runModal()
                        }
                    }
                }
            } else {
                let invitation=try JSONDecoder().decode(UpgradeInvitation.self,from:data)
                runUpgradeOperation({try $0.prepareUpgrade(invitation)}) {request in
                    self.saveUpgradeFile(request,name:"AttestNode-upgrade-request.json") {
                        self.runUpgradeOperation({try $0.trackUpgrade(request)}) {_ in
                            let done=NSAlert();done.messageText="Bring this request to your original app";done.informativeText="Import the request there and approve the handoff. Keep both copies open. New key: \(hex(keccak(request.newPoint).prefix(8)))";done.runModal()
                        }
                    }
                }
            }
        } catch {NSAlert(error:error).runModal()}
    }
    @objc private func toggleDetails() {
        let show=diagnosticScroll.isHidden;diagnosticScroll.isHidden = !show
        detailsButton.title=show ? "Hide technical details":"Show technical details"
        var frame=window.frame;let delta:CGFloat=show ? 200:-200
        frame.origin.y-=delta;frame.size.height+=delta;window.setFrame(frame,display:true,animate:true)
    }
    private func captureStatus(to url:URL) throws {
        guard let content=window.contentView else {throw DemoError.invalid("status view unavailable")}
        content.layoutSubtreeIfNeeded();window.displayIfNeeded()
        guard let bitmap=content.bitmapImageRepForCachingDisplay(in:content.bounds) else {throw DemoError.invalid("status image unavailable")}
        content.cacheDisplay(in:content.bounds,to:bitmap)
        guard let png=bitmap.representation(using:.png,properties:[:]) else {throw DemoError.invalid("status PNG unavailable")}
        try png.write(to:url,options:.atomic)
    }
    @objc private func saveStatusImage() {
        let panel=NSSavePanel();panel.nameFieldStringValue="AttestNode-status.png"
        if panel.runModal() == .OK,let url=panel.url {
            do {try captureStatus(to:url)} catch {NSAlert(error:error).runModal()}
        }
    }
    @objc private func openBadgeReceipt() {
        guard let receiptContract=status["badgeContract"] as? String,let token=status["badgeToken"],
              (status["chainId"] as? NSNumber)?.uint64Value==84532,let url=URL(string:"https://sepolia.basescan.org/token/\(artworkContract(receiptContract, token:token))?a=\(token)") else {return}
        NSWorkspace.shared.open(url)
    }
    private func artworkContract(_ receipt:String,token:Any)->String {
        // Only these original receipts have verified, published artwork reissues.
        if receipt.lowercased()=="0x6ac5fb83f5bf615842b5a9a6c50b8011fab50c3b",["1","2"].contains(String(describing:token)) {
            return "0xc3da5f4d5013dD6fB4a16EF3ace0C0F9e1F8C1Ed"
        }
        return receipt
    }
    private func showVerifiedArtwork() {
        foldStage.image=nil;foldStage.token=status["badgeToken"].map {String(describing:$0)}
        guard (status["chainId"] as? NSNumber)?.uint64Value==84532,
              (status["badgeContract"] as? String)?.lowercased()=="0x6ac5fb83f5bf615842b5a9a6c50b8011fab50c3b",
              let token=status["badgeToken"] else {return}
        let number=String(describing:token)
        guard ["1","2"].contains(number),let url=Bundle.main.url(forResource:"fold-token-"+number,withExtension:"png"),let image=NSImage(contentsOf:url) else {return}
        foldStage.image=image;foldStage.token=String(format:"%03d",Int(number) ?? 0)
        titleLabel.stringValue="Your Fold.\n"+String(format:"%03d",Int(number) ?? 0)
    }
    @objc private func quit() {NSApp.terminate(nil)}
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication)->Bool {false}

    private func runParticipant() {
        do {
            var settings=ReleaseNetwork.settings
            // Developer launch only: explicit local config, no editor or buttons.
            if CommandLine.arguments.count==3 && CommandLine.arguments[1]=="--config" {
                settings=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2]))) as? [String:Any]
            }
            guard var config=settings else {
                emit("configuration unavailable",["message":"This development build has no validated release network yet."]);return
            }
            if config["name"] == nil {
                let defaults=UserDefaults.standard
                let identity=defaults.string(forKey:"participantName") ?? UUID().uuidString.lowercased()
                defaults.set(identity,forKey:"participantName");config["name"]=identity
            }
            config["persistentIdentity"]=true
            let cfg=try Config(config)
            try need(!cfg.peer.isEmpty,"missing faucet peer")
            emit("configured",["network":ReleaseNetwork.name,"chainId":cfg.chainId,"registry":cfg.registry,"participant":cfg.name])
            let participant=Node(cfg,log:emit);DispatchQueue.main.async {self.node=participant}
            var delay:Double=2
            while true {
                do {try participant.participate();return}
                catch {
                    let message=String(describing:error)
                    if message.contains("App Attest unsupported") || message.contains("identity already running") {
                        emit("stopped",["error":message]);return
                    }
                    emit("retrying",["error":message,"retryAfterSeconds":delay])
                    Thread.sleep(forTimeInterval:delay);delay=min(delay*2,60)
                }
            }
        } catch {emit("stopped",["error":String(describing:error)])}
    }
    private func emit(_ event:String,_ fields:[String:Any]) {
        var entry=fields;entry["event"]=event;entry["t"]=Date().timeIntervalSince1970
        guard let data=try? JSONSerialization.data(withJSONObject:entry,options:[.sortedKeys]) else {return}
        let line=String(decoding:data,as:UTF8.self);print(line);fflush(stdout)
        DispatchQueue.main.async {
            self.eventLines.append(line);self.eventLines=Array(self.eventLines.suffix(100))
            self.diagnostics.string=self.eventLines.joined(separator:"\n")
            self.status.merge(fields){_,new in new};self.status["lastEvent"]=event;self.status["updatedAt"]=entry["t"]
            switch event {
            case "account handed off":self.badgeLabel.stringValue="This account was handed off. Continue in your independently signed copy.";self.upgradeButton.isEnabled=false;self.badgeReceiptButton.isEnabled=false
            case "upgrade awaiting approval":self.badgeLabel.stringValue="Waiting for your original app to approve the handoff…";self.badgeReceiptButton.isEnabled=false
            case "upgrade approved":self.badgeLabel.stringValue="Account handoff confirmed. Continue in your independently signed app."
            case "builder claiming":self.badgeLabel.stringValue="Claiming your independent-builder NFT…"
            case "badge preparing":self.badgeLabel.stringValue="Preparing your personal NFT account…"
            case "badge claiming":self.badgeLabel.stringValue="Claiming your participant NFT…"
            case "badge retrying":self.badgeLabel.stringValue="NFT claim pending; retrying automatically. Your peer remains connected."
            case "badge claimed":self.upgradeButton.isEnabled=true;self.badgeReceiptButton.isEnabled=(fields["chainId"] as? NSNumber)?.uint64Value==84532;self.badgeLabel.stringValue="\((fields["badgeLevel"] as? NSNumber)?.intValue==2 ? "Independent builder":"Participant") / #\(fields["badgeToken"] ?? "") confirmed";self.showVerifiedArtwork()
            case "connecting":self.setState("connecting","Connecting.","Checking the configured network and relay.")
            case "attesting":self.setState("attesting","Verify the app.","Checking the signed app and this Mac’s attestation identity.")
            case "getting key":self.setState("getting-key","Finding a peer.","Waiting for an admitted peer and a verifiable receipt.")
            case "key verified":
                self.receiptLabel.stringValue="Shared testnet key verified · epoch \(fields["keyEpoch"] ?? 0)"
            case "participating":self.setState("active","You’re in.","Your shared testnet key is verified. This Mac is participating in the network.");self.showVerifiedArtwork()
            case "peer holds group key":
                if let peer=fields["peer"] as? String {self.peerNames.insert(peer)}
                self.status["verifiedPeersThisSession"]=self.peerNames.count
            case "retrying":self.setState("retrying","Connection interrupted; retrying…","Retrying in \(fields["retryAfterSeconds"] ?? 0) seconds. Details are below.")
            case "configuration unavailable":self.setState("unconfigured","Release network not configured",fields["message"] as? String ?? "")
            case "stopped":self.setState("stopped","Couldn’t connect.","The connection attempt stopped. Save a diagnostic report for help; technical details contain the exact error.")
            default:break
            }
            #if !ASSEMBLY_PREVIEW
            self.writeStatus()
            #endif
            #if ASSEMBLY_CAPTURE
            assemblyCaptureEvent(event,app:self)
            #endif
            // Explicit agent invocation captures the same AppKit view as the menu
            // action, after a confirmed claim. No whole-desktop permission needed.
            let args=CommandLine.arguments
            if event=="badge claimed",args.count==3,args[1]=="--capture-status" {
                do {try self.captureStatus(to:URL(fileURLWithPath:args[2]));print("Status image saved");fflush(stdout)}
                catch {NSLog("Status image failed: %@",String(describing:error))}
            }
        }
    }
    private func setState(_ state:String,_ title:String,_ detail:String) {
        status["state"]=state;titleLabel.stringValue=title;detailLabel.stringValue=detail
        stateLabel.stringValue=state == "active" ? "● CONNECTED / PEER ACTIVE":state.uppercased().replacingOccurrences(of:"-",with:" ")
        stateLabel.textColor=["stopped","retrying","unconfigured"].contains(state) ? AssemblyPalette.red:AssemblyPalette.blue
        participationCaption.stringValue="RESEARCH TESTNET / NO MONETARY VALUE\n"+(state == "active" ? "Closing this window keeps your peer running. Quit stops it.":"Keep the app open while connecting. Quit stops this session.")
        menuItem.button?.title=state=="active" ? "● Testnet":"◌ Testnet"
    }
    private func writeStatus() {
        // Agent-readable evidence follows exactly the same events as the window.
        guard let root=try? FileManager.default.url(for:.applicationSupportDirectory,in:.userDomainMask,appropriateFor:nil,create:true) else {return}
        let dir=root.appendingPathComponent("AttestNode",isDirectory:true)
        do {
            try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true)
            let file=dir.appendingPathComponent("status.json")
            try JSONSerialization.data(withJSONObject:status,options:[.sortedKeys,.prettyPrinted]).write(to:file,options:.atomic)
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:file.path)
        } catch {NSLog("Could not write participant status: %@",String(describing:error))}
    }
}
func runParticipantApp() {
    let app=NSApplication.shared;let delegate=ParticipantApp();app.delegate=delegate
    withExtendedLifetime(delegate){app.run()}
}
#endif
