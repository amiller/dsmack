import XCTest

final class NodeUITests:XCTestCase {
    private func launch(_ scenario:String) -> XCUIApplication {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchEnvironment["ATTESTNODE_UI_SCENARIO"] = scenario
        app.launch()
        XCTAssertTrue(app.staticTexts["SIMULATOR SCENARIO — no hardware attestation or NFT transaction"].waitForExistence(timeout:10))
        XCTAssertTrue(app.staticTexts["SIMULATOR SCENARIO — no hardware attestation or NFT transaction"].isHittable)
        return app
    }
    private func capture(_ label:String) {
        let evidence = XCTAttachment(screenshot:XCUIScreen.main.screenshot())
        evidence.name = label;evidence.lifetime = .keepAlways;add(evidence)
    }
    func testUnsupportedSimulatorAndPersistentIdentity() throws {
        let app = XCUIApplication()
        func participant() throws -> String {
            app.launch()
            XCTAssertTrue(app.staticTexts["Couldn’t join the network"].waitForExistence(timeout:10))
            app.buttons["Technical details"].tap()
            let report = app.staticTexts.containing(NSPredicate(format:"label CONTAINS %@", "appAttestSupported")).firstMatch.label
            let events = try report.split(separator:"\n").map {try JSONSerialization.jsonObject(with:Data($0.utf8)) as! [String:Any]}
            XCTAssertTrue(events.contains {($0["appAttestSupported"] as? Bool) == false})
            XCTAssertFalse(events.contains {$0["event"] as? String == "badge claimed"})
            return try XCTUnwrap(events.first {$0["event"] as? String == "configured"}?["participant"] as? String)
        }
        let first = try participant()
        capture("REAL-simulator-unsupported")
        app.terminate()
        XCTAssertEqual(try participant(),first,"Restart must retain participant identity")
    }
    func testAttesting() {
        let app = launch("attesting")
        XCTAssertTrue(app.staticTexts["Verifying this app…"].exists)
        XCTAssertFalse(app.buttons["Listen"].exists)
        XCTAssertFalse(app.textViews.firstMatch.exists)
        capture("SIMULATED-attesting")
    }
    func testClaimed() {
        let app = launch("claimed")
        XCTAssertTrue(app.staticTexts["You’re connected"].exists)
        XCTAssertTrue(app.staticTexts["Participant NFT #42 confirmed"].exists)
        capture("SIMULATED-claimed")
    }
    func testUpgradeControlsAndFilePicker() {
        let app = launch("claimed")
        app.buttons["Developer upgrade"].tap()
        XCTAssertTrue(app.buttons["Save invitation"].isEnabled)
        app.buttons["Import upgrade file"].tap()
        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout:5))
        capture("SIMULATED-upgrade-file-picker")
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.buttons["Save invitation"].waitForExistence(timeout:5))
        // A simulator scenario cannot accidentally invoke a real signer.
        app.buttons["Save invitation"].tap()
        XCTAssertTrue(app.staticTexts["Connect to the network before continuing the upgrade."].waitForExistence(timeout:5))
    }
    func testUpgradeInvitationExport() {
        let app = launch("upgrade-export")
        app.buttons["Developer upgrade"].tap()
        app.buttons["Save invitation"].tap()
        XCTAssertTrue(app.buttons["Save"].waitForExistence(timeout:10))
        capture("SIMULATED-invitation-export-picker")
        app.buttons["Save"].tap()
        if app.buttons["Replace"].waitForExistence(timeout:2) {app.buttons["Replace"].tap()}
        XCTAssertTrue(app.staticTexts["SIMULATED invitation saved and read back successfully. No account transfer occurred."].waitForExistence(timeout:10))
        capture("SIMULATED-invitation-export-readback")
        app.buttons["OK"].tap()
        app.buttons["Import upgrade file"].tap()
        let saved = app.cells.matching(NSPredicate(format:"label CONTAINS %@", "AttestNode-upgrade-invitation")).firstMatch
        XCTAssertTrue(saved.waitForExistence(timeout:10))
        capture("SIMULATED-invitation-reimport-picker")
        saved.tap()
        // The actual importer decoded the saved invitation and reached the
        // Node operation guard. A simulator fixture has no real Node to sign.
        XCTAssertTrue(app.staticTexts["Connect to the network before continuing the upgrade."].waitForExistence(timeout:10))
    }
    func testUpgradeConsentAndCancellation() {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchEnvironment["ATTESTNODE_UI_SCENARIO"] = "upgrade-approval"
        app.launch()
        XCTAssertTrue(app.buttons["Approve handoff"].waitForExistence(timeout:10))
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format:"label CONTAINS %@", "SIMULATED-ACCOUNT")).firstMatch.exists)
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format:"label CONTAINS %@", "SIMULATED-TEAM")).firstMatch.exists)
        capture("SIMULATED-upgrade-consent")
        app.buttons["Cancel"].tap()
        XCTAssertFalse(app.buttons["Approve handoff"].exists)
        XCTAssertFalse(app.staticTexts["Connect to the network before continuing the upgrade."].exists)
        XCTAssertTrue(app.staticTexts["Participant NFT #42 confirmed"].exists)
        app.terminate();app.launch()
        XCTAssertTrue(app.buttons["Approve handoff"].waitForExistence(timeout:10))
        app.buttons["Approve handoff"].tap()
        // Proves the presented request reached the action after modal dismissal;
        // the fixture has no Node, so no signing/network operation can occur.
        XCTAssertTrue(app.staticTexts["Connect to the network before continuing the upgrade."].waitForExistence(timeout:5))
        XCTAssertFalse(app.staticTexts["Account handoff confirmed. Continue in your independently signed copy to claim the builder NFT."].exists)
    }
    func testUpgradeRejectsMalformedAndOversizedFiles() {
        continueAfterFailure = false
        let app = XCUIApplication()
        for (scenario,message) in [
            ("upgrade-invalid-file","This is not an AttestNode upgrade invitation or request."),
            ("upgrade-oversize-file","Upgrade file must be at most 64 KiB")
        ] {
            app.launchEnvironment["ATTESTNODE_UI_SCENARIO"] = scenario
            app.launch()
            XCTAssertTrue(app.staticTexts[message].waitForExistence(timeout:10))
            XCTAssertFalse(app.buttons["Approve handoff"].exists)
            capture("SIMULATED-"+scenario)
            app.buttons["OK"].tap()
            app.terminate()
        }
    }
    func testCodeEvidenceUnavailableInSimulator() {
        let app = launch("apple-failure")
        app.buttons["Technical details"].tap()
        app.buttons["Prepare code evidence"].tap()
        let message = "Code admission evidence requires the installed iPhone app. Simulator evidence cannot admit a device build."
        XCTAssertTrue(app.staticTexts[message].waitForExistence(timeout:10))
        XCTAssertFalse(app.buttons["Share code evidence"].exists)
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format:"label CONTAINS %@", "code evidence unavailable")).firstMatch.exists)
        capture("SIMULATED-code-evidence-unavailable")
    }
    func testRetry() {
        let app = launch("retry")
        XCTAssertTrue(app.staticTexts["Waiting to reconnect…"].exists)
        capture("SIMULATED-retry")
    }
    func testFailureReport() {
        let app = launch("apple-failure")
        XCTAssertTrue(app.staticTexts["Couldn’t join the network"].exists)
        app.buttons["Technical details"].tap()
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format:"label CONTAINS %@", "attestKey")).firstMatch.exists)
        capture("SIMULATED-apple-failure-details")
        app.buttons["Technical details"].tap()
        app.buttons["Share diagnostic report"].tap()
        XCTAssertTrue(app.cells["Copy"].waitForExistence(timeout:5))
        capture("SIMULATED-share-report")
        app.cells["Copy"].tap()
    }
}
