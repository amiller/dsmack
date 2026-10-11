import XCTest

final class LabUITests: XCTestCase {
    private func launch(_ endpoint: String = "https://localhost:8443") -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["--endpoint", endpoint]
        app.launch()
        return app
    }

    func testRealSimulatorCannotEnroll() {
        let app = launch()
        XCTAssertTrue(app.staticTexts["appAttestSupport"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.staticTexts["appAttestSupport"].label, "App Attest supported: no")
        XCTAssertFalse(app.buttons["generateKey"].isEnabled)
        XCTAssertFalse(app.buttons["attestKey"].isEnabled)
        XCTAssertFalse(app.buttons["assertOperation"].isEnabled)
    }

    func testRealHTTPSAndLocalOperation() {
        let app = launch()
        #if MODIFIED
        let output = 5
        #else
        let output = 4
        #endif
        XCTAssertEqual(app.staticTexts["localOutput"].label, "Local double(2): \(output) (unattested)")
        app.buttons["checkSetup"].tap()
        let status = app.staticTexts["labStatus"]
        let success = NSPredicate(format: "label BEGINSWITH %@", "HTTPS verified.")
        expectation(for: success, evaluatedWith: status)
        waitForExpectations(timeout: 25)
        XCTAssertTrue(status.label.contains("Local output \(output) (unattested)"))
        XCTAssertTrue(status.label.contains("unsupported"))
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "HTTPS verified - simulator"
        screenshot.lifetime = .keepAlways
        add(screenshot)
        app.swipeUp()
        let resultScreenshot = XCTAttachment(screenshot: app.screenshot())
        resultScreenshot.name = "HTTPS verified result - simulator"
        resultScreenshot.lifetime = .keepAlways
        add(resultScreenshot)
        // Keep the result visible for the requested simulator recording.
        Thread.sleep(forTimeInterval: 4)
        XCTAssertFalse(app.buttons["generateKey"].isEnabled)
    }

    func testUntrustedTLSCertificateRejected() {
        let app = launch("https://localhost:8444")
        app.buttons["checkSetup"].tap()
        let status = app.staticTexts["labStatus"]
        expectation(for: NSPredicate(format: "label BEGINSWITH %@", "Setup failed:"), evaluatedWith: status)
        waitForExpectations(timeout: 25)
        XCTAssertTrue(status.label.lowercased().contains("certificate"), status.label)
    }

    func testHTTPRejectedBeforeConnection() {
        let app = launch("http://localhost:8443")
        app.buttons["checkSetup"].tap()
        let status = app.staticTexts["labStatus"]
        expectation(for: NSPredicate(format: "label CONTAINS %@", "Enter an HTTPS server URL"), evaluatedWith: status)
        waitForExpectations(timeout: 10)
    }
}
