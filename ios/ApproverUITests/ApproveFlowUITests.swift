import XCTest

/// Drives the real app against a live hub and demo adapter (see ios/README.md, "End-to-end UI test").
/// The hub's management UI comes from the environment: `TEST_RUNNER_INTERPOSE_ADMIN_URL=http://127.0.0.1:18741` on
/// xcodebuild. The hub runs without OIDC (local mode), so phone sign-in answers at once for `?user=vince`.
/// Expects one normal-risk request titled "claude wants RW on db-01" and one high-risk "helper wants ADMIN on web-02".
final class ApproveFlowUITests: XCTestCase {
    /// The app switcher's snapshot is taken once the scene is no longer active: the screen must be covered by then.
    /// Notification Center pulled over the app takes it out of the active state too (to background, on iOS 27), and
    /// leaves its accessibility tree to check. Needs no hub.
    func testPrivacyCoverWhenNotActive() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-interposeReset"]
        app.launch()
        XCTAssertTrue(app.textFields["interpose-hub.home.example"].waitForExistence(timeout: 10))
        let cover = app.descendants(matching: .any)["privacy-cover"]
        XCTAssertFalse(cover.exists, "covered while active")

        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.2, dy: 0.001))
            .press(forDuration: 0.1, thenDragTo: springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.2, dy: 0.7)))
        XCTAssertTrue(cover.waitForExistence(timeout: 5), "not covered once not active")
        attach(XCUIScreen.main, "covered")

        springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.99))
            .press(forDuration: 0.1, thenDragTo: springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.2)))
        XCTAssertTrue(app.textFields["interpose-hub.home.example"].waitForExistence(timeout: 10))
        XCTAssertFalse(cover.waitForExistence(timeout: 2), "still covered once active again")
    }

    func testEnrollApproveAndHoldToApprove() throws {
        guard let admin = ProcessInfo.processInfo.environment["INTERPOSE_ADMIN_URL"], !admin.isEmpty else {
            throw XCTSkip("INTERPOSE_ADMIN_URL not set: needs a running hub")
        }
        let app = XCUIApplication()
        app.launchArguments = ["-interposeReset"]
        app.launch()

        // Step 1: the Interpose server. Return submits, and the app checks the address is one (/app/hello).
        let address = app.textFields["interpose-hub.home.example"]
        XCTAssertTrue(address.waitForExistence(timeout: 10), "the app does not open on the server step")
        attach(app, "server-step")
        address.tap()
        if let old = address.value as? String, !old.isEmpty, old != address.placeholderValue {
            address.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: old.count)) // a remembered address
        }
        address.typeText(admin + "\n")

        // Step 2: continue on the server. This hub is in local mode, so it asks for a user id instead of a sign-in;
        // the app still opens the server in a private browser session and gets the enrollment link back.
        let user = app.textFields["Your user id"]
        XCTAssertTrue(user.waitForExistence(timeout: 10), "the server was not accepted")
        user.tap()
        user.typeText("vince\n")
        let onServer = app.buttons.containing(NSPredicate(format: "label BEGINSWITH 'Continue on'")).firstMatch
        scrollTo(onServer, in: app)
        attach(app, "server-accepted")
        onServer.tap()

        // Step 3: connect this device.
        let newAccount = app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'first device of a new account'")).firstMatch
        XCTAssertTrue(newAccount.waitForExistence(timeout: 20), "the server sent back no enrollment link")
        attach(app, "connect-step")
        let connect = app.buttons["Connect this device"]
        scrollTo(connect, in: app)
        connect.tap()

        let done = app.buttons["Done"]
        XCTAssertTrue(done.waitForExistence(timeout: 20), "enrollment summary did not appear")
        attach(app, "enrolled")
        done.tap()

        // The hub lists the demo adapter; its key is pinned only once confirmed here, and its requests wait until then.
        XCTAssertFalse(app.staticTexts["claude wants RW on db-01"].waitForExistence(timeout: 3), "a request from an unconfirmed adapter")
        let trust = app.buttons["Trust…"]
        XCTAssertTrue(trust.waitForExistence(timeout: 20), "the hub's adapter is not offered for confirmation")
        attach(app, "adapter-offered")
        trust.tap()
        let matches = app.buttons["It matches: trust it"]
        XCTAssertTrue(matches.waitForExistence(timeout: 5), "no adapter confirmation")
        matches.tap()

        // Normal risk: a plain Approve.
        let rw = app.staticTexts["claude wants RW on db-01"]
        XCTAssertTrue(rw.waitForExistence(timeout: 20), "request not in the inbox")
        attach(app, "inbox")
        rw.tap()
        attach(app, "detail-normal")
        app.buttons["Approve"].tap()
        XCTAssertTrue(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 20), "no verified ack")
        attach(app, "approved")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // High risk: a tap is not enough; a long press is.
        let adminRequest = app.staticTexts["helper wants ADMIN on web-02"]
        XCTAssertTrue(adminRequest.waitForExistence(timeout: 10))
        adminRequest.tap()
        attach(app, "detail-high")
        let hold = app.buttons["Hold to approve"]
        XCTAssertTrue(hold.waitForExistence(timeout: 5))
        hold.tap()
        XCTAssertFalse(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 3), "a tap approved a high-risk request")
        hold.press(forDuration: 0.6)
        XCTAssertFalse(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 3), "a hold cut short approved a high-risk request")
        hold.press(forDuration: 2.5)
        XCTAssertTrue(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 20), "hold did not approve")
        attach(app, "approved-high")

        // Kill and relaunch: the decisions made here are on disk, with their verified outcome, so the inbox still
        // lists them under "Decided here" (the hub no longer lists approved requests).
        app.terminate()
        app.launchArguments = []
        app.launch()
        XCTAssertTrue(app.staticTexts["claude wants RW on db-01"].waitForExistence(timeout: 10), "normal-risk decision gone after relaunch")
        XCTAssertTrue(app.staticTexts["helper wants ADMIN on web-02"].exists, "high-risk decision gone after relaunch")
        XCTAssertTrue(app.staticTexts["Approved"].firstMatch.exists, "decision gone after relaunch")
        XCTAssertTrue(app.staticTexts["approved (confirmed by demo)"].firstMatch.waitForExistence(timeout: 10), "outcome gone after relaunch")
        attach(app, "relaunched")

        // A tap on a decision opens what was asked: the facts and the reason are kept with it on disk.
        XCTAssertFalse(app.staticTexts["fix the backups"].exists, "details shown before the decision was opened")
        app.staticTexts["claude wants RW on db-01"].tap()
        // A labelled row is one element to accessibility: "label, value".
        XCTAssertTrue(app.staticTexts["Host, db-01"].waitForExistence(timeout: 5), "the facts of a past decision do not show")
        XCTAssertTrue(app.staticTexts["Access, RW"].exists, "a levelled fact of a past decision does not show")
        XCTAssertTrue(app.staticTexts["“fix the backups”"].exists, "the reason of a past decision does not show")
        attach(app, "decided-opened")
        app.staticTexts["claude wants RW on db-01"].tap()
        XCTAssertFalse(app.staticTexts["“fix the backups”"].waitForExistence(timeout: 2), "a second tap did not close the decision")

        // Re-enroll from the Device tab with a join code for vince (same hub: what you do after leaving it, or after the
        // hub forgot the device). This phone is already on vince's roster, so it comes back active at once. The code
        // can only exist now that vince does, so the test asks the management UI for it, as an admin would.
        // Typed in as a person would paste it. Then leave the hub.
        let link2 = try joinLink(admin: admin, user: "vince")
        app.tabBars.buttons["Device"].tap()
        let another = app.buttons["Connect to another server…"]
        scrollTo(another, in: app) // below the Account section; SwiftUI lists load rows lazily
        another.tap()
        let useLink = app.buttons["I have an enrollment link"]
        XCTAssertTrue(useLink.waitForExistence(timeout: 5), "connect sheet did not open on the server step")
        useLink.tap()
        let field = app.textFields["interpose://enroll?hub=…&code=…"]
        XCTAssertTrue(field.waitForExistence(timeout: 5), "no link field")
        field.tap()
        field.typeText(link2)
        attach(app, "switch-hub")
        let connectHere = app.buttons["Connect this device"]
        scrollTo(connectHere, in: app) // the keyboard covers the lower half of the sheet
        connectHere.tap()
        XCTAssertTrue(app.buttons["Done"].waitForExistence(timeout: 20), "re-enrollment summary did not appear")
        app.buttons["Done"].tap()

        let leave = app.buttons["Leave this hub"]
        scrollTo(leave, in: app)
        leave.tap()
        app.buttons["Leave hub"].tap()
        XCTAssertTrue(app.textFields["interpose-hub.home.example"].waitForExistence(timeout: 5), "leaving did not return to the server step")
        attach(app, "left-hub")
    }

    /// A phone joining an account whose first device is the Go software device (scripts/e2e-ui.sh creates user ann
    /// and admits every join for it). Once admitted, the phone pins the account fingerprint only after the person says
    /// it matches what their other device shows; until then it shows none to give an adapter.
    func testJoinPinsTheAccountOnlyOnceConfirmed() throws {
        let env = ProcessInfo.processInfo.environment
        guard let admin = env["INTERPOSE_ADMIN_URL"], !admin.isEmpty, let account = env["INTERPOSE_ANN_ACCOUNT"], !account.isEmpty else {
            throw XCTSkip("INTERPOSE_ADMIN_URL / INTERPOSE_ANN_ACCOUNT not set: needs a running hub and user ann")
        }
        let link = try joinLink(admin: admin, user: "ann")
        let app = XCUIApplication()
        app.launchArguments = ["-interposeReset", "-interposeAutoEnroll", link]
        app.launch()

        let done = app.buttons["Done"]
        XCTAssertTrue(done.waitForExistence(timeout: 20), "enrollment summary did not appear")
        XCTAssertFalse(app.staticTexts[account].exists, "the summary shows the account fingerprint before it is confirmed")
        attach(app, "join-enrolled")
        done.tap()

        // Admitted by ann's software device: the inbox asks to compare the account fingerprint.
        let matches = app.buttons["It matches"]
        XCTAssertTrue(matches.waitForExistence(timeout: 30), "no account confirmation after admission")
        XCTAssertEqual(app.staticTexts["unconfirmed-account"].label, account)
        attach(app, "join-confirm-account")

        app.tabBars.buttons["Device"].tap()
        XCTAssertTrue(app.staticTexts["Not confirmed: compare it with your other device in the inbox."].waitForExistence(timeout: 5),
                      "Settings does not say the account is unconfirmed")
        XCTAssertFalse(app.staticTexts[account].exists, "Settings shows the unconfirmed account fingerprint as the account's")
        attach(app, "join-settings-unconfirmed")

        app.tabBars.buttons["Requests"].tap()
        matches.tap()
        app.tabBars.buttons["Device"].tap()
        XCTAssertTrue(app.staticTexts[account].waitForExistence(timeout: 20), "the confirmed account fingerprint is not shown")
        let roster = app.staticTexts.containing(NSPredicate(format: "label CONTAINS[c] 'on this account (roster 2)'")).firstMatch
        XCTAssertTrue(roster.exists, "the verified roster is not shown")
        XCTAssertTrue(app.staticTexts["this-device-badge"].exists, "this device is not marked in the device list")
        attach(app, "join-settings-confirmed")

        // This device's keys sit collapsed under the device list.
        let keys = app.buttons["This device's keys"]
        scrollTo(keys, in: app)
        XCTAssertFalse(app.staticTexts["Device id"].exists, "the device's keys are shown before they are expanded")
        keys.tap()
        XCTAssertTrue(app.staticTexts["Device id"].waitForExistence(timeout: 5), "expanding does not show the device's keys")
        attach(app, "join-settings-keys")
    }

    private func scrollTo(_ element: XCUIElement, in app: XCUIApplication) {
        for _ in 0..<6 where !(element.exists && element.isHittable) {
            app.swipeUp()
        }
        XCTAssertTrue(element.waitForExistence(timeout: 3), "\(element) not found after scrolling")
    }

    /// Posts the overview's "Add a device for <user>" form and reads the enrollment link off the page it redirects to.
    private func joinLink(admin: String, user: String) throws -> String {
        var req = URLRequest(url: URL(string: admin + "/enroll")!)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue("same-origin", forHTTPHeaderField: "Sec-Fetch-Site")
        req.httpBody = Data("user=\(user)&mode=join".utf8)
        var html = ""
        let done = expectation(description: "join code")
        URLSession.shared.dataTask(with: req) { data, _, _ in
            html = data.map { String(decoding: $0, as: UTF8.self) } ?? ""
            done.fulfill()
        }.resume()
        wait(for: [done], timeout: 10)
        guard let r = html.range(of: #"interpose://enroll[^<"']*"#, options: .regularExpression) else {
            XCTFail("no enrollment link in the management UI's page:\n\(html.prefix(500))")
            throw URLError(.cannotParseResponse)
        }
        return html[r].replacingOccurrences(of: "&amp;", with: "&")
    }

    private func attach(_ app: XCUIScreenshotProviding, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }
}
