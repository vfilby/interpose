import ApproverKit
import Foundation
import SwiftUI
import UserNotifications

/// What became of a decision this device sent.
enum Outcome: Equatable {
    case sent                  // posted; no ack yet
    case final(Ack)            // verified ack: approved, denied or expired
    case note(Ack)             // verified ack: rejected or failed. Still pending: decide again
    case unconfirmed(String)   // an ack arrived but did not verify
    case failed(String)        // the hub did not take the decision

    var isFinal: Bool { if case .final = self { return true } else { return false } }
    /// Approve / Deny stay available unless the request is settled or a decision is in flight.
    var allowsDecision: Bool {
        switch self {
        case .final, .sent: return false
        default: return true
        }
    }
}

/// This device's place in its user's roster, from the last verified head.
enum Membership: Equatable {
    case unknown   // no verified roster yet
    case pending   // enrolled with a join code; not in the roster yet
    case member
    case removed   // was a member, no longer is
}

@MainActor
final class AppModel: ObservableObject {
    let keys: KeyStore = defaultKeyStore()
    var device: Device { Device(keys: keys) }

    /// Plain http to a hub only in debug builds, and only to loopback (the simulator and a hub on the Mac). Everything
    /// else is https (HubTransport).
    #if DEBUG
    static let allowLoopbackHTTP = true
    #else
    static let allowLoopbackHTTP = false
    #endif

    @Published private(set) var hubURL: URL?
    @Published private(set) var token: String?
    @Published private(set) var adapters: [PinnedAdapter] = []
    /// Adapters the hub lists that are not pinned yet: shown with their fingerprint, used once confirmed (trustAdapter).
    @Published private(set) var offeredAdapters: [PinnedAdapter] = []
    /// Requests listed for an offered adapter: not opened until it is confirmed.
    @Published private(set) var heldRequests = 0
    @Published private(set) var conflicts: [AdapterConflict] = []
    @Published private(set) var requests: [OpenedRequest] = []
    /// Every request opened this session, kept after the hub stops listing it so its detail screen can show the outcome.
    private(set) var seen: [String: OpenedRequest] = [:]
    @Published private(set) var refused: [String] = []
    @Published private(set) var outcomes: [String: Outcome] = [:]
    /// Decisions this device sent, newest first, kept on disk (DecidedStore) so the list survives a relaunch.
    @Published private(set) var decided: [Decided] = []
    @Published var lastError: String?
    @Published var pendingLink: EnrollmentLink?

    // Account (docs/PROTOCOL.md "Users and rosters").
    @Published private(set) var user: String?
    /// Pinned account fingerprint: set at genesis, or, on a joining device, once the person confirmed that another
    /// device of the account shows the same one (confirmAccount). Never from the hub's say-so alone: the hub holds the
    /// join card, so it could put it on a chain of its own.
    @Published private(set) var account: String?
    /// The account fingerprint of the hub's chain while none is pinned: not trusted, never presented as one to pin.
    @Published private(set) var unconfirmedAccount: String?
    /// The hub's chain includes this device but its account is not pinned: the person must compare unconfirmedAccount
    /// with another device of the account before this device acts as a member.
    @Published private(set) var accountNeedsConfirmation = false
    @Published private(set) var head: Head?
    @Published private(set) var membership: Membership = .unknown
    @Published private(set) var joins: [HubJoin] = []
    @Published private(set) var rosterError: String?

    /// The one sheet RootView shows: enrolling with another hub, then the summary of an enrollment. One item, so the
    /// first can turn into the second without two sheets colliding.
    @Published var sheet: Sheet?

    enum Sheet: Identifiable, Equatable {
        case switchHub
        case summary(EnrollmentSummary)
        var id: String {
            switch self {
            case .switchHub: return "switch"
            case .summary(let s): return "summary-" + s.deviceFingerprint
            }
        }
    }

    private let secrets = KeychainStorage()
    private var pinStore: PinStore { PinStore(storage: secrets) }
    private let defaults = UserDefaults.standard
    private let decidedStore = DecidedStore()
    /// Hashes of the decisions sent per request, oldest first: a note counts only for the latest one.
    private var sentHashes: [String: [String]] = [:]
    private var ackSince: Int64 = 0

    struct EnrollmentSummary: Equatable {
        var deviceFingerprint: String
        var adapters: [PinnedAdapter]
        /// Adapters the hub lists, not pinned until confirmed.
        var offered: [PinnedAdapter]
        var user: String
        /// Pinned account fingerprint; nil while a join waits for approval.
        var account: String?
    }

    init() {
        hubURL = defaults.url(forKey: "hubURL")
        token = (try? secrets.get("hub.token")).flatMap { String(data: $0, encoding: .utf8) }
        user = defaults.string(forKey: "user")
        decided = decidedStore.load()
        do {
            try pinStore.migrate(from: defaults)
            adapters = try pinStore.load(.adapters) ?? []
            account = try pinStore.load(.account)
        } catch {
            lastError = "Pins could not be read from the Keychain: \(error.localizedDescription)"
        }
        refreshKeyState()
    }

    var isEnrolled: Bool { hubURL != nil && token != nil && keys.hasKeys() }
    var isInsecure: Bool { keys.kind == .software }
    /// Only a current member of its user's roster may approve: adapters seal requests to roster members only, and a
    /// removed device must not act on anything it still holds.
    var canApprove: Bool { membership == .member }
    var deviceFingerprint: String? { (try? keys.publicKeys()).map { Fingerprint.of($0.approve) } }
    var deviceID: String? { try? device.deviceID() }

    /// The last head accepted (seq + payload hash), persisted: refuses rollbacks and forks across restarts.
    private func knownHead() throws -> KnownHead? { try pinStore.load(.knownHead) }

    /// Why the app will not talk to the stored hub (plain http where it is refused, e.g. kept from an older version).
    var hubRefusal: String? {
        guard let hubURL else { return nil }
        do { try HubTransport.check(hubURL, allowLoopbackHTTP: Self.allowLoopbackHTTP); return nil } catch {
            return error.localizedDescription + " Connect again: Device → Connect to another server."
        }
    }

    /// No client for a hub the transport policy refuses: the token is never sent there.
    private var client: HubClient? {
        guard let hubURL, hubRefusal == nil else { return nil }
        return HubClient(base: hubURL, token: token)
    }

    private var pins: [String: Data] { Dictionary(uniqueKeysWithValues: adapters.map { ($0.id, $0.key) }) }

    // MARK: push

    @Published var pushError: String?

    /// Asks once for permission to notify, then registers with APNs on every launch (Apple's advice: tokens change).
    /// The token reaches the hub in registerPush.
    func enablePush() async {
        guard isEnrolled else { return }
        let center = UNUserNotificationCenter.current()
        let granted = (try? await center.requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        if granted { UIApplication.shared.registerForRemoteNotifications() }
    }

    /// The last APNs token, sent again when a pending join is admitted (the hub refuses it before).
    private var apnsToken: String?

    func registerPush(_ token: String) async {
        apnsToken = token
        guard let client, membership != .pending else { return }
        #if DEBUG
        let environment = "development"
        #else
        let environment = "production"
        #endif
        do {
            try await client.registerPush(token: token, environment: environment)
            pushError = nil
        } catch HubClient.HubError.http(403, _) {
            pushError = nil // still waiting for admission: sent again then
        } catch {
            pushError = "Push notifications: \(error.localizedDescription)"
        }
    }

    // MARK: enrollment

    /// mode new: this device creates the user's first roster (r1) and pins its account fingerprint.
    /// mode join: this device asks to join; it is pending until a device of the user signs a roster that includes it.
    func enroll(_ link: EnrollmentLink, name: String, pin: String?) async {
        lastError = nil
        do {
            let keys = self.keys
            let user = link.user
            let mode = link.mode
            // Before any key is made or signs: software keys on a phone would look protected to adapters, and over
            // plain http the code and the token are readable on the way.
            guard keys.canEnroll else { throw NoSecureEnclave() }
            try HubTransport.check(link.hub, allowLoopbackHTTP: Self.allowLoopbackHTTP)
            if !keys.hasKeys() { try await Task.detached { try keys.generate(pin: pin) }.value }
            // Signing uses the approve key: Face ID / PIN on a device (for a new user twice: card, then r1).
            let (card, genesis): (Envelope, Envelope?) = try await withApproveKey(pin: pin) { pin in
                let dev = Device(keys: keys)
                let card = try dev.card(name: name, pin: pin)
                return (card, mode == .new ? try dev.genesis(user: user, card: card, pin: pin) : nil)
            }
            let resp = try await HubClient(base: link.hub, token: nil).enroll(code: link.code, card: card, genesis: genesis)
            let ours = try device.deviceID()
            guard resp.deviceId == ours else {
                throw ProtocolError.mismatch("hub enrolled \(resp.deviceId), this device is \(ours)")
            }
            if let u = resp.user, u != user { throw ProtocolError.mismatch("hub enrolled this device for \(u), not \(user)") }
            // Only now, with the new hub's token in hand, forget the old hub (and the account, if it changes, or if
            // this is a new account). Adapter pins are per hub; keys are kept.
            if hubURL != link.hub || self.user != user || genesis != nil { forgetHub() }
            try secrets.set("hub.token", Data(resp.token.utf8))
            defaults.set(link.hub, forKey: "hubURL")
            hubURL = link.hub
            token = resp.token
            self.user = user
            defaults.set(user, forKey: "user")
            if let genesis {
                try setAccount(accountFingerprint(genesisPayload: try B64.decode(genesis.payload)))
            }
            await refreshRoster()
            await refreshAdapters() // only once a member: the hub serves a pending join its roster and nothing else
            pendingLink = nil
            sheet = .summary(EnrollmentSummary(deviceFingerprint: Fingerprint.of(try keys.publicKeys().approve),
                                               adapters: adapters, offered: offeredAdapters, user: user,
                                               account: account))
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func setAccount(_ a: String?) throws {
        try pinStore.save(.account, a)
        account = a
    }

    /// Lists the adapters the hub knows. Keys for ids not pinned yet are only offered: the hub could have minted them,
    /// so each is pinned when the person confirms its fingerprint (trustAdapter). A different key for a pinned id is a
    /// conflict: it is shown and never used.
    func refreshAdapters() async {
        guard let client, membership == .member else { return }
        do {
            (offeredAdapters, conflicts) = sortAdapters(try await client.adapters(), pinned: adapters)
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Pins an offered adapter key, once the person compared its fingerprint with the one the adapter prints.
    func trustAdapter(_ a: PinnedAdapter) async {
        guard offeredAdapters.contains(a), !adapters.contains(where: { $0.id == a.id }) else { return }
        let pinned = (adapters + [a]).sorted { $0.id < $1.id }
        do {
            try pinStore.save(.adapters, pinned)
        } catch {
            lastError = "Pin not saved: \(error.localizedDescription)"
            return
        }
        adapters = pinned
        offeredAdapters.removeAll { $0.id == a.id }
        await refresh()
    }

    // MARK: roster

    /// Fetches the user's chain, verifies it against the pinned account, and accepts it only if it builds on the head
    /// already accepted (no rollback, no fork). On failure the last good head stays and the error is shown.
    func refreshRoster() async {
        guard let client, let user else { return }
        do {
            let r = try await client.roster()
            guard r.user == user else { throw ProtocolError.mismatch("hub sent the roster of \(r.user)") }
            let h = try verifyChain(r.chain, user: user, account: account)
            let me = try device.deviceID()
            let inHead = h.devices[me] != nil
            if account == nil {
                // Nothing pinned yet (a join): the chain verifies, but the hub could have built it, genesis included,
                // around this device's card. Pin nothing; once it includes this device, the person compares its
                // account fingerprint with another device of the account (confirmAccount).
                let rejected: String? = try pinStore.load(.rejectedAccount)
                unconfirmedAccount = h.account
                accountNeedsConfirmation = inHead && h.account != rejected
                membership = .pending
                rosterError = h.account == rejected
                    ? "You said your other device shows a different account fingerprint than \(h.account). This hub may be "
                        + "serving a device list of its own: do not give that fingerprint to an adapter. Leave this hub."
                    : nil
                return
            }
            try requireBuildsOn(r.chain, known: try knownHead())
            try pinStore.save(.knownHead, KnownHead(h))
            head = h
            if inHead {
                membership = .member
                defaults.set(true, forKey: "wasMember")
            } else {
                membership = defaults.bool(forKey: "wasMember") ? .removed : .pending
            }
            rosterError = nil
        } catch HubClient.HubError.http(404, _) {
            membership = .pending // the hub has no roster for this user yet
        } catch HubClient.HubError.http(401, _) {
            // refresh() reports the 401
        } catch {
            rosterError = "Roster refused: \(error.localizedDescription)"
        }
    }

    func refreshJoins() async {
        guard let client, membership == .member else { joins = []; return }
        if let j = try? await client.joins() { joins = j }
    }

    /// The person compared the hub's account fingerprint with another device of the account and it matches: pin it.
    func confirmAccount(_ a: String) async {
        guard account == nil, accountNeedsConfirmation, a == unconfirmedAccount else { return }
        do {
            try setAccount(a)
        } catch {
            lastError = "Account not pinned: \(error.localizedDescription)"
            return
        }
        unconfirmedAccount = nil
        accountNeedsConfirmation = false
        await refresh()
    }

    /// The person's other device shows a different account fingerprint: never pin this one.
    func rejectAccount(_ a: String) async {
        guard account == nil, a == unconfirmedAccount else { return }
        do {
            try pinStore.save(.rejectedAccount, a)
        } catch {
            lastError = error.localizedDescription
            return
        }
        await refreshRoster()
    }

    /// Admits a device asking to join: next roster = verified head + its card, signed here (Face ID).
    func approveJoin(_ join: HubJoin, pin: String? = nil) async throws {
        try await changeRoster(pin: pin) { dev, head, pin in
            let card = try verifyCard(join.card)
            guard card.deviceId == join.deviceId else { throw ProtocolError.mismatch("join card is for another device") }
            guard head.devices[card.deviceId] == nil else { throw ProtocolError.mismatch("already a member") }
            return try dev.admit(join.card, after: head, pin: pin)
        }
        joins.removeAll { $0.deviceId == join.deviceId }
    }

    /// Removes a device: next roster = verified head without it, signed here (Face ID).
    func removeDevice(_ id: String, pin: String? = nil) async throws {
        try await changeRoster(pin: pin) { dev, head, pin in try dev.remove(id, after: head, pin: pin) }
    }

    private func changeRoster(pin: String?, _ build: @escaping @Sendable (Device, Head, String?) throws -> Envelope) async throws {
        guard let client else { throw ProtocolError.untrusted("no hub") }
        try await client.postRoster(try await nextRoster(pin: pin, build))
        await refreshRoster()
    }

    /// Builds and signs the next roster from this device's own freshly verified copy of the chain, never from the
    /// hub's say-so.
    private func nextRoster(pin: String?, _ build: @escaping @Sendable (Device, Head, String?) throws -> Envelope) async throws -> Envelope {
        guard let client, let user, let account else { throw ProtocolError.untrusted("no pinned account") }
        let r = try await client.roster()
        let h = try verifyChain(r.chain, user: user, account: account)
        try requireBuildsOn(r.chain, known: try knownHead())
        guard h.devices[try device.deviceID()] != nil else { throw ProtocolError.untrusted("this device is not a member") }
        let keys = self.keys
        let env = try await withApproveKey(pin: pin) { pin in try build(Device(keys: keys), h, pin) }
        _ = try extend(h, env) // check our own work before sending it
        return env
    }

    // MARK: inbox

    func refresh() async {
        if isEnrolled, let r = hubRefusal {
            lastError = r
            return
        }
        guard isEnrolled, let client else { return }
        let wasMember = membership == .member
        await refreshRoster()
        // The hub serves a join that is not admitted yet its roster only.
        if membership == .pending { return }
        if !wasMember && membership == .member {
            await refreshAdapters()
            if let apnsToken { await registerPush(apnsToken) }
        }
        await refreshJoins()
        do {
            var opened: [OpenedRequest] = []
            var bad: [String] = []
            var held = 0
            for l in try await client.requests() {
                if pins[l.adapter] == nil, offeredAdapters.contains(where: { $0.id == l.adapter }) {
                    held += 1 // its adapter's key is not confirmed yet
                    continue
                }
                do {
                    opened.append(try device.open(l, pinned: pins))
                } catch {
                    bad.append("\(l.adapter)/\(l.id): \(error.localizedDescription)")
                }
            }
            requests = opened.sorted { $0.record.createdAt > $1.record.createdAt }
            for r in opened { seen[r.id] = r }
            refused = bad
            heldRequests = held

            applyAcks(try await client.acks(since: ackSince))
            lastError = nil
        } catch HubClient.HubError.http(401, _) {
            lastError = "The hub no longer recognizes this device: it was revoked, or the hub's state was reset. "
                + "Get a new enrollment code, then Device → Connect to another server (the same server works too)."
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Final acks (approved, denied, expired) settle a request whoever decided it. Notes (rejected, failed) count
    /// only when they answer this device's latest decision; older or foreign ones are dropped.
    private func applyAcks(_ acks: [HubAck]) {
        var verified: [(key: String, ack: Ack)] = []
        for a in acks {
            let key = "\(a.adapter)/\(a.requestId)"
            do {
                verified.append((key, try device.verifyAck(a, pinned: pins)))
            } catch {
                if outcomes[key]?.isFinal != true, sentHashes[key] != nil { outcomes[key] = .unconfirmed(error.localizedDescription) }
            }
        }
        var maxTS = ackSince
        for (key, ack) in verified.sorted(by: { $0.ack.ts < $1.ack.ts }) {
            maxTS = max(maxTS, ack.ts)
            if outcomes[key]?.isFinal == true { continue }
            if ack.isFinal {
                outcomes[key] = .final(ack)
                if let i = decided.firstIndex(where: { $0.id == key }), decided[i].settled != ack {
                    decided[i].settled = ack
                    saveDecided()
                }
            } else if let latest = sentHashes[key]?.last, ack.decisionHash == latest {
                outcomes[key] = .note(ack)
            }
        }
        // Overlap by a few seconds so acks written in the same second as the last one seen are not missed.
        ackSince = max(ackSince, maxTS - 5)
    }

    func decide(_ req: OpenedRequest, approve: Bool, pin: String? = nil) async {
        guard let client else { return }
        guard canApprove else {
            outcomes[req.id] = .failed("this device is not a member of \(user ?? "its account")")
            return
        }
        guard let user else { return }
        let keys = self.keys
        do {
            let env = try await withApproveKey(pin: pin) { pin in
                try Device(keys: keys).decide(req, user: user, approve: approve, pin: pin)
            }
            sentHashes[req.id, default: []].append(B64.encode(sha256(try B64.decode(env.payload))))
            try await client.postDecision(DecisionPost(adapter: req.record.adapter, requestId: req.record.id, decision: env))
            outcomes[req.id] = .sent
            decided.removeAll { $0.id == req.id }
            decided.insert(Decided(id: req.id, title: req.record.title, approve: approve, at: Date()), at: 0)
            decided = Array(decided.prefix(DecidedStore.limit))
            saveDecided()
            // The adapter usually answers within a second or two: poll quickly for the ack instead of waiting for the
            // regular 5 s cycle.
            for _ in 0..<15 {
                try? await Task.sleep(for: .seconds(1))
                await refresh()
                if outcomes[req.id]?.isFinal == true { break }
            }
        } catch {
            outcomes[req.id] = .failed(error.localizedDescription)
        }
    }

    /// A failed write is not worth a banner: the list is still right for this run and is written again next time.
    private func saveDecided() {
        try? decidedStore.save(decided)
    }

    // MARK: the approve key

    /// Asks for the app PIN: shown by PINPromptModifier on whatever screen is on top.
    final class PINPrompt: Identifiable {
        let message: String?
        private var answer: CheckedContinuation<String?, Never>?

        init(message: String?, _ answer: CheckedContinuation<String?, Never>) {
            self.message = message
            self.answer = answer
        }

        /// The typed PIN, or nil for cancel. Only the first answer counts.
        func finish(_ pin: String?) {
            answer?.resume(returning: pin)
            answer = nil
        }
    }

    @Published var pinPrompt: PINPrompt?
    /// An approve-key signature is in progress: its Face ID prompt makes the scene inactive, and the privacy cover
    /// (PrivacyCover) must not hide what the person is approving behind it.
    @Published private(set) var signing = 0

    private func askPIN(_ message: String?) async -> String? {
        pinPrompt?.finish(nil)
        return await withCheckedContinuation { pinPrompt = PINPrompt(message: message, $0) }
    }

    /// Runs something that signs with the approve key, off the main thread (its Face ID prompt blocks). With no `pin`
    /// it tries Face ID; when Face ID cannot open the key, or a PIN was wrong, it asks for the app PIN and tries again
    /// until the PIN works, the person cancels or the PIN is locked out. iOS no longer asks for the PIN itself: the
    /// key's password is a random secret the PIN only unwraps (KeyStore.swift).
    func withApproveKey<T: Sendable>(pin: String? = nil, _ op: @escaping @Sendable (String?) throws -> T) async throws -> T {
        var pin = pin
        signing += 1
        defer { signing -= 1 }
        while true {
            let message: String?
            do {
                let p = pin
                let r = try await Task.detached { try op(p) }.value
                if pin != nil { refreshKeyState() }
                return r
            } catch let e as ApproveKeyError {
                refreshKeyState()
                switch e {
                case .keysDeleted:
                    await keysDeleted()
                    throw e
                case .lockedOut, .wrongPIN(_, .some):
                    throw e
                case .wrongPIN:
                    message = e.localizedDescription
                case .pinNeeded:
                    message = faceIDState == .changed
                        ? "Faces or fingerprints on this phone changed since Face ID was set up for approvals, so only the app PIN opens the approve key."
                        : nil
                }
            }
            guard let typed = await askPIN(message), !typed.isEmpty else { throw ApproveKeyError.pinNeeded }
            pin = typed
        }
    }

    /// Face ID for approvals and the PIN counter, as last read from the key store (for Settings).
    @Published private(set) var faceIDState: FaceIDState = .notApplicable
    @Published private(set) var pinFailures: (count: Int, lockedUntil: Date?) = (0, nil)

    func refreshKeyState() {
        faceIDState = keys.hasKeys() ? keys.faceIDState() : .notApplicable
        pinFailures = keys.pinFailures
    }

    /// Lets Face ID open the approve key again, with the app PIN. The person has confirmed that every face or finger
    /// enrolled on this phone is theirs.
    func enableFaceID(pin: String) async throws {
        let keys = self.keys
        defer { refreshKeyState() }
        do {
            try await Task.detached { try keys.enableFaceID(pin: pin) }.value
        } catch ApproveKeyError.keysDeleted {
            await keysDeleted()
            throw ApproveKeyError.keysDeleted
        }
    }

    /// Too many wrong PINs deleted the keys: tell the hub (best effort) and start over. The account still lists this
    /// device until another device removes it.
    private func keysDeleted() async {
        if let client { try? await client.leave(LeavePost()) }
        forgetLocally(deleteKeys: true)
        lastError = ApproveKeyError.keysDeleted.localizedDescription
    }

    // MARK: reset

    /// What resetting (deleting the keys) does to the account, from the last verified roster.
    enum ResetEffect { case none, removesThisDevice, deletesAccount }
    var resetEffect: ResetEffect {
        guard isEnrolled, membership == .member, let head, let me = try? device.deviceID(), head.devices[me] != nil else {
            return .none
        }
        return head.devices.count == 1 ? .deletesAccount : .removesThisDevice
    }

    /// Leaves the hub: the hub forgets this device (the roster stays, so it can come back with a join code), then the
    /// app forgets the hub: token, hub URL, pins, account and everything seen through it. The device keys stay.
    func leaveHub() async throws {
        try await tellHubLeaving(LeavePost())
        forgetLocally(deleteKeys: false)
    }

    /// Deletes the device keys, after taking this device off its account at the hub: a new roster without it (signed
    /// here, Face ID), or, for the account's last device, deleting the account, which nothing could sign for again.
    func reset(pin: String? = nil) async throws {
        switch resetEffect {
        case .none:
            try await tellHubLeaving(LeavePost())
        case .removesThisDevice:
            let me = try device.deviceID()
            let env = try await nextRoster(pin: pin) { dev, head, pin in try dev.remove(me, after: head, pin: pin) }
            try await tellHubLeaving(LeavePost(roster: env))
        case .deletesAccount:
            try await tellHubLeaving(LeavePost(deleteAccount: true))
        }
        forgetLocally(deleteKeys: true)
    }

    /// A hub that no longer knows this device (401) has nothing to forget.
    private func tellHubLeaving(_ l: LeavePost) async throws {
        guard isEnrolled, let client else { return }
        do {
            try await client.leave(l)
        } catch HubClient.HubError.http(401, _) {}
    }

    /// Forgets the hub on this phone only, without telling it (it is unreachable, or this is a UI test).
    func forgetLocally(deleteKeys: Bool) {
        if deleteKeys { try? keys.reset() }
        forgetHub()
        refreshKeyState()
        lastError = nil
    }

    private func forgetHub() {
        try? secrets.delete("hub.token")
        defaults.removeObject(forKey: "hubURL")
        try? pinStore.clear()
        hubURL = nil
        token = nil
        adapters = []
        offeredAdapters = []
        heldRequests = 0
        conflicts = []
        requests = []
        seen = [:]
        refused = []
        outcomes = [:]
        decided = []
        decidedStore.delete()
        sentHashes = [:]
        ackSince = 0
        user = nil
        account = nil
        unconfirmedAccount = nil
        accountNeedsConfirmation = false
        head = nil
        membership = .unknown
        joins = []
        rosterError = nil
        defaults.removeObject(forKey: "user")
        defaults.removeObject(forKey: "wasMember")
    }
}
