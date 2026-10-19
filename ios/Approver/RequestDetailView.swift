import ApproverKit
import SwiftUI

/// Authoritative first: title, requester, on-behalf-of, facts (all written by the adapter from the service's own
/// state). The requester's reason comes after, quoted and labelled as their claim.
struct RequestDetailView: View {
    @EnvironmentObject var model: AppModel
    let req: OpenedRequest
    @State private var working = false
    @State private var pin = ""
    @State private var usePIN = false

    private var r: Record { req.record }

    var body: some View {
        List {
            Section {
                Text(sanitize(r.title)).font(.title3.weight(.semibold))
                RecordRows(record: r)
                LabeledContent("Expires") { Text(Date(timeIntervalSince1970: TimeInterval(r.expiresAt)), style: .relative) }
            } header: {
                Text("\(sanitize(r.adapter)) · \(sanitize(r.kind))")
            } footer: {
                if r.isHighRisk { Text("High risk: approving needs a long press, then Face ID.").foregroundStyle(.red) }
            }

            if r.hasReason {
                Section(ReasonRow.title(r)) { ReasonRow(record: r) }
            }

            Section {
                let outcome = model.outcomes[req.id]
                if let outcome {
                    // A note (rejected / failed) or an unconfirmed ack leaves the request actionable: a new tap signs a
                    // fresh decision on the same record.
                    OutcomeText(outcome: outcome)
                }
                if r.isExpired() {
                    Text("Expired").foregroundStyle(.secondary)
                } else if !model.canApprove {
                    Text(model.membership == .removed
                         ? "This device was removed from its account: it can no longer decide."
                         : "This device is not on the account's verified device list yet: it cannot decide.")
                        .foregroundStyle(.secondary)
                } else if outcome?.allowsDecision ?? true {
                    if !model.isInsecure {
                        Toggle("Use app PIN instead of Face ID", isOn: $usePIN)
                        if usePIN {
                            SecureField("App PIN", text: $pin)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                    }
                    if r.isHighRisk {
                        HoldToConfirmButton(title: "Hold to approve", busy: working) { decide(true) }
                    } else {
                        Button { decide(true) } label: {
                            // Title centred like Deny below it; the Face ID glyph sits at the leading edge rather
                            // than pushing the title off centre.
                            Text("Approve")
                                .frame(maxWidth: .infinity)
                                .overlay(alignment: .leading) { Image(systemName: "faceid") }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    Button(role: .destructive) { decide(false) } label: {
                        Text("Deny").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
            }
            .disabled(working)
        }
        .navigationTitle("Request")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func decide(_ approve: Bool) {
        working = true
        Task {
            await model.decide(req, approve: approve, pin: usePIN ? pin : nil)
            working = false
        }
    }
}

/// The authoritative rows of a record, as list rows: requester, on-behalf-of, facts, lease. Shared by the request
/// screen and the opened "Decided here" entry, so a past decision shows exactly what was decided.
struct RecordRows: View {
    let record: Record

    var body: some View {
        LabeledContent("Requester", value: sanitize(record.requester))
        if let who = record.onBehalfOf {
            LabeledContent("On behalf of") {
                VStack(alignment: .trailing) {
                    Text(sanitize(who.display ?? who.principal))
                    Text("attested by \(sanitize(who.attestedBy))").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        ForEach(record.facts ?? [], id: \.self) { f in
            LabeledContent(sanitize(f.label)) {
                Text(sanitize(f.value)).foregroundStyle(f.color).fontWeight(f.level?.isEmpty == false ? .semibold : .regular)
            }
        }
        if let l = record.lease {
            LabeledContent("Lease", value: "\(sanitize(l.scope)) for \(Duration.seconds(l.durationS).formatted(.units(allowed: [.hours, .minutes])))"
                           + ((l.maxUses ?? 0) > 0 ? ", max \(l.maxUses!) uses" : ""))
        }
    }
}

/// The requester's reason, quoted: it is their claim, not something the adapter checked.
struct ReasonRow: View {
    let record: Record

    static func title(_ r: Record) -> String { "Reason given by \(sanitize(r.requester)) (their claim)" }

    var body: some View {
        Text("“\(sanitize(record.reason ?? ""))”").italic()
    }
}

extension Record {
    var hasReason: Bool { !(reason ?? "").isEmpty }
}

/// The second deliberate gesture for high-risk approvals: press and hold until the bar fills.
///
/// The fill is drawn from the wall clock (how long the finger has been down over `duration`), and the action fires from
/// a timer started at the same instant, so what the bar shows and when it fires cannot drift apart. Nothing here
/// depends on a SwiftUI animation running: the earlier version animated the fill with `withAnimation` from the button's
/// press tracking, and on the phone that animation did not run, so the bar went red at once instead of filling. A
/// release before `duration` empties the bar and cancels the timer. Once it has fired the bar stays full while `busy` (the parent acting on the
/// confirmation) and empties when that clears, so a failed or cancelled Face ID leaves the button ready for another
/// hold.
struct HoldToConfirmButton: View {
    let title: String
    var busy = false
    var duration: Double = 1.5
    let action: () -> Void
    @State private var pressStart: Date? // set while the finger is down
    @State private var confirmed = false
    @State private var timer: Task<Void, Never>?

    var body: some View {
        Button {} label: {
            Text(title)
                .font(.headline)
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background {
                    TimelineView(.animation(paused: pressStart == nil)) { context in
                        GeometryReader { g in
                            ZStack(alignment: .leading) {
                                Color.red.opacity(0.45)
                                Color.red.frame(width: fill(at: context.date) * g.size.width)
                            }
                        }
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .contentShape(Rectangle())
        }
        .buttonStyle(PressTracking(onPress: pressChanged))
        .accessibilityHint("Press and hold to approve")
        .onChange(of: busy) { _, busy in
            if !busy { confirmed = false }
        }
    }

    private func fill(at now: Date) -> CGFloat {
        if confirmed { return 1 }
        guard let start = pressStart else { return 0 }
        return CGFloat(min(1, max(0, now.timeIntervalSince(start) / duration)))
    }

    private func pressChanged(_ down: Bool) {
        timer?.cancel()
        timer = nil
        guard !confirmed else { return }
        if down {
            pressStart = .now
            timer = Task { @MainActor in
                try? await Task.sleep(for: .seconds(duration))
                guard !Task.isCancelled, pressStart != nil, !confirmed else { return }
                confirmed = true
                pressStart = nil
                action()
            }
        } else {
            pressStart = nil
        }
    }
}

/// Reports presses and leaves the label alone: the hold button draws its own state.
private struct PressTracking: ButtonStyle {
    let onPress: (Bool) -> Void

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .onChange(of: configuration.isPressed) { _, down in onPress(down) }
    }
}
