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
                LabeledContent("Requester", value: sanitize(r.requester))
                if let who = r.onBehalfOf {
                    LabeledContent("On behalf of") {
                        VStack(alignment: .trailing) {
                            Text(sanitize(who.display ?? who.principal))
                            Text("attested by \(sanitize(who.attestedBy))").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                ForEach(r.facts ?? [], id: \.self) { f in
                    LabeledContent(sanitize(f.label)) {
                        Text(sanitize(f.value)).foregroundStyle(f.color).fontWeight(f.level?.isEmpty == false ? .semibold : .regular)
                    }
                }
                if let l = r.lease {
                    LabeledContent("Lease", value: "\(sanitize(l.scope)) for \(Duration.seconds(l.durationS).formatted(.units(allowed: [.hours, .minutes])))"
                                   + ((l.maxUses ?? 0) > 0 ? ", max \(l.maxUses!) uses" : ""))
                }
                LabeledContent("Expires") { Text(Date(timeIntervalSince1970: TimeInterval(r.expiresAt)), style: .relative) }
            } header: {
                Text("\(sanitize(r.adapter)) · \(sanitize(r.kind))")
            } footer: {
                if r.isHighRisk { Text("High risk: approving needs a long press, then Face ID.").foregroundStyle(.red) }
            }

            if let reason = r.reason, !reason.isEmpty {
                Section("Reason given by \(sanitize(r.requester)) (their claim)") {
                    Text("“\(sanitize(reason))”").italic()
                }
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

/// The second deliberate gesture for high-risk approvals: press and hold until the bar fills.
///
/// The fill animation is the timer: the action runs when it completes, so the bar is full before Face ID comes up.
/// Once it has fired the bar stays full while `busy` (the parent acting on the confirmation) and empties when that
/// clears, so a failed or cancelled Face ID leaves the button ready for another hold.
struct HoldToConfirmButton: View {
    let title: String
    var busy = false
    var duration: Double = 1.5
    let action: () -> Void
    @State private var pressing = false
    @State private var confirmed = false
    @State private var fill: CGFloat = 0
    @State private var hold = 0 // one per press, so a cut-short hold's animation completion is ignored

    var body: some View {
        Button {} label: {
            Text(title)
                .font(.headline)
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background {
                    GeometryReader { g in
                        ZStack(alignment: .leading) {
                            Color.red.opacity(0.45)
                            Color.red.frame(width: fill * g.size.width)
                        }
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .contentShape(Rectangle())
        }
        .buttonStyle(PressTracking(onPress: pressChanged))
        .accessibilityHint("Press and hold to approve")
        .onChange(of: busy) { _, busy in
            if !busy { reset() }
        }
    }

    private func pressChanged(_ down: Bool) {
        pressing = down
        guard !confirmed else { return }
        if down {
            hold += 1
            let h = hold
            withAnimation(.linear(duration: duration), completionCriteria: .logicallyComplete) {
                fill = 1
            } completion: {
                // Also called when a release cuts the hold short: the emptying animation replaces this one.
                guard h == hold, pressing, !confirmed else { return }
                confirmed = true
                action()
            }
        } else {
            withAnimation(.easeOut(duration: 0.2)) { fill = 0 }
        }
    }

    private func reset() {
        confirmed = false
        withAnimation(.easeOut(duration: 0.2)) { fill = 0 }
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
