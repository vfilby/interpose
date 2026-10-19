import ApproverKit
import SwiftUI

struct InboxView: View {
    @EnvironmentObject var model: AppModel
    @State private var now = Date()
    /// The decision whose details are open; one at a time keeps the list readable.
    @State private var expanded: String?

    var body: some View {
        List {
            Section {
                InsecureBanner().listRowInsets(EdgeInsets())
            }
            .listRowBackground(Color.clear)

            MembershipBanner()

            OfferedAdaptersSection()

            if !model.joins.isEmpty {
                Section {
                    ForEach(model.joins) { j in
                        NavigationLink(value: JoinRoute(deviceID: j.deviceId)) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(joinName(j)).font(.headline)
                                Text(joinFingerprint(j)).font(.footnote.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Text("Devices asking to join \(model.user ?? "")")
                }
            }

            Section("Pending") {
                let live = model.requests.filter { !$0.record.isExpired(at: now) }
                if live.isEmpty {
                    Text("Nothing waiting").foregroundStyle(.secondary)
                }
                ForEach(live) { req in
                    NavigationLink(value: req.id) { RequestRow(req: req, now: now) }
                }
            }

            let expired = model.requests.filter { $0.record.isExpired(at: now) }
            if !expired.isEmpty {
                Section("Expired") {
                    ForEach(expired) { req in RequestRow(req: req, now: now).opacity(0.4) }
                }
            }

            if !model.decided.isEmpty {
                Section {
                    ForEach(model.decided) { d in
                        DecidedRow(decided: d, expanded: binding(expanding: d.id))
                    }
                } header: {
                    Text("Decided here")
                } footer: {
                    Text("Tap a decision to see what was asked.")
                }
            }

            if !model.refused.isEmpty {
                Section {
                    ForEach(model.refused, id: \.self) { Text(sanitize($0)).font(.footnote).foregroundStyle(.red) }
                } header: {
                    Text("Refused (not shown)")
                } footer: {
                    Text("These did not open or verify against a pinned adapter key. They cannot be approved.")
                }
            }

            if let e = model.lastError {
                Section { Text(sanitize(e)).font(.footnote).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Requests")
        .navigationDestination(for: String.self) { id in
            if let req = model.requests.first(where: { $0.id == id }) ?? model.seen[id] {
                RequestDetailView(req: req)
            } else {
                Text("No longer pending").foregroundStyle(.secondary)
            }
        }
        .navigationDestination(for: JoinRoute.self) { route in
            if let j = model.joins.first(where: { $0.deviceId == route.deviceID }) {
                JoinDetailView(join: j)
            } else {
                Text("No longer asking to join").foregroundStyle(.secondary)
            }
        }
        .refreshable { await model.refresh() }
        .task {
            // Only the clock for expiry display; RootView does the polling (this task stops when a detail is pushed).
            while !Task.isCancelled {
                now = Date()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }
}

extension InboxView {
    private func binding(expanding id: String) -> Binding<Bool> {
        Binding(get: { expanded == id }, set: { open in
            if open { expanded = id } else if expanded == id { expanded = nil }
        })
    }
}

/// One past decision. Closed: the summary line as before. Opened (a tap on the row): what was on the request screen
/// when it was decided (the record kept with the decision), when it was decided, and the request id.
struct DecidedRow: View {
    @EnvironmentObject var model: AppModel
    let decided: Decided
    @Binding var expanded: Bool

    var body: some View {
        DisclosureGroup(isExpanded: $expanded.animation()) {
            if let r = decided.record {
                LabeledContent("Adapter", value: "\(sanitize(r.adapter)) · \(sanitize(r.kind))")
                RecordRows(record: r)
                if r.hasReason {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ReasonRow.title(r)).font(.footnote).foregroundStyle(.secondary)
                        ReasonRow(record: r)
                    }
                }
            } else {
                Text("The details of this decision were not kept.").foregroundStyle(.secondary)
            }
            LabeledContent(decided.approve ? "Approved" : "Denied") {
                Text(decided.at, format: .dateTime.day().month().hour().minute())
            }
            LabeledContent("Request", value: sanitize(decided.id)).font(.footnote)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    if decided.record?.isHighRisk == true { Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red) }
                    Text(sanitize(decided.title)).lineLimit(expanded ? nil : 1)
                }
                HStack {
                    Text(decided.approve ? "Approved" : "Denied")
                    Text("·")
                    // The live outcome first; after a relaunch only the stored final ack is left.
                    if let o = model.outcomes[decided.id] ?? decided.settled.map(Outcome.final) {
                        OutcomeText(outcome: o)
                    } else {
                        Text("not confirmed before the app closed")
                    }
                }
                .font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

struct RequestRow: View {
    let req: OpenedRequest
    let now: Date

    var body: some View {
        let r = req.record
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                if r.isHighRisk { Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red) }
                Text(sanitize(r.title)).font(.headline).lineLimit(2)
            }
            HStack(spacing: 6) {
                Text(sanitize(r.adapter))
                Text("·")
                Text(sanitize(r.requester))
                Spacer()
                Text(Date(timeIntervalSince1970: TimeInterval(r.expiresAt)), style: .relative)
            }
            .font(.footnote).foregroundStyle(.secondary)
        }
    }
}

struct OutcomeText: View {
    let outcome: Outcome?

    var body: some View {
        switch outcome {
        case .none: Text("waiting")
        case .sent: Text("sent, waiting for the adapter")
        case .final(let a): Text("\(sanitize(a.outcome)) (confirmed by \(sanitize(a.adapter)))")
            .foregroundStyle(a.outcome == "expired" ? Color.secondary : Color.green)
        case .note(let a):
            Text("\(a.outcome == "rejected" ? "Rejected by adapter" : "Service call failed"): \(sanitize(a.detail ?? "")). Still pending.")
                .foregroundStyle(.orange)
        case .unconfirmed(let why): Text("unconfirmed: \(sanitize(why))").foregroundStyle(.orange)
        case .failed(let why): Text("not delivered: \(sanitize(why))").foregroundStyle(.red)
        }
    }
}
