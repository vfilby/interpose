import ApproverKit
import SwiftUI

struct InboxView: View {
    @EnvironmentObject var model: AppModel
    @State private var now = Date()

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
                Section("Decided here") {
                    ForEach(model.decided) { d in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(sanitize(d.title)).lineLimit(1)
                            HStack {
                                Text(d.approve ? "Approved" : "Denied")
                                Text("·")
                                // The live outcome first; after a relaunch only the stored final ack is left.
                                if let o = model.outcomes[d.id] ?? d.settled.map(Outcome.final) {
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
