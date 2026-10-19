import ApproverKit
import Foundation

/// A decision this device sent, kept for the "Decided here" list: what was asked, which way it went, and the verified
/// final ack once one arrived.
struct Decided: Identifiable, Equatable, Codable {
    /// adapter/requestId, the same key as AppModel.outcomes.
    var id: String
    var title: String
    var approve: Bool
    var at: Date
    /// The verified final ack (approved, denied or expired), so the outcome still shows after the app was relaunched
    /// and the live outcomes are gone.
    var settled: Ack?
    /// The verified record as it was decided (facts, requester, reason, lease), so the list can show what was approved
    /// or denied, not only the title. Absent for entries written before the app kept it.
    var record: Record?
}

/// The decided list on disk: one JSON file in Application Support, readable only while the phone is unlocked, not
/// backed up. It holds request titles, so it is cleared with the hub (forgetHub).
struct DecidedStore {
    /// Newest first; older entries are dropped beyond this.
    static let limit = 50

    let url: URL

    init(name: String = "decided.json") {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        url = dir.appendingPathComponent(name)
    }

    /// Whatever is on disk; an unreadable or missing file is an empty list, never an error the person has to act on.
    func load() -> [Decided] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([Decided].self, from: data)) ?? []
    }

    func save(_ entries: [Decided]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(Array(entries.prefix(Self.limit)))
            .write(to: url, options: [.atomic, .completeFileProtection])
        var u = url
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        try u.setResourceValues(v)
    }

    func delete() { try? FileManager.default.removeItem(at: url) }
}
