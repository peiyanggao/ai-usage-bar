import AppKit
import Foundation
import Security

// MARK: - Config

enum Config {
    static let keychainService = "Claude Code-credentials"
    static let clientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    static let tokenURL = URL(string: "https://console.anthropic.com/v1/oauth/token")!
    static let usageURL = URL(string: "https://api.anthropic.com/api/oauth/usage")!
    static let oauthBeta = "oauth-2025-04-20"
    static let refreshSkew: TimeInterval = 120
    static let pollInterval: TimeInterval = 60
}

// MARK: - Keychain (shared with Claude Code)

enum Keychain {
    static func read() -> [String: Any]? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Config.keychainService,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let oauth = obj["claudeAiOauth"] as? [String: Any]
        else { return nil }
        return oauth
    }

    static func write(oauth: [String: Any]) {
        let wrapped = ["claudeAiOauth": oauth]
        guard let data = try? JSONSerialization.data(withJSONObject: wrapped) else { return }
        let match: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Config.keychainService,
        ]
        let status = SecItemUpdate(match as CFDictionary,
                                   [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = match
            add[kSecValueData as String] = data
            add[kSecAttrAccount as String] = NSUserName()
            SecItemAdd(add as CFDictionary, nil)
        }
    }
}

// MARK: - Token management

final class TokenManager {
    private(set) var accessToken: String?
    private var expiresAt: Date = .distantPast
    private var refreshCooldownUntil: Date = .distantPast

    enum TokenError: LocalizedError {
        case noCredentials, refreshFailed(String), rateLimited
        var errorDescription: String? {
            switch self {
            case .noCredentials: return "未登录 Claude Code"
            case .refreshFailed(let m): return "刷新令牌失败：\(m)"
            case .rateLimited: return "刷新被限流，稍后重试"
            }
        }
    }

    var isFresh: Bool {
        accessToken != nil && Date() < expiresAt.addingTimeInterval(-Config.refreshSkew)
    }

    func loadFromKeychain() {
        guard let oauth = Keychain.read() else { return }
        if let tok = oauth["accessToken"] as? String { accessToken = tok }
        if let exp = oauth["expiresAt"] as? Double {
            expiresAt = Date(timeIntervalSince1970: exp / 1000.0)
        }
    }

    func ensureValidToken() throws -> String {
        loadFromKeychain()
        if isFresh, let t = accessToken { return t }
        return try refresh()
    }

    @discardableResult
    func refresh() throws -> String {
        if Date() < refreshCooldownUntil { throw TokenError.rateLimited }
        guard let oauth = Keychain.read(),
              let refreshToken = oauth["refreshToken"] as? String
        else { throw TokenError.noCredentials }

        var req = URLRequest(url: Config.tokenURL)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": Config.clientID,
        ])

        let (data, resp) = try syncRequest(req)
        let http = resp as? HTTPURLResponse
        let code = http?.statusCode ?? 0
        if code == 429 {
            let retry = (http?.value(forHTTPHeaderField: "Retry-After")).flatMap(Double.init) ?? 300
            refreshCooldownUntil = Date().addingTimeInterval(max(60, retry))
            throw TokenError.rateLimited
        }
        guard code == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let newAccess = json["access_token"] as? String
        else {
            let msg = String(data: data, encoding: .utf8) ?? "unknown"
            throw TokenError.refreshFailed("HTTP \(code): \(msg.prefix(120))")
        }

        var updated = oauth
        updated["accessToken"] = newAccess
        if let newRefresh = json["refresh_token"] as? String { updated["refreshToken"] = newRefresh }
        if let expiresIn = json["expires_in"] as? Double {
            let exp = Date().addingTimeInterval(expiresIn)
            updated["expiresAt"] = exp.timeIntervalSince1970 * 1000.0
            expiresAt = exp
        }
        accessToken = newAccess
        Keychain.write(oauth: updated)
        return newAccess
    }
}

// MARK: - Usage model

struct UsageWindow {
    var title: String
    var usedPercent: Double
    var resetsAt: Date?
    var remainingPercent: Int { max(0, min(100, Int((100 - usedPercent).rounded()))) }
}

struct UsageSnapshot {
    var fiveHour: UsageWindow?
    var weekly: UsageWindow?
    var weeklyOpus: UsageWindow?
    var fetchedAt = Date()
}

// MARK: - Usage client

final class UsageClient {
    let tokens = TokenManager()

    enum FetchError: LocalizedError {
        case http(Int, String)
        var errorDescription: String? {
            switch self { case .http(let c, _): return "请求失败（HTTP \(c)）" }
        }
    }

    func readUsage(_ completion: @escaping (Result<UsageSnapshot, Error>) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            do { completion(.success(try self.fetch())) }
            catch { completion(.failure(error)) }
        }
    }

    private func fetch() throws -> UsageSnapshot {
        let token = try tokens.ensureValidToken()
        var data = try get(token: token)
        if data == nil {
            let fresh = try tokens.refresh()
            data = try get(token: fresh)
        }
        guard let payload = data else { throw FetchError.http(401, "unauthorized") }
        return Self.parse(payload)
    }

    private func get(token: String) throws -> Data? {
        var req = URLRequest(url: Config.usageURL)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue(Config.oauthBeta, forHTTPHeaderField: "anthropic-beta")
        let (data, resp) = try syncRequest(req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if code == 401 { return nil }
        guard code == 200 else {
            throw FetchError.http(code, String(data: data, encoding: .utf8) ?? "")
        }
        return data
    }

    static func parse(_ data: Data) -> UsageSnapshot {
        let dbg = (NSHomeDirectory() as NSString).appendingPathComponent(".claude-usage-debug.json")
        try? data.write(to: URL(fileURLWithPath: dbg))

        var snap = UsageSnapshot()
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return snap }

        var candidates: [(key: String, obj: [String: Any])] = []
        func collect(_ dict: [String: Any], depth: Int) {
            for (k, v) in dict {
                guard let obj = v as? [String: Any] else { continue }
                if hasUsage(obj) { candidates.append((k, obj)) }
                else if depth < 2 { collect(obj, depth: depth + 1) }
            }
        }
        collect(root, depth: 0)

        for (key, obj) in candidates {
            let used = usedValue(obj)
            let reset = resetValue(obj)
            let k = key.lowercased()
            if k.contains("opus") {
                snap.weeklyOpus = UsageWindow(title: "周 · Opus", usedPercent: used, resetsAt: reset)
            } else if k.contains("five") || k.contains("5") || k.contains("hour") || k.contains("session") {
                snap.fiveHour = UsageWindow(title: "5 小时", usedPercent: used, resetsAt: reset)
            } else if k.contains("seven") || k.contains("week") || k.contains("7") || k.contains("day") {
                if snap.weekly == nil {
                    snap.weekly = UsageWindow(title: "周限额", usedPercent: used, resetsAt: reset)
                } else {
                    snap.weeklyOpus = UsageWindow(title: "周 · Opus", usedPercent: used, resetsAt: reset)
                }
            }
        }
        return snap
    }

    private static func hasUsage(_ obj: [String: Any]) -> Bool {
        for key in ["utilization", "used_percent", "usedPercent", "percent_used", "percent", "used"] {
            if numeric(obj[key]) != nil { return true }
        }
        return false
    }

    private static func usedValue(_ obj: [String: Any]) -> Double {
        var used = 0.0
        for key in ["utilization", "used_percent", "usedPercent", "percent_used", "percent", "used"] {
            if let v = numeric(obj[key]) { used = v; break }
        }
        if used > 0, used <= 1.0 { used *= 100 }
        return used
    }

    private static func resetValue(_ obj: [String: Any]) -> Date? {
        for key in ["resets_at", "resetsAt", "reset_at", "reset", "resets"] {
            if let r = date(obj[key]) { return r }
        }
        return nil
    }

    private static func numeric(_ any: Any?) -> Double? {
        if let d = any as? Double { return d }
        if let i = any as? Int { return Double(i) }
        if let n = any as? NSNumber { return n.doubleValue }
        if let s = any as? String { return Double(s) }
        return nil
    }

    private static func date(_ any: Any?) -> Date? {
        if let n = numeric(any) {
            return Date(timeIntervalSince1970: n > 1_000_000_000_000 ? n / 1000 : n)
        }
        if let s = any as? String {
            let iso = ISO8601DateFormatter()
            iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = iso.date(from: s) { return d }
            iso.formatOptions = [.withInternetDateTime]
            return iso.date(from: s)
        }
        return nil
    }
}

// MARK: - Synchronous HTTP helper (background thread only)

func syncRequest(_ req: URLRequest) throws -> (Data, URLResponse) {
    let sem = DispatchSemaphore(value: 0)
    var out: (Data, URLResponse)?
    var err: Error?
    URLSession.shared.dataTask(with: req) { d, r, e in
        if let d = d, let r = r { out = (d, r) } else { err = e }
        sem.signal()
    }.resume()
    sem.wait()
    if let out = out { return out }
    throw err ?? URLError(.badServerResponse)
}

// MARK: - Usage view (Codex-style two-row segmented bars)

final class UsageView: NSView {
    var snapshot: UsageSnapshot? { didSet { needsDisplay = true } }
    var statusText = "正在读取额度…" { didSet { needsDisplay = true } }

    private let compact: Bool
    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "zh_CN")
        f.dateFormat = "M/d HH:mm"
        return f
    }()

    init(frame: NSRect, compact: Bool = false) {
        self.compact = compact
        super.init(frame: frame)
    }
    required init?(coder: NSCoder) { fatalError() }

    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        guard let snapshot else {
            drawText(statusText, rect: bounds.insetBy(dx: 12, dy: 8),
                     font: .systemFont(ofSize: compact ? 11 : 12),
                     color: .secondaryLabelColor, alignment: .center)
            return
        }

        let inset: CGFloat = compact ? 6 : 12
        let gap: CGFloat = compact ? 3 : 7
        let rows: [(String, UsageWindow?)] = [("5 小时", snapshot.fiveHour), ("周限额", snapshot.weekly)]
        let availableHeight = bounds.height - inset * 2 - gap * CGFloat(rows.count - 1)
        let rowHeight = availableHeight / CGFloat(rows.count)
        for (i, row) in rows.enumerated() {
            let y = inset + (rowHeight + gap) * CGFloat(i)
            drawRow(title: row.0, usage: row.1,
                    rect: NSRect(x: inset, y: y, width: bounds.width - inset * 2, height: rowHeight))
        }
    }

    private func drawRow(title: String, usage: UsageWindow?, rect: NSRect) {
        let titleWidth: CGFloat = compact ? 42 : 54
        let detailWidth: CGFloat = compact ? 128 : 176
        let spacing: CGFloat = compact ? 5 : 8
        let barRect = NSRect(
            x: rect.minX + titleWidth + spacing,
            y: rect.minY + (compact ? 5 : 8),
            width: rect.width - titleWidth - detailWidth - spacing * 2,
            height: compact ? 9 : 12
        )

        drawText(title,
                 rect: NSRect(x: rect.minX, y: rect.minY + (compact ? 1 : 4), width: titleWidth, height: 18),
                 font: .systemFont(ofSize: compact ? 10 : 12, weight: .semibold),
                 color: .labelColor, alignment: .left)

        let remaining = usage?.remainingPercent ?? 0
        drawSegments(in: barRect, remainingPercent: remaining, hasData: usage != nil)

        let detail: String
        if let usage {
            let reset = usage.resetsAt.map { "重置 \(dateFormatter.string(from: $0))" } ?? "重置时间未知"
            detail = "\(usage.remainingPercent)% 剩余  ·  \(reset)"
        } else {
            detail = "无数据"
        }
        drawText(detail,
                 rect: NSRect(x: barRect.maxX + spacing, y: rect.minY + (compact ? 1 : 4), width: detailWidth, height: 18),
                 font: .monospacedDigitSystemFont(ofSize: compact ? 9 : 11, weight: .regular),
                 color: .secondaryLabelColor, alignment: .right)
    }

    private func drawSegments(in rect: NSRect, remainingPercent: Int, hasData: Bool) {
        let segmentCount = compact ? 10 : 20
        let segmentGap: CGFloat = compact ? 2 : 2.5
        let segmentWidth = (rect.width - CGFloat(segmentCount - 1) * segmentGap) / CGFloat(segmentCount)
        let activeCount = hasData ? Int(ceil(Double(remainingPercent) / 100 * Double(segmentCount))) : 0
        let activeColor: NSColor
        switch remainingPercent {
        case 0..<20: activeColor = .systemRed
        case 20..<50: activeColor = .systemOrange
        default: activeColor = .systemGreen
        }
        for index in 0..<segmentCount {
            let segment = NSRect(
                x: rect.minX + CGFloat(index) * (segmentWidth + segmentGap),
                y: rect.minY, width: segmentWidth, height: rect.height)
            let path = NSBezierPath(roundedRect: segment, xRadius: 2, yRadius: 2)
            (index < activeCount ? activeColor : NSColor.quaternaryLabelColor).setFill()
            path.fill()
        }
    }

    private func drawText(_ text: String, rect: NSRect, font: NSFont, color: NSColor, alignment: NSTextAlignment) {
        let style = NSMutableParagraphStyle()
        style.alignment = alignment
        style.lineBreakMode = .byTruncatingTail
        text.draw(in: rect, withAttributes: [.font: font, .foregroundColor: color, .paragraphStyle: style])
    }
}

// MARK: - Codex app-server client (JSON-RPC over stdio)

final class CodexClient {
    static let executablePath = "/Applications/Codex.app/Contents/Resources/codex"

    private let queue = DispatchQueue(label: "ClaudeUsageBar.CodexClient")
    private var process: Process?
    private var stdin: FileHandle?
    private var stdoutBuffer = Data()
    private var nextID = 1
    private var initialized = false
    private var pending: [Int: (Result<Any, Error>) -> Void] = [:]

    enum CodexError: LocalizedError {
        case notInstalled, stopped, exited(Int32), invalid, rpc(String), parse
        var errorDescription: String? {
            switch self {
            case .notInstalled: return "未找到 /Applications/Codex.app"
            case .stopped: return "Codex app-server 未运行"
            case .exited(let s): return "Codex app-server 退出（\(s)）"
            case .invalid: return "Codex 返回无效响应"
            case .rpc(let m): return m
            case .parse: return "Codex 额度解析失败"
            }
        }
    }

    func readUsage(_ completion: @escaping (Result<UsageSnapshot, Error>) -> Void) {
        queue.async {
            do {
                try self.startIfNeeded()
                self.initializeIfNeeded { result in
                    switch result {
                    case .success:
                        self.sendRequest(method: "account/rateLimits/read", params: NSNull()) { resp in
                            completion(resp.flatMap { value in Result { try Self.parse(value) } })
                        }
                    case .failure(let e): completion(.failure(e))
                    }
                }
            } catch { completion(.failure(error)) }
        }
    }

    func stop() {
        queue.sync {
            process?.terminationHandler = nil
            process?.terminate()
            process = nil; stdin = nil; initialized = false
        }
    }

    private func startIfNeeded() throws {
        if let process, process.isRunning { return }
        guard FileManager.default.isExecutableFile(atPath: Self.executablePath) else { throw CodexError.notInstalled }
        let process = Process()
        let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: Self.executablePath)
        process.arguments = ["app-server", "--listen", "stdio://"]
        process.standardInput = inPipe
        process.standardOutput = outPipe
        process.standardError = errPipe
        outPipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            self?.queue.async { self?.consume(d) }
        }
        errPipe.fileHandleForReading.readabilityHandler = { h in _ = h.availableData }
        process.terminationHandler = { [weak self] p in
            self?.queue.async {
                guard self?.process === p else { return }
                self?.process = nil; self?.stdin = nil; self?.initialized = false
                self?.failPending(with: CodexError.exited(p.terminationStatus))
            }
        }
        try process.run()
        self.process = process
        stdin = inPipe.fileHandleForWriting
        stdoutBuffer.removeAll(keepingCapacity: true)
        initialized = false
    }

    private func initializeIfNeeded(_ completion: @escaping (Result<Void, Error>) -> Void) {
        if initialized { completion(.success(())); return }
        let params: [String: Any] = [
            "clientInfo": ["name": "touchbar-claude-usage", "title": "Claude Usage Bar", "version": "0.1.0"],
            "capabilities": [:],
        ]
        sendRequest(method: "initialize", params: params) { result in
            switch result {
            case .success:
                do { try self.send(["method": "initialized"]); self.initialized = true; completion(.success(())) }
                catch { completion(.failure(error)) }
            case .failure(let e): completion(.failure(e))
            }
        }
    }

    private func sendRequest(method: String, params: Any, completion: @escaping (Result<Any, Error>) -> Void) {
        let id = nextID; nextID += 1
        pending[id] = completion
        do { try send(["id": id, "method": method, "params": params]) }
        catch { pending.removeValue(forKey: id); completion(.failure(error)) }
    }

    private func send(_ object: [String: Any]) throws {
        guard let stdin else { throw CodexError.stopped }
        var data = try JSONSerialization.data(withJSONObject: object)
        data.append(0x0A)
        try stdin.write(contentsOf: data)
    }

    private func consume(_ data: Data) {
        stdoutBuffer.append(data)
        while let nl = stdoutBuffer.firstRange(of: Data([0x0A])) {
            let line = stdoutBuffer[..<nl.lowerBound]
            stdoutBuffer.removeSubrange(...nl.lowerBound)
            guard !line.isEmpty else { continue }
            handleLine(Data(line))
        }
    }

    private func handleLine(_ data: Data) {
        guard let msg = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = (msg["id"] as? NSNumber)?.intValue,
              let cb = pending.removeValue(forKey: id) else { return }
        if let err = msg["error"] as? [String: Any] {
            cb(.failure(CodexError.rpc(err["message"] as? String ?? "未知 JSON-RPC 错误")))
        } else if let result = msg["result"] {
            cb(.success(result))
        } else {
            cb(.failure(CodexError.invalid))
        }
    }

    private func failPending(with error: Error) {
        let cbs = Array(pending.values); pending.removeAll()
        cbs.forEach { $0(.failure(error)) }
    }

    private static func parse(_ result: Any) throws -> UsageSnapshot {
        guard let root = result as? [String: Any] else { throw CodexError.parse }
        let limits: [String: Any]?
        if let buckets = root["rateLimitsByLimitId"] as? [String: Any],
           let codex = buckets["codex"] as? [String: Any] { limits = codex }
        else { limits = root["rateLimits"] as? [String: Any] }
        guard let limits else { throw CodexError.parse }

        struct W { let used: Int; let reset: Date?; let dur: Int? }
        let windows = ["primary", "secondary"].compactMap { key -> W? in
            guard let v = limits[key] as? [String: Any], let used = int(v["usedPercent"]) else { return nil }
            return W(used: used,
                     reset: int(v["resetsAt"]).map { Date(timeIntervalSince1970: TimeInterval($0)) },
                     dur: int(v["windowDurationMins"]))
        }.sorted { ($0.dur ?? .max) < ($1.dur ?? .max) }
        guard windows.count >= 2 else { throw CodexError.parse }

        var snap = UsageSnapshot()
        snap.fiveHour = UsageWindow(title: "5 小时", usedPercent: Double(windows[0].used), resetsAt: windows[0].reset)
        snap.weekly = UsageWindow(title: "周限额", usedPercent: Double(windows[1].used), resetsAt: windows[1].reset)
        return snap
    }

    private static func int(_ v: Any?) -> Int? {
        if let i = v as? Int { return i }
        if let n = v as? NSNumber { return n.intValue }
        return nil
    }
}

// MARK: - Segment drawing helper (shared)

enum Seg {
    static func color(remaining: Int) -> NSColor {
        switch remaining {
        case 0..<20: return .systemRed
        case 20..<50: return .systemOrange
        default:      return .systemGreen
        }
    }
    static func draw(in rect: NSRect, remaining: Int, count: Int, gap: CGFloat, hasData: Bool) {
        let w = (rect.width - CGFloat(count - 1) * gap) / CGFloat(count)
        let active = hasData ? Int(ceil(Double(remaining) / 100 * Double(count))) : 0
        let col = color(remaining: remaining)
        for i in 0..<count {
            let seg = NSRect(x: rect.minX + CGFloat(i) * (w + gap), y: rect.minY, width: w, height: rect.height)
            let p = NSBezierPath(roundedRect: seg, xRadius: 2, yRadius: 2)
            (i < active ? col : NSColor.quaternaryLabelColor).setFill()
            p.fill()
        }
    }
}

func drawText(_ text: String, in rect: NSRect, font: NSFont, color: NSColor, alignment: NSTextAlignment) {
    let style = NSMutableParagraphStyle()
    style.alignment = alignment
    style.lineBreakMode = .byTruncatingTail
    text.draw(in: rect, withAttributes: [.font: font, .foregroundColor: color, .paragraphStyle: style])
}

// MARK: - Dual Touch Bar view (Claude Code | Codex)

final class DualTouchBarView: NSView {
    var claude: UsageSnapshot? { didSet { needsDisplay = true } }
    var codex: UsageSnapshot? { didSet { needsDisplay = true } }
    var claudeStatus = "读取中…" { didSet { needsDisplay = true } }
    var codexStatus = "读取中…" { didSet { needsDisplay = true } }

    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let dividerX = bounds.midX
        let inset: CGFloat = 8
        drawSide(title: "Claude Code", snap: claude, status: claudeStatus,
                 rect: NSRect(x: inset, y: 0, width: dividerX - inset - 6, height: bounds.height))

        NSColor.tertiaryLabelColor.setFill()
        NSRect(x: dividerX - 0.5, y: 6, width: 1, height: bounds.height - 12).fill()

        drawSide(title: "Codex", snap: codex, status: codexStatus,
                 rect: NSRect(x: dividerX + 6, y: 0, width: bounds.width - dividerX - 6 - inset, height: bounds.height))
    }

    private func drawSide(title: String, snap: UsageSnapshot?, status: String, rect: NSRect) {
        let headerW: CGFloat = 74
        drawText(title, in: NSRect(x: rect.minX, y: rect.midY - 8, width: headerW, height: 16),
                 font: .systemFont(ofSize: 11, weight: .bold), color: .labelColor, alignment: .left)

        let bodyX = rect.minX + headerW + 6
        let bodyW = rect.maxX - bodyX
        guard let snap, (snap.fiveHour != nil || snap.weekly != nil) else {
            drawText(status, in: NSRect(x: bodyX, y: rect.midY - 8, width: bodyW, height: 16),
                     font: .systemFont(ofSize: 10), color: .secondaryLabelColor, alignment: .left)
            return
        }
        let rows: [(String, UsageWindow?)] = [("5h", snap.fiveHour), ("周", snap.weekly)]
        let rowH: CGFloat = 11
        let gap: CGFloat = 4
        let totalH = rowH * 2 + gap
        let topY = rect.midY - totalH / 2
        for (i, row) in rows.enumerated() {
            drawMiniRow(tag: row.0, usage: row.1,
                        rect: NSRect(x: bodyX, y: topY + CGFloat(i) * (rowH + gap), width: bodyW, height: rowH))
        }
    }

    private func drawMiniRow(tag: String, usage: UsageWindow?, rect: NSRect) {
        let tagW: CGFloat = 20
        let pctW: CGFloat = 40
        let spacing: CGFloat = 5
        drawText(tag, in: NSRect(x: rect.minX, y: rect.minY - 1, width: tagW, height: rect.height + 2),
                 font: .systemFont(ofSize: 9, weight: .medium), color: .secondaryLabelColor, alignment: .left)
        let barRect = NSRect(x: rect.minX + tagW + spacing, y: rect.minY + 1,
                             width: rect.width - tagW - pctW - spacing * 2, height: rect.height - 2)
        Seg.draw(in: barRect, remaining: usage?.remainingPercent ?? 0, count: 8, gap: 2, hasData: usage != nil)
        let pct = usage.map { "\($0.remainingPercent)%" } ?? "--"
        drawText(pct, in: NSRect(x: barRect.maxX + spacing, y: rect.minY - 1, width: pctW, height: rect.height + 2),
                 font: .monospacedDigitSystemFont(ofSize: 9, weight: .regular), color: .secondaryLabelColor, alignment: .right)
    }
}

// MARK: - Demo data (for screenshots / preview)

enum DemoData {
    static func claude() -> UsageSnapshot {
        var snap = UsageSnapshot()
        let cal = Calendar.current
        snap.fiveHour = UsageWindow(title: "5 小时", usedPercent: 55,
                                    resetsAt: cal.date(byAdding: .minute, value: 132, to: Date()))
        snap.weekly = UsageWindow(title: "周限额", usedPercent: 12,
                                  resetsAt: cal.date(byAdding: .hour, value: 96, to: Date()))
        return snap
    }

    static func codex() -> UsageSnapshot {
        var snap = UsageSnapshot()
        let cal = Calendar.current
        snap.fiveHour = UsageWindow(title: "5 小时", usedPercent: 8,
                                    resetsAt: cal.date(byAdding: .minute, value: 218, to: Date()))
        snap.weekly = UsageWindow(title: "周限额", usedPercent: 86,
                                  resetsAt: cal.date(byAdding: .hour, value: 51, to: Date()))
        return snap
    }
}

// MARK: - Preview canvas / menu-bar preview (for screenshots)

final class CanvasView: NSView {
    var background: NSColor = .clear
    let content: NSView

    init(content: NSView, background: NSColor) {
        self.content = content
        self.background = background
        super.init(frame: content.frame)
        addSubview(content)
    }
    required init?(coder: NSCoder) { fatalError() }
    override var isFlipped: Bool { false }
    override func draw(_ dirtyRect: NSRect) {
        background.setFill()
        bounds.fill()
        super.draw(dirtyRect)
    }
}

/// Draws a faithful preview of the menu-bar item: "Claude NN%" + battery glyph.
final class MenuBarPreview: NSView {
    var remaining: Int = 73
    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let text = "Claude \(remaining)%"
        let font = NSFont.systemFont(ofSize: 13, weight: .regular)
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: NSColor.white]
        let size = (text as NSString).size(withAttributes: attrs)
        let glyphSize: CGFloat = 18
        let spacing: CGFloat = 5
        let totalW = size.width + spacing + glyphSize
        let startX = (bounds.width - totalW) / 2
        let midY = bounds.height / 2
        (text as NSString).draw(at: NSPoint(x: startX, y: midY - size.height / 2), withAttributes: attrs)

        let symbol = AppDelegate.batterySymbol(for: remaining)
        if let img = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) {
            let cfg = NSImage.SymbolConfiguration(pointSize: 13, weight: .regular)
            let tinted = (img.withSymbolConfiguration(cfg) ?? img)
            tinted.isTemplate = true
            let glyphRect = NSRect(x: startX + size.width + spacing,
                                   y: midY - glyphSize / 2, width: glyphSize, height: glyphSize)
            NSColor.white.set()
            tinted.draw(in: glyphRect, from: .zero, operation: .sourceOver, fraction: 1,
                        respectFlipped: true, hints: nil)
        }
    }
}

// MARK: - Offscreen screenshot rendering

enum Screenshot {
    static func renderAll(toDirectory dir: String) {
        let fm = FileManager.default
        try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)

        // Dropdown: the two-row segmented bars from the menu.
        let dropdown = UsageView(frame: NSRect(x: 0, y: 0, width: 460, height: 104))
        dropdown.snapshot = DemoData.claude()
        write(CanvasView(content: dropdown, background: .windowBackgroundColor),
              to: dir, name: "dropdown.png")

        // Touch Bar: Claude Code | Codex side by side on a black strip.
        let touch = DualTouchBarView(frame: NSRect(x: 0, y: 0, width: 660, height: 30))
        touch.claude = DemoData.claude()
        touch.codex = DemoData.codex()
        write(CanvasView(content: touch, background: .black), to: dir, name: "touchbar.png")

        // Menu bar: "Claude 73%" + battery glyph on a dark bar.
        let menubar = MenuBarPreview(frame: NSRect(x: 0, y: 0, width: 150, height: 28))
        menubar.remaining = 73
        write(CanvasView(content: menubar, background: NSColor(white: 0.13, alpha: 1)),
              to: dir, name: "menubar.png")

        FileHandle.standardError.write(Data("Rendered screenshots to \(dir)\n".utf8))
    }

    private static func write(_ view: NSView, to dir: String, name: String) {
        view.appearance = NSAppearance(named: .darkAqua)
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        rep.size = view.bounds.size
        view.cacheDisplay(in: view.bounds, to: rep)
        // Render at 2x for crisp output.
        guard let scaled = scale2x(rep, size: view.bounds.size),
              let png = scaled.representation(using: .png, properties: [:]) else { return }
        let path = (dir as NSString).appendingPathComponent(name)
        try? png.write(to: URL(fileURLWithPath: path))
    }

    private static func scale2x(_ rep: NSBitmapImageRep, size: NSSize) -> NSBitmapImageRep? {
        let w = Int(size.width * 2), h = Int(size.height * 2)
        guard let out = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else { return rep }
        out.size = size
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: out)
        NSGraphicsContext.current?.imageInterpolation = .high
        NSImage(cgImage: rep.cgImage!, size: size).draw(in: NSRect(origin: .zero, size: size))
        NSGraphicsContext.restoreGraphicsState()
        return out
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSTouchBarDelegate {
    private let client = UsageClient()
    private let codexClient = CodexClient()
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let menuUsageView = UsageView(frame: NSRect(x: 0, y: 0, width: 460, height: 104))
    private let touchUsageView = DualTouchBarView(frame: NSRect(x: 0, y: 0, width: 660, height: 30))
    private var touchBarPanel: TouchBarHostPanel?
    private var timer: Timer?
    private var isRefreshing = false
    private var snapshot: UsageSnapshot?
    private let demo: Bool

    init(demo: Bool = false) {
        self.demo = demo
        super.init()
    }

    func applicationDidFinishLaunching(_ note: Notification) {
        NSApp.setActivationPolicy(.accessory)
        configureStatusItem()
        configureMenu()
        configureTouchBar()
        if demo {
            applyDemo()
        } else {
            refresh()
            timer = Timer.scheduledTimer(withTimeInterval: Config.pollInterval, repeats: true) { [weak self] _ in
                self?.refresh()
            }
        }
    }

    private func applyDemo() {
        let claude = DemoData.claude()
        let codex = DemoData.codex()
        snapshot = claude
        menuUsageView.snapshot = claude
        touchUsageView.claude = claude
        touchUsageView.codex = codex
        updateStatusItem(with: claude)
    }

    func applicationWillTerminate(_ note: Notification) { timer?.invalidate(); codexClient.stop() }

    private func configureStatusItem() {
        guard let button = statusItem.button else { return }
        button.image = NSImage(systemSymbolName: "battery.75percent", accessibilityDescription: "Claude 剩余额度")
        button.imagePosition = .imageTrailing
        button.title = "Claude --% "
        button.toolTip = "Claude 剩余额度"
    }

    private func configureMenu() {
        menu.delegate = self
        let usageItem = NSMenuItem()
        usageItem.view = menuUsageView
        menu.addItem(usageItem)
        menu.addItem(.separator())

        let refreshItem = NSMenuItem(title: "立即刷新", action: #selector(refreshFromMenu), keyEquivalent: "r")
        refreshItem.target = self
        menu.addItem(refreshItem)

        let touchBarItem = NSMenuItem(title: "显示 Touch Bar", action: #selector(showTouchBar), keyEquivalent: "t")
        touchBarItem.target = self
        menu.addItem(touchBarItem)

        let quitItem = NSMenuItem(title: "退出 Claude Usage Bar", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
        statusItem.menu = menu
    }

    func menuWillOpen(_ menu: NSMenu) { NSApp.activate(ignoringOtherApps: true) }
    func menuDidClose(_ menu: NSMenu) { showTouchBar() }

    private func configureTouchBar() {
        let touchBar = NSTouchBar()
        touchBar.delegate = self
        touchBar.defaultItemIdentifiers = [.usage]
        touchBar.customizationIdentifier = NSTouchBar.CustomizationIdentifier("com.claudeusagebar.touchbar")

        let hostView = TouchBarHostView(frame: NSRect(x: 0, y: 0, width: 1, height: 1))
        hostView.touchBar = touchBar

        let panel = TouchBarHostPanel(contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
                                      styleMask: [.borderless], backing: .buffered, defer: false)
        panel.contentView = hostView
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.alphaValue = 0.01
        panel.hasShadow = false
        panel.ignoresMouseEvents = true
        panel.isReleasedWhenClosed = false
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
        panel.level = .floating
        positionTouchBarPanel(panel)
        touchBarPanel = panel
    }

    func touchBar(_ touchBar: NSTouchBar, makeItemForIdentifier identifier: NSTouchBarItem.Identifier) -> NSTouchBarItem? {
        guard identifier == .usage else { return nil }
        let item = NSCustomTouchBarItem(identifier: identifier)
        item.view = touchUsageView
        return item
    }

    @objc private func refreshFromMenu() { refresh() }

    @objc private func showTouchBar() {
        guard let panel = touchBarPanel, let hostView = panel.contentView else { return }
        positionTouchBarPanel(panel)
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        panel.makeFirstResponder(hostView)
    }

    @objc private func quit() { NSApp.terminate(nil) }

    private func positionTouchBarPanel(_ panel: NSPanel) {
        let frame = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1, height: 1)
        panel.setFrameOrigin(NSPoint(x: frame.maxX - 1, y: frame.maxY - 1))
    }

    private func refresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        let oldSnapshot = snapshot
        if oldSnapshot == nil {
            menuUsageView.statusText = "正在读取额度…"
            touchUsageView.claudeStatus = "读取中…"
        }

        let group = DispatchGroup()

        group.enter()
        client.readUsage { [weak self] result in
            DispatchQueue.main.async {
                defer { group.leave() }
                guard let self else { return }
                switch result {
                case .success(let newSnapshot):
                    self.snapshot = newSnapshot
                    self.menuUsageView.snapshot = newSnapshot
                    self.touchUsageView.claude = newSnapshot
                    self.updateStatusItem(with: newSnapshot)
                case .failure(let error):
                    self.touchUsageView.claudeStatus = "读取失败"
                    guard oldSnapshot == nil else {
                        self.statusItem.button?.toolTip = "刷新失败：\(error.localizedDescription)"
                        return
                    }
                    self.menuUsageView.statusText = "读取失败：\(error.localizedDescription)"
                    self.statusItem.button?.title = "Claude ! "
                    self.statusItem.button?.toolTip = error.localizedDescription
                }
            }
        }

        group.enter()
        codexClient.readUsage { [weak self] result in
            DispatchQueue.main.async {
                defer { group.leave() }
                guard let self else { return }
                switch result {
                case .success(let snap): self.touchUsageView.codex = snap
                case .failure(let error): self.touchUsageView.codexStatus = error.localizedDescription
                }
            }
        }

        group.notify(queue: .main) { [weak self] in self?.isRefreshing = false }
    }

    private func updateStatusItem(with snapshot: UsageSnapshot) {
        let five = snapshot.fiveHour?.remainingPercent
        let week = snapshot.weekly?.remainingPercent
        statusItem.button?.image = NSImage(systemSymbolName: Self.batterySymbol(for: five ?? 0),
                                           accessibilityDescription: "Claude 剩余额度")
        statusItem.button?.title = "Claude \(five.map { "\($0)%" } ?? "--") "
        statusItem.button?.toolTip = "Claude 剩余额度：5 小时 \(five.map { "\($0)%" } ?? "--")，周 \(week.map { "\($0)%" } ?? "--")"
    }

    static func batterySymbol(for remaining: Int) -> String {
        switch remaining {
        case ..<13: return "battery.0percent"
        case ..<38: return "battery.25percent"
        case ..<63: return "battery.50percent"
        case ..<88: return "battery.75percent"
        default:    return "battery.100percent"
        }
    }
}

private final class TouchBarHostPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

private final class TouchBarHostView: NSView {
    override var acceptsFirstResponder: Bool { true }
}

private extension NSTouchBarItem.Identifier {
    static let usage = NSTouchBarItem.Identifier("com.claudeusagebar.usage")
}

// MARK: - Entry

let env = ProcessInfo.processInfo.environment

if let renderDir = env["AI_USAGE_RENDER"], !renderDir.isEmpty {
    // Offscreen render mode: generate the README screenshots, then exit.
    _ = NSApplication.shared           // initialize AppKit for drawing
    Screenshot.renderAll(toDirectory: renderDir)
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate(demo: env["AI_USAGE_DEMO"] == "1")
app.delegate = delegate
app.run()
