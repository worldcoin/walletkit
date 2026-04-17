import XCTest
@testable import WalletKit

private final class CapturingLogger: WalletKit.Logger {
    private let lock = NSLock()
    private var entries: [(WalletKit.LogLevel, String)] = []

    func log(level: WalletKit.LogLevel, message: String) {
        lock.lock()
        entries.append((level, message))
        lock.unlock()
    }

    func snapshot() -> [(WalletKit.LogLevel, String)] {
        lock.lock()
        defer { lock.unlock() }
        return entries
    }
}

final class SimpleTest: XCTestCase {
    func testInitLoggingForwardsLevelAndMessage() {
        let logger = CapturingLogger()
        WalletKit.initLogging(logger: logger, level: .info)
        WalletKit.emitLog(level: .info, message: "bridge test")

        // Log delivery happens on a dedicated background thread via an mpsc
        // channel. Poll with a generous timeout so CI runners under load
        // don't flake.
        let deadline = Date().addingTimeInterval(5.0)
        var entries: [(WalletKit.LogLevel, String)] = []
        while Date() < deadline {
            entries = logger.snapshot()
            if entries.contains(where: { $0.0 == .info && $0.1.contains("bridge test") }) {
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }


        XCTAssertFalse(entries.isEmpty, "expected at least one bridged log entry")

        let hasBridgedMessage = entries.contains { level, message in
            level == .info && message.contains("bridge test")
        }
        XCTAssertTrue(hasBridgedMessage, "expected info-level bridged log")
    }
}
