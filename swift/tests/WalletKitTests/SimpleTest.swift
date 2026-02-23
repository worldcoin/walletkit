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
        WalletKit.initLogging(logger: logger)

        let entries = logger.snapshot()
        XCTAssertFalse(entries.isEmpty, "expected at least one bridged log entry")

        let hasInitInfo = entries.contains { level, message in
            level == .info && message.contains("WalletKit logging initialized")
        }
        XCTAssertTrue(hasInitInfo, "expected info-level initialization log")
    }
}
