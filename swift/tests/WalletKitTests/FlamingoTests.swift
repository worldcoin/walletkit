import XCTest
@testable import WalletKit

final class FlamingoTests: XCTestCase {
    func testDebugMeasurementsRequireExplicitOptIn() throws {
        let measurements: [UInt32: Data] = [
            0: Data(repeating: 0, count: 48),
            1: Data(repeating: 0, count: 48),
            2: Data(repeating: 0, count: 48)
        ]
        let matcher = try FlamingoMatcher(hostUrl: "https://verifier.example.com")
        XCTAssertThrowsError(try matcher.withMeasurements(measurements: measurements))
        let debug = try matcher.withDebugMeasurements(measurements: measurements)
        XCTAssertThrowsError(try debug.withMeasurements(measurements: measurements))

        var missing = measurements
        missing.removeValue(forKey: 2)
        XCTAssertThrowsError(try matcher.withDebugMeasurements(measurements: missing))
        var malformed = measurements
        malformed[0] = Data(repeating: 0, count: 47)
        XCTAssertThrowsError(try matcher.withDebugMeasurements(measurements: malformed))
    }
}
