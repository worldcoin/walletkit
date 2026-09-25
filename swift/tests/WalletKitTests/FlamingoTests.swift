import XCTest
@testable import WalletKit

final class FlamingoTests: XCTestCase {
    func testMeasurementSkipIsExplicitAndStrictMeasurementsCanBeRestored() throws {
        let zeroMeasurements: [UInt32: Data] = [
            0: Data(repeating: 0, count: 48),
            1: Data(repeating: 0, count: 48),
            2: Data(repeating: 0, count: 48)
        ]
        let trustedMeasurements = zeroMeasurements.mapValues { _ in Data(repeating: 1, count: 48) }
        let matcher = try FlamingoMatcher(hostUrl: "https://verifier.example.com")
        XCTAssertThrowsError(try matcher.withMeasurements(measurements: zeroMeasurements))
        let skip = try matcher.dangerouslySkipMeasurements()
        XCTAssertThrowsError(try skip.withMeasurements(measurements: [:]))
        XCTAssertThrowsError(try skip.withMeasurements(measurements: zeroMeasurements))
        let strict = try skip.withMeasurements(measurements: trustedMeasurements)
        XCTAssertThrowsError(try strict.withMeasurements(measurements: zeroMeasurements))
    }
}
