import Foundation
import XCTest
@testable import WalletKit

final class FlamingoMatcherTest: XCTestCase {
    func testFluentConfiguration() throws {
        let matcher = try FlamingoMatcher(hostUrl: "https://verifier.example.com")
            .withMeasurements(measurements: FlamingoMeasurements(
                pcr0: Data(repeating: 1, count: 48),
                pcr1: Data(repeating: 2, count: 48),
                pcr2: Data(repeating: 3, count: 48)
            ))
            .withHeaders(headers: ["Authorization": "Bearer test-token"])

        XCTAssertNoThrow(try matcher.withHeaders(headers: [:]))
        XCTAssertThrowsError(try matcher.withHeaders(headers: ["x-test": "invalid\nvalue"]))
        XCTAssertThrowsError(try matcher.withMeasurements(measurements: FlamingoMeasurements(
            pcr0: Data(repeating: 0, count: 48),
            pcr1: Data(repeating: 2, count: 48),
            pcr2: Data(repeating: 3, count: 48)
        )))
    }
}
