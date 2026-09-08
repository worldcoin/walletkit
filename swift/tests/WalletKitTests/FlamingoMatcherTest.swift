import Foundation
import XCTest
@testable import WalletKit

final class FlamingoMatcherTest: XCTestCase {
    func testFluentConfiguration() throws {
        let matcher = try FlamingoMatcher(hostUrl: "https://verifier.example.com")
            .withMeasurements(measurements: [
                0: Data(repeating: 1, count: 48),
                1: Data(repeating: 2, count: 48),
                2: Data(repeating: 3, count: 48)
            ])
            .withHeaders(headers: ["Authorization": "Bearer test-token"])

        XCTAssertNoThrow(try matcher.withHeaders(headers: [:]))
        XCTAssertThrowsError(try matcher.withHeaders(headers: ["x-test": "invalid\nvalue"]))
        XCTAssertThrowsError(try matcher.withMeasurements(measurements: [:]))
        XCTAssertThrowsError(try matcher.withMeasurements(measurements: [
            0: Data(repeating: 0, count: 48),
            1: Data(repeating: 2, count: 48),
            2: Data(repeating: 3, count: 48)
        ]))
    }
}
