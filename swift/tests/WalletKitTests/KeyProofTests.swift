import XCTest
@testable import WalletKit

final class KeyProofTests: XCTestCase {
    func testSignsWithoutRegistrationAndRestoresTheSameKey() throws {
        let expiresAt = 2_000_000_300
        let challenge = Data("""
        {"version":1,"issuer":"https://auth.world.org","ceremony_id":"019af784-3d00-7000-8000-000000000001","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":\(expiresAt)}
        """.utf8)
        let proof = try createWorldIdKeyProof(
            seed: Data(repeating: 0x11, count: 32),
            challenge: challenge,
            expectedIssuer: "https://auth.world.org"
        )
        XCTAssertEqual(proof.publicKey, "A66IqHPC21NxH6PvdYOc4CiP0dUZ0YJU-c1P3Wnqc8Vg")
        XCTAssertEqual(proof.signature, "MEQCIHLt1lsDPExtD-b-ZUOwQoLDlPSNZRJt80TQYNBUqA-nAiA2wgeTY2esbHXsNxceE4XAmyu8CgyUzrPtiHrrHmh2gQ")
        XCTAssertEqual(proof, try createWorldIdKeyProof(
            seed: Data(repeating: 0x11, count: 32),
            challenge: challenge,
            expectedIssuer: "https://auth.world.org"
        ))
        XCTAssertThrowsError(try createWorldIdKeyProof(
            seed: Data(repeating: 0x11, count: 32),
            challenge: challenge,
            expectedIssuer: "https://other.example"
        ))
    }
}
