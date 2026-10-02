import Foundation
import XCTest
@testable import WalletKit

private final class IntegrityTestSigner: RequestDigestSigner, @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private let fails: Bool

    init(fails: Bool = false) {
        self.fails = fails
    }

    func signDigest(clientDataHash: Data) throws -> Data {
        XCTAssertEqual(clientDataHash, Data(repeating: 0xA5, count: 32))
        lock.lock()
        calls += 1
        lock.unlock()
        if fails {
            throw RequestIntegrityError.SigningFailed
        }
        return Data([1, 2, 3])
    }

    func callCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return calls
    }
}

private final class IntegrityTestProvider: RequestIntegrityProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private let fails: Bool
    let signer: IntegrityTestSigner

    init(signer: IntegrityTestSigner, fails: Bool = false) {
        self.signer = signer
        self.fails = fails
    }

    private func recordCall() {
        lock.lock()
        calls += 1
        lock.unlock()
    }

    func callCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return calls
    }

    func prepare() async throws -> RequestIntegritySession {
        await Task.yield()
        recordCall()
        if fails {
            throw RequestIntegrityError.Unavailable
        }
        return RequestIntegritySession(
            token: "test-key-token",
            platform: .ios,
            signer: signer
        )
    }
}

final class RequestIntegrityTest: XCTestCase {
    private func request() -> FlamingoMatchRequest {
        .grayBadge(
            live: .vanilla(image: Data([1])),
            rtmsChallenge: Data([2]),
            matchThreshold: 0.5
        )
    }

    private func matcher(_ provider: IntegrityTestProvider) throws -> FlamingoMatcher {
        try FlamingoMatcher(
            hostUrl: "https://verifier.invalid",
            integrityProvider: provider
        ).dangerouslySkipMeasurements()
    }

    func testPreparesEachAttemptAndSignsMockDigestBeforeFailingClosed() async throws {
        let signer = IntegrityTestSigner()
        let provider = IntegrityTestProvider(signer: signer)
        let configured = try matcher(provider)

        for _ in 0..<2 {
            do {
                _ = try await configured.performMatch(request: request())
                XCTFail("mock signing must stop before transport")
            } catch FlamingoError.CanonicalSigningUnavailable {}
        }

        XCTAssertEqual(provider.callCount(), 2)
        XCTAssertEqual(signer.callCount(), 2)
    }

    func testPreservesTypedProviderFailureWithoutSigning() async throws {
        let signer = IntegrityTestSigner()
        let provider = IntegrityTestProvider(signer: signer, fails: true)

        do {
            _ = try await matcher(provider).performMatch(request: request())
            XCTFail("provider failure must propagate")
        } catch FlamingoError.RequestIntegrity(let failure) {
            XCTAssertEqual(failure, .Unavailable)
        }

        XCTAssertEqual(signer.callCount(), 0)
    }

    func testPreservesTypedSignerFailure() async throws {
        let provider = IntegrityTestProvider(signer: IntegrityTestSigner(fails: true))

        do {
            _ = try await matcher(provider).performMatch(request: request())
            XCTFail("signer failure must propagate")
        } catch FlamingoError.RequestIntegrity(let failure) {
            XCTAssertEqual(failure, .SigningFailed)
        }

        XCTAssertEqual(provider.signer.callCount(), 1)
    }
}
