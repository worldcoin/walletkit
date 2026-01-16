import XCTest
@testable import WalletKit

final class AuthenticatorTests: XCTestCase {

    let testRpcUrl = "https://worldchain-sepolia.g.alchemy.com/public"

    // MARK: - Helper Functions

    func generateRandomSeed() -> [UInt8] {
        return (0..<32).map { _ in UInt8.random(in: 0...255) }
    }

    // MARK: - U256Wrapper Tests

    func testU256WrapperFromU64() {
        let value: UInt64 = 12345
        let u256 = U256Wrapper.fromU64(value: value)
        XCTAssertEqual(u256.toDecimalString(), "12345")
    }

    func testU256WrapperFromDecimalString() throws {
        let decimalString = "999999999999999999"
        let u256 = try U256Wrapper.fromDecimalString(value: decimalString)
        XCTAssertEqual(u256.toDecimalString(), decimalString)
    }

    func testU256WrapperFromHexString() throws {
        let hexString = "0x1a2b3c4d5e6f"
        let u256 = try U256Wrapper.fromHexString(value: hexString)
        XCTAssertNotNil(u256)
    }

    func testU256WrapperInvalidDecimalString() {
        XCTAssertThrowsError(try U256Wrapper.fromDecimalString(value: "not_a_number")) { error in
            XCTAssertTrue(error is WalletKitError)
        }
    }

    func testU256WrapperInvalidHexString() {
        XCTAssertThrowsError(try U256Wrapper.fromHexString(value: "0xZZZ")) { error in
            XCTAssertTrue(error is WalletKitError)
        }
    }

    // MARK: - Authenticator Initialization Tests

    func testAuthenticatorInitWithDefaultsAccountDoesNotExist() async {
        let seed = generateRandomSeed()

        do {
            _ = try await Authenticator.initWithDefaults(
                seed: seed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
            XCTFail("Should have thrown AccountDoesNotExist error")
        } catch let error as WalletKitError {
            // Expected - account doesn't exist for random seed
            switch error {
            case .AccountDoesNotExist:
                break // Expected
            default:
                XCTFail("Expected AccountDoesNotExist, got \(error)")
            }
        } catch {
            XCTFail("Expected WalletKitError, got \(error)")
        }
    }

    func testInvalidSeedEmpty() async {
        let emptySeed: [UInt8] = []

        do {
            _ = try await Authenticator.initWithDefaults(
                seed: emptySeed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
            XCTFail("Should have thrown InvalidSeed error")
        } catch let error as WalletKitError {
            switch error {
            case .InvalidSeed:
                break // Expected
            default:
                XCTFail("Expected InvalidSeed, got \(error)")
            }
        } catch {
            XCTFail("Expected WalletKitError, got \(error)")
        }
    }

    func testInvalidSeedTooShort() async {
        let shortSeed = [UInt8](repeating: 0, count: 16) // Too short

        do {
            _ = try await Authenticator.initWithDefaults(
                seed: shortSeed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
            XCTFail("Should have thrown InvalidSeed error")
        } catch let error as WalletKitError {
            switch error {
            case .InvalidSeed:
                break // Expected
            default:
                XCTFail("Expected InvalidSeed, got \(error)")
            }
        } catch {
            XCTFail("Expected WalletKitError, got \(error)")
        }
    }

    func testInvalidRpcUrlEmpty() async {
        let seed = generateRandomSeed()

        do {
            _ = try await Authenticator.initWithDefaults(
                seed: seed,
                rpcUrl: "",
                environment: .staging
            )
            XCTFail("Should have thrown InvalidRpcUrl error")
        } catch let error as WalletKitError {
            switch error {
            case .InvalidRpcUrl:
                break // Expected
            default:
                XCTFail("Expected InvalidRpcUrl, got \(error)")
            }
        } catch {
            XCTFail("Expected WalletKitError, got \(error)")
        }
    }

    // MARK: - Environment Tests

    func testEnvironmentValues() {
        // Just verify environments exist and can be created
        let staging = Environment.staging
        let production = Environment.production

        XCTAssertNotNil(staging)
        XCTAssertNotNil(production)
    }
}
