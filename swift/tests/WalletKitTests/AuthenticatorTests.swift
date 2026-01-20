import XCTest
@testable import WalletKit

final class AuthenticatorTests: XCTestCase {

    let testRpcUrl = "https://worldchain-sepolia.g.alchemy.com/public"

    // MARK: - Helper Functions

    func generateRandomSeed() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 {
            bytes[i] = UInt8.random(in: 0...255)
        }
        return Data(bytes)
    }

    // MARK: - U256Wrapper Tests

    func testU256WrapperFromU64() {
        let value: UInt64 = 12345
        let u256 = U256Wrapper.fromU64(value: value)
        XCTAssertEqual(u256.toDecimalString(), "12345")
    }

    func testU256WrapperFromU32() {
        let value: UInt32 = 54321
        let u256 = U256Wrapper.fromU32(value: value)
        XCTAssertEqual(u256.toDecimalString(), "54321")
    }

    func testU256WrapperTryFromHexString() throws {
        let hexString = "0x1a2b3c4d5e6f"
        let u256 = try U256Wrapper.tryFromHexString(hexString: hexString)
        XCTAssertNotNil(u256)
        // Verify the hex round-trips correctly
        XCTAssertTrue(u256.toHexString().hasSuffix("1a2b3c4d5e6f"))
    }

    func testU256WrapperTryFromHexStringWithoutPrefix() throws {
        let hexString = "1a2b3c4d5e6f"
        let u256 = try U256Wrapper.tryFromHexString(hexString: hexString)
        XCTAssertNotNil(u256)
    }

    func testU256WrapperInvalidHexString() {
        XCTAssertThrowsError(try U256Wrapper.tryFromHexString(hexString: "0xZZZ")) { error in
            XCTAssertTrue(error is WalletKitError)
        }
    }

    func testU256WrapperFromLimbs() throws {
        // Test with simple value [1, 0, 0, 0]
        let limbs: [UInt64] = [1, 0, 0, 0]
        let u256 = try U256Wrapper.fromLimbs(limbs: limbs)
        XCTAssertEqual(u256.toDecimalString(), "1")
    }

    func testU256WrapperFromLimbsInvalidLength() {
        // Must be exactly 4 limbs
        XCTAssertThrowsError(try U256Wrapper.fromLimbs(limbs: [1, 0, 0])) { error in
            XCTAssertTrue(error is WalletKitError)
        }
    }

    func testU256WrapperToHexString() {
        let u256 = U256Wrapper.fromU64(value: 42)
        let hexString = u256.toHexString()
        // Should be padded to 66 characters (0x + 64 hex digits)
        XCTAssertEqual(hexString.count, 66)
        XCTAssertTrue(hexString.hasPrefix("0x"))
        XCTAssertTrue(hexString.hasSuffix("2a"))
    }

    func testU256WrapperIntoLimbs() {
        let u256 = U256Wrapper.fromU64(value: 12345)
        let limbs = u256.intoLimbs()
        XCTAssertEqual(limbs.count, 4)
        XCTAssertEqual(limbs[0], 12345)
        XCTAssertEqual(limbs[1], 0)
        XCTAssertEqual(limbs[2], 0)
        XCTAssertEqual(limbs[3], 0)
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
            XCTFail("Should have thrown an error for non-existent account")
        } catch let error as WalletKitError {
            // Expected - account doesn't exist for random seed
            // This could be AccountDoesNotExist or AuthenticatorError depending on
            // how the contract call fails (contract not found, account not found, etc.)
            switch error {
            case .AccountDoesNotExist:
                break // Expected - account not in registry
            case .AuthenticatorError(let message):
                // Also acceptable - contract/RPC errors when account doesn't exist
                XCTAssertTrue(message.contains("contract") || message.contains("account"),
                             "Error message should mention contract or account: \(message)")
            default:
                XCTFail("Expected AccountDoesNotExist or AuthenticatorError, got \(error)")
            }
        } catch {
            XCTFail("Expected WalletKitError, got \(error)")
        }
    }

    func testInvalidSeedEmpty() async {
        let emptySeed = Data()

        do {
            _ = try await Authenticator.initWithDefaults(
                seed: emptySeed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
            XCTFail("Should have thrown InvalidInput error")
        } catch let error as WalletKitError {
            switch error {
            case .InvalidInput(let attribute, _):
                XCTAssertEqual(attribute, "seed")
            default:
                XCTFail("Expected InvalidInput for seed, got \(error)")
            }
        } catch {
            XCTFail("Expected WalletKitError, got \(error)")
        }
    }

    func testInvalidSeedTooShort() async {
        let shortSeed = Data(repeating: 0, count: 16) // Too short

        do {
            _ = try await Authenticator.initWithDefaults(
                seed: shortSeed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
            XCTFail("Should have thrown InvalidInput error")
        } catch let error as WalletKitError {
            switch error {
            case .InvalidInput(let attribute, _):
                XCTAssertEqual(attribute, "seed")
            default:
                XCTFail("Expected InvalidInput for seed, got \(error)")
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
            XCTFail("Should have thrown InvalidInput error")
        } catch let error as WalletKitError {
            switch error {
            case .InvalidInput(let attribute, _):
                XCTAssertEqual(attribute, "rpc_url")
            default:
                XCTFail("Expected InvalidInput for rpc_url, got \(error)")
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
