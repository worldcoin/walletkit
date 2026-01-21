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

    func testU256WrapperFromU64MaxValue() {
        // Test with max u64 value
        let maxU64 = UInt64.max
        let u256 = U256Wrapper.fromU64(value: maxU64)
        XCTAssertEqual(u256.toDecimalString(), "18446744073709551615")
        XCTAssertEqual(u256.toHexString(), "0x000000000000000000000000000000000000000000000000ffffffffffffffff")
    }

    func testU256WrapperFromU32MaxValue() {
        // Test with max u32 value
        let maxU32 = UInt32.max
        let u256 = U256Wrapper.fromU32(value: maxU32)
        XCTAssertEqual(u256.toDecimalString(), "4294967295")
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

    func testU256WrapperDeterministicHexParsing() throws {
        // Test with known values from Rust tests
        let testCases: [(String, String, String)] = [
            (
                "0x0000000000000000000000000000000000000000000000000000000000000001",
                "1",
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ),
            (
                "0x000000000000000000000000000000000000000000000000000000000000002a",
                "42",
                "0x000000000000000000000000000000000000000000000000000000000000002a"
            ),
            (
                "0x00000000000000000000000000000000000000000000000000000000000f423f",
                "999999",
                "0x00000000000000000000000000000000000000000000000000000000000f423f"
            ),
            (
                "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
                "80084422859880547211683076133703299733277748156566366325829078699459944778998",
                "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
            ),
        ]

        for (hexInput, expectedDecimal, expectedHex) in testCases {
            let u256 = try U256Wrapper.tryFromHexString(hexString: hexInput)
            XCTAssertEqual(u256.toDecimalString(), expectedDecimal, "Decimal mismatch for \(hexInput)")
            XCTAssertEqual(u256.toHexString(), expectedHex, "Hex mismatch for \(hexInput)")
        }
    }

    func testU256WrapperHexRoundTrip() throws {
        // Test that parsing and formatting hex strings round-trips correctly
        let hexStrings = [
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x00000000000000000000000000000000000000000000000000000000000000ff",
            "0x0000000000000000000000000000000000000000000000000000000000001234",
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ]

        for hexString in hexStrings {
            let u256 = try U256Wrapper.tryFromHexString(hexString: hexString)
            XCTAssertEqual(u256.toHexString(), hexString, "Round-trip failed for \(hexString)")
        }
    }

    func testU256WrapperInvalidHexString() {
        XCTAssertThrowsError(try U256Wrapper.tryFromHexString(hexString: "0xZZZ")) { error in
            XCTAssertTrue(error is WalletKitError)
        }
    }

    func testU256WrapperInvalidHexStrings() {
        // Test multiple invalid inputs
        let invalidInputs = [
            "0xZZZZ",
            "1g",
            "not a hex string",
            "0xGGGG",
        ]

        for invalidInput in invalidInputs {
            XCTAssertThrowsError(try U256Wrapper.tryFromHexString(hexString: invalidInput)) { error in
                XCTAssertTrue(error is WalletKitError, "Should throw WalletKitError for: \(invalidInput)")
            }
        }
    }

    func testU256WrapperEmptyString() throws {
        // Empty string parses as 0 (after trimming "0x", "" is passed to radix parser)
        let u256 = try U256Wrapper.tryFromHexString(hexString: "")
        XCTAssertEqual(u256.toDecimalString(), "0")
        XCTAssertEqual(u256.toHexString(), "0x0000000000000000000000000000000000000000000000000000000000000000")
    }

    func testU256WrapperFromLimbs() throws {
        // Test with simple value [1, 0, 0, 0]
        let limbs: [UInt64] = [1, 0, 0, 0]
        let u256 = try U256Wrapper.fromLimbs(limbs: limbs)
        XCTAssertEqual(u256.toDecimalString(), "1")
    }

    func testU256WrapperFromLimbsComplexValue() throws {
        // Test with complex limb values from Rust tests
        let limbs: [UInt64] = [1, 0, 0, 2161727821137838080]
        let u256 = try U256Wrapper.fromLimbs(limbs: limbs)
        XCTAssertEqual(
            u256.toHexString(),
            "0x1e00000000000000000000000000000000000000000000000000000000000001"
        )
    }

    func testU256WrapperFromLimbsInvalidLength() {
        // Must be exactly 4 limbs
        XCTAssertThrowsError(try U256Wrapper.fromLimbs(limbs: [1, 0, 0])) { error in
            XCTAssertTrue(error is WalletKitError)
        }

        XCTAssertThrowsError(try U256Wrapper.fromLimbs(limbs: [1, 0, 0, 0, 5])) { error in
            XCTAssertTrue(error is WalletKitError)
        }

        XCTAssertThrowsError(try U256Wrapper.fromLimbs(limbs: [])) { error in
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

    func testU256WrapperToHexStringPadding() {
        // Test that small values are properly padded
        let testCases: [(UInt64, String)] = [
            (1, "0x0000000000000000000000000000000000000000000000000000000000000001"),
            (2, "0x0000000000000000000000000000000000000000000000000000000000000002"),
            (255, "0x00000000000000000000000000000000000000000000000000000000000000ff"),
        ]

        for (value, expectedHex) in testCases {
            let u256 = U256Wrapper.fromU64(value: value)
            XCTAssertEqual(u256.toHexString(), expectedHex)
        }
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

    func testU256WrapperLimbsRoundTrip() throws {
        // Test that converting to/from limbs round-trips correctly
        let originalLimbs: [UInt64] = [12345, 67890, 11111, 22222]
        let u256 = try U256Wrapper.fromLimbs(limbs: originalLimbs)
        let resultLimbs = u256.intoLimbs()

        XCTAssertEqual(resultLimbs, originalLimbs)
    }

    func testU256WrapperZeroValue() {
        let u256 = U256Wrapper.fromU64(value: 0)
        XCTAssertEqual(u256.toDecimalString(), "0")
        XCTAssertEqual(u256.toHexString(), "0x0000000000000000000000000000000000000000000000000000000000000000")

        let limbs = u256.intoLimbs()
        XCTAssertEqual(limbs, [0, 0, 0, 0])
    }

    func testU256WrapperMultipleConversions() throws {
        // Test creating U256 from different sources and verifying consistency
        let value: UInt64 = 999999

        let fromU64 = U256Wrapper.fromU64(value: value)
        let fromHex = try U256Wrapper.tryFromHexString(
            hexString: "0x00000000000000000000000000000000000000000000000000000000000f423f"
        )
        let fromLimbs = try U256Wrapper.fromLimbs(limbs: [999999, 0, 0, 0])

        // All should produce the same decimal string
        XCTAssertEqual(fromU64.toDecimalString(), "999999")
        XCTAssertEqual(fromHex.toDecimalString(), "999999")
        XCTAssertEqual(fromLimbs.toDecimalString(), "999999")

        // All should produce the same hex string
        let expectedHex = "0x00000000000000000000000000000000000000000000000000000000000f423f"
        XCTAssertEqual(fromU64.toHexString(), expectedHex)
        XCTAssertEqual(fromHex.toHexString(), expectedHex)
        XCTAssertEqual(fromLimbs.toHexString(), expectedHex)
    }

    // MARK: - Authenticator Initialization Tests

    func testInvalidSeedEmpty() async {
        let emptySeed = Data()

        await XCTAssertThrowsErrorAsync(
            try await Authenticator.initWithDefaults(
                seed: emptySeed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
        ) { error in
            if let walletError = error as? WalletKitError,
               case .InvalidInput(let attribute, _) = walletError {
                XCTAssertEqual(attribute, "seed")
            } else {
                XCTFail("Expected InvalidInput for seed, got \(error)")
            }
        }
    }

    func testInvalidSeedTooShort() async {
        let shortSeed = Data(repeating: 0, count: 16)

        await XCTAssertThrowsErrorAsync(
            try await Authenticator.initWithDefaults(
                seed: shortSeed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
        ) { error in
            if let walletError = error as? WalletKitError,
               case .InvalidInput(let attribute, _) = walletError {
                XCTAssertEqual(attribute, "seed")
            } else {
                XCTFail("Expected InvalidInput for seed, got \(error)")
            }
        }
    }

    func testInvalidSeedTooLong() async {
        let longSeed = Data(repeating: 0, count: 64)

        await XCTAssertThrowsErrorAsync(
            try await Authenticator.initWithDefaults(
                seed: longSeed,
                rpcUrl: testRpcUrl,
                environment: .staging
            )
        ) { error in
            if let walletError = error as? WalletKitError,
               case .InvalidInput(let attribute, _) = walletError {
                XCTAssertEqual(attribute, "seed")
            } else {
                XCTFail("Expected InvalidInput for seed, got \(error)")
            }
        }
    }

    func testInvalidRpcUrlEmpty() async {
        let seed = generateRandomSeed()

        await XCTAssertThrowsErrorAsync(
            try await Authenticator.initWithDefaults(
                seed: seed,
                rpcUrl: "",
                environment: .staging
            )
        ) { error in
            if let walletError = error as? WalletKitError,
               case .InvalidInput(let attribute, _) = walletError {
                XCTAssertEqual(attribute, "rpc_url")
            } else {
                XCTFail("Expected InvalidInput for rpc_url, got \(error)")
            }
        }
    }

    func testMultipleEnvironments() async {
        let seed = generateRandomSeed()
        let environments: [Environment] = [.staging, .production]

        for environment in environments {
            await XCTAssertThrowsErrorAsync(
                try await Authenticator.initWithDefaults(
                    seed: seed,
                    rpcUrl: testRpcUrl,
                    environment: environment
                )
            ) { error in
                // Should throw an error for non-existent account in any environment
                XCTAssertTrue(error is WalletKitError, "Should throw WalletKitError for \(environment)")
            }
        }
    }

    func testValidSeedLength() {
        let validSeed = Data(repeating: 0, count: 32)
        XCTAssertEqual(validSeed.count, 32, "Valid seed should be 32 bytes")
    }

    func testGenerateRandomSeedLength() {
        let seed = generateRandomSeed()
        XCTAssertEqual(seed.count, 32, "Generated seed should be 32 bytes")
    }

    func testGenerateRandomSeedRandomness() {
        // Generate multiple seeds and verify they're different
        let seed1 = generateRandomSeed()
        let seed2 = generateRandomSeed()
        let seed3 = generateRandomSeed()

        XCTAssertNotEqual(seed1, seed2, "Seeds should be random and different")
        XCTAssertNotEqual(seed2, seed3, "Seeds should be random and different")
        XCTAssertNotEqual(seed1, seed3, "Seeds should be random and different")
    }

    // MARK: - Helper for async error assertions

    func XCTAssertThrowsErrorAsync<T>(
        _ expression: @autoclosure () async throws -> T,
        _ message: @autoclosure () -> String = "",
        file: StaticString = #filePath,
        line: UInt = #line,
        _ errorHandler: (_ error: Error) -> Void = { _ in }
    ) async {
        do {
            _ = try await expression()
            XCTFail(message(), file: file, line: line)
        } catch {
            errorHandler(error)
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