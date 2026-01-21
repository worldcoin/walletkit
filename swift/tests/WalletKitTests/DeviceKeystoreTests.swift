import CryptoKit
import Foundation
import Security
import XCTest
@testable import WalletKit

final class DeviceKeystoreTests: XCTestCase {
    private let account = "test-account"

    func testSealAndOpenRoundTrip() throws {
        let service = uniqueKeystoreService()
        defer { deleteKeychainItem(service: service, account: account) }

        let keystore = IOSDeviceKeystore(service: service, account: account)
        let associatedData = Data("ad".utf8)
        let plaintext = Data("hello".utf8)

        let ciphertext = try keystore.seal(
            associatedData: associatedData,
            plaintext: plaintext
        )
        let opened = try keystore.openSealed(
            associatedData: associatedData,
            ciphertext: ciphertext
        )

        XCTAssertEqual(opened, plaintext)
    }

    func testAssociatedDataMismatchFails() throws {
        let service = uniqueKeystoreService()
        defer { deleteKeychainItem(service: service, account: account) }

        let keystore = IOSDeviceKeystore(service: service, account: account)
        let plaintext = Data("secret".utf8)

        let ciphertext = try keystore.seal(
            associatedData: Data("ad-1".utf8),
            plaintext: plaintext
        )

        XCTAssertThrowsError(
            try keystore.openSealed(
                associatedData: Data("ad-2".utf8),
                ciphertext: ciphertext
            )
        )
    }
}
