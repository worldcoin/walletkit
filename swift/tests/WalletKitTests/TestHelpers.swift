import Foundation
import Security

func makeTempDirectory() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(
        "walletkit-tests-\(UUID().uuidString)",
        isDirectory: true
    )
}

func uniqueKeystoreService() -> String {
    "walletkit.devicekeystore.test.\(UUID().uuidString)"
}

func deleteKeychainItem(service: String, account: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]
    SecItemDelete(query as CFDictionary)
}
