import CryptoKit
import Foundation
import Security

public final class IOSDeviceKeystore: DeviceKeystore {
    private let service: String
    private let account: String
    private let lock = NSLock()
    private static let fallbackLock = NSLock()
    private static var fallbackKeys: [String: Data] = [:]

    public init(
        service: String = "walletkit.devicekeystore",
        account: String = "default"
    ) {
        self.service = service
        self.account = account
    }

    public func seal(associatedData: Data, plaintext: Data) throws -> Data {
        let key = try loadOrCreateKey()
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: key,
            authenticating: associatedData
        )
        guard let combined = sealedBox.combined else {
            throw StorageError.Keystore("missing AES-GCM combined payload")
        }
        return combined
    }

    public func openSealed(associatedData: Data, ciphertext: Data) throws -> Data {
        let key = try loadOrCreateKey()
        let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
        return try AES.GCM.open(
            sealedBox,
            using: key,
            authenticating: associatedData
        )
    }

    private func loadOrCreateKey() throws -> SymmetricKey {
        lock.lock()
        defer { lock.unlock() }

        if let data = try loadKeyData() {
            return SymmetricKey(data: data)
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw StorageError.Keystore("random key generation failed: \(status)")
        }
        let keyData = Data(bytes)

        let addStatus = SecItemAdd(
            keychainAddQuery(keyData: keyData) as CFDictionary,
            nil
        )
        if addStatus == errSecDuplicateItem {
            if let data = try loadKeyData() {
                return SymmetricKey(data: data)
            }
            throw StorageError.Keystore("keychain item duplicated but unreadable")
        }
        if addStatus == errSecMissingEntitlement {
            Self.setFallbackKey(id: fallbackKeyId(), data: keyData)
            return SymmetricKey(data: keyData)
        }
        guard addStatus == errSecSuccess else {
            throw StorageError.Keystore("keychain add failed: \(addStatus)")
        }

        return SymmetricKey(data: keyData)
    }

    private func loadKeyData() throws -> Data? {
        var query = keychainBaseQuery()
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        if status == errSecMissingEntitlement {
            return Self.fallbackKey(id: fallbackKeyId())
        }
        guard status == errSecSuccess else {
            throw StorageError.Keystore("keychain read failed: \(status)")
        }
        guard let data = item as? Data else {
            throw StorageError.Keystore("keychain read returned non-data")
        }
        return data
    }

    private func keychainBaseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
    }

    private func keychainAddQuery(keyData: Data) -> [String: Any] {
        var query = keychainBaseQuery()
        query[kSecValueData as String] = keyData
        return query
    }

    private func fallbackKeyId() -> String {
        "\(service)::\(account)"
    }

    private static func fallbackKey(id: String) -> Data? {
        fallbackLock.lock()
        defer { fallbackLock.unlock() }
        return fallbackKeys[id]
    }

    private static func setFallbackKey(id: String, data: Data) {
        fallbackLock.lock()
        defer { fallbackLock.unlock() }
        fallbackKeys[id] = data
    }
}
