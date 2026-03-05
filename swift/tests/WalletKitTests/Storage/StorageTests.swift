import CryptoKit
import Foundation
import Security
import XCTest
@testable import WalletKit

final class AtomicBlobStoreTests: XCTestCase {
    func testWriteReadDelete() throws {
        let root = makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = TestIOSAtomicBlobStore(baseURL: root)
        let path = "account_keys.bin"
        let payload = Data([1, 2, 3, 4])

        try store.writeAtomic(path: path, bytes: payload)
        let readBack = try store.read(path: path)

        XCTAssertEqual(readBack, payload)

        try store.delete(path: path)
        let afterDelete = try store.read(path: path)
        XCTAssertNil(afterDelete)
    }
}

final class CredentialStoreTests: XCTestCase {
    private let account = "test-account"

    func testMethodsRequireInit() throws {
        let root = makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let service = uniqueKeystoreService()
        defer { deleteKeychainItem(service: service, account: account) }

        let store = try CredentialStore.newWithComponents(
            paths: StoragePaths.fromRoot(root: root.path),
            keystore: TestIOSDeviceKeystore(service: service, account: account),
            blobStore: TestIOSAtomicBlobStore(
                baseURL: root.appendingPathComponent("worldid", isDirectory: true)
            )
        )

        XCTAssertThrowsError(try store.listCredentials(
            issuerSchemaId: Optional<UInt64>.none,
            now: 100
        )) { error in
            XCTAssertEqual(error as? StorageError, .NotInitialized)
        }
        XCTAssertThrowsError(try store.merkleCacheGet(validUntil: 100)) { error in
            XCTAssertEqual(error as? StorageError, .NotInitialized)
        }
    }

    func testStoreAndCacheFlows() throws {
        let root = makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let service = uniqueKeystoreService()
        defer { deleteKeychainItem(service: service, account: account) }

        let keystore = TestIOSDeviceKeystore(service: service, account: account)
        let worldidDir = root.appendingPathComponent("worldid", isDirectory: true)
        let blobStore = TestIOSAtomicBlobStore(baseURL: worldidDir)
        let paths = StoragePaths.fromRoot(root: root.path)

        let store = try CredentialStore.newWithComponents(
            paths: paths,
            keystore: keystore,
            blobStore: blobStore
        )

        try store.`init`(leafIndex: 42, now: 100)
        XCTAssertNil(try store.merkleCacheGet(validUntil: 100))

        let credentialId = try store.storeCredential(
            credential: sampleCredential(),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_800_000_000,
            associatedData: Data([4, 5, 6]),
            now: 100
        )

        let records = try store.listCredentials(issuerSchemaId: Optional<UInt64>.none, now: 101)
        XCTAssertEqual(records.count, 1)
        let record = records[0]
        XCTAssertEqual(record.credentialId, credentialId)
        XCTAssertEqual(record.issuerSchemaId, 7)
        XCTAssertEqual(record.expiresAt, 1_800_000_000)

        let proofBytes = Data([9, 9, 9])
        try store.merkleCachePut(
            proofBytes: proofBytes,
            now: 100,
            ttlSeconds: 60
        )
        let cached = try store.merkleCacheGet(
            validUntil: 110
        )
        XCTAssertEqual(cached, proofBytes)
        let expired = try store.merkleCacheGet(validUntil: 161)
        XCTAssertNil(expired)
    }

    func testReopenPersistsVaultAndCache() throws {
        let root = makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let service = uniqueKeystoreService()
        defer { deleteKeychainItem(service: service, account: account) }

        let firstStore = try CredentialStore.newWithComponents(
            paths: StoragePaths.fromRoot(root: root.path),
            keystore: TestIOSDeviceKeystore(service: service, account: account),
            blobStore: TestIOSAtomicBlobStore(
                baseURL: root.appendingPathComponent("worldid", isDirectory: true)
            )
        )
        try firstStore.`init`(leafIndex: 42, now: 100)
        let credentialId = try firstStore.storeCredential(
            credential: sampleCredential(),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_800_000_000,
            associatedData: nil,
            now: 100
        )
        let proofBytes = Data([9, 9, 9])
        try firstStore.merkleCachePut(proofBytes: proofBytes, now: 100, ttlSeconds: 60)

        let reopenedStore = try CredentialStore.newWithComponents(
            paths: StoragePaths.fromRoot(root: root.path),
            keystore: TestIOSDeviceKeystore(service: service, account: account),
            blobStore: TestIOSAtomicBlobStore(
                baseURL: root.appendingPathComponent("worldid", isDirectory: true)
            )
        )
        try reopenedStore.`init`(leafIndex: 42, now: 101)

        let records = try reopenedStore.listCredentials(
            issuerSchemaId: Optional<UInt64>.none,
            now: 102
        )
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].credentialId, credentialId)
        XCTAssertEqual(try reopenedStore.merkleCacheGet(validUntil: 120), proofBytes)
    }
}

final class DeviceKeystoreTests: XCTestCase {
    private let account = "test-account"

    func testSealAndOpenRoundTrip() throws {
        let service = uniqueKeystoreService()
        defer { deleteKeychainItem(service: service, account: account) }

        let keystore = TestIOSDeviceKeystore(service: service, account: account)
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

        let keystore = TestIOSDeviceKeystore(service: service, account: account)
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

    func testReopenWithSameIdentityCanOpenCiphertext() throws {
        let service = uniqueKeystoreService()
        defer { deleteKeychainItem(service: service, account: account) }

        let firstKeystore = TestIOSDeviceKeystore(service: service, account: account)
        let secondKeystore = TestIOSDeviceKeystore(service: service, account: account)
        let associatedData = Data("ad".utf8)
        let plaintext = Data("hello".utf8)

        let ciphertext = try firstKeystore.seal(
            associatedData: associatedData,
            plaintext: plaintext
        )
        let opened = try secondKeystore.openSealed(
            associatedData: associatedData,
            ciphertext: ciphertext
        )

        XCTAssertEqual(opened, plaintext)
    }
}

func makeTempDirectory() -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(
        "walletkit-tests-\(UUID().uuidString)",
        isDirectory: true
    )
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
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

func sampleCredential(
    issuerSchemaId: UInt64 = 7,
    expiresAt: UInt64 = 1_800_000_000
) throws -> Credential {
    let sampleCredentialJSON = """
    {"id":13758530325042616850,"version":"V1","issuer_schema_id":\(issuerSchemaId),"sub":"0x114edc9e30c245ac8e1f98375f71668a9cd4e9f1e3e9b3385a1801e9d43d731b","genesis_issued_at":1700000000,"expires_at":\(expiresAt),"claims":["0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000"],"associated_data_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","signature":null,"issuer":"0100000000000000000000000000000000000000000000000000000000000000"}
    """
    let bytes = Data(sampleCredentialJSON.utf8)
    return try Credential.fromBytes(bytes: bytes)
}

func sampleBlindingFactor() -> FieldElement {
    FieldElement.fromU64(value: 17)
}

final class TestIOSAtomicBlobStore: AtomicBlobStore {
    private let baseURL: URL
    private let fileManager = FileManager.default

    init(baseURL: URL) {
        self.baseURL = baseURL
    }

    func read(path: String) throws -> Data? {
        let url = baseURL.appendingPathComponent(path)
        guard fileManager.fileExists(atPath: url.path) else {
            return nil
        }
        do {
            return try Data(contentsOf: url)
        } catch {
            throw StorageError.BlobStore("read failed: \(error)")
        }
    }

    func writeAtomic(path: String, bytes: Data) throws {
        let url = baseURL.appendingPathComponent(path)
        let parent = url.deletingLastPathComponent()
        do {
            try fileManager.createDirectory(
                at: parent,
                withIntermediateDirectories: true
            )
            try bytes.write(to: url, options: .atomic)
        } catch {
            throw StorageError.BlobStore("write failed: \(error)")
        }
    }

    func delete(path: String) throws {
        let url = baseURL.appendingPathComponent(path)
        guard fileManager.fileExists(atPath: url.path) else {
            throw StorageError.BlobStore("delete failed: file not found")
        }
        do {
            try fileManager.removeItem(at: url)
        } catch {
            throw StorageError.BlobStore("delete failed: \(error)")
        }
    }
}

final class TestIOSDeviceKeystore: DeviceKeystore {
    private let service: String
    private let account: String
    private let lock = NSLock()
    private static let fallbackLock = NSLock()
    private static var fallbackKeys: [String: Data] = [:]

    init(
        service: String = "walletkit.devicekeystore",
        account: String = "default"
    ) {
        self.service = service
        self.account = account
    }

    func seal(associatedData: Data, plaintext: Data) throws -> Data {
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

    func openSealed(associatedData: Data, ciphertext: Data) throws -> Data {
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
