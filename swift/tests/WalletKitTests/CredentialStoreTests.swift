import Foundation
import XCTest
@testable import WalletKit

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

    func testInitRejectsLeafIndexMismatch() throws {
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

        try store.`init`(leafIndex: 42, now: 100)

        XCTAssertThrowsError(try store.`init`(leafIndex: 43, now: 101)) { error in
            guard case let .InvalidLeafIndex(expected, provided) = error as? StorageError else {
                return XCTFail("Expected InvalidLeafIndex, got \(error)")
            }
            XCTAssertEqual(expected, 42)
            XCTAssertEqual(provided, 43)
        }
    }

    func testInitIsIdempotentForSameLeafIndex() throws {
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

        try store.`init`(leafIndex: 42, now: 100)
        let credentialId = try store.storeCredential(
            credential: sampleCredential(),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_800_000_000,
            associatedData: nil,
            now: 100
        )

        try store.`init`(leafIndex: 42, now: 101)

        let records = try store.listCredentials(issuerSchemaId: Optional<UInt64>.none, now: 102)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].credentialId, credentialId)
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

    func testStoreCredentialReturnsStableDistinctIds() throws {
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

        try store.`init`(leafIndex: 42, now: 100)
        let firstCredentialId = try store.storeCredential(
            credential: sampleCredential(issuerSchemaId: 7, expiresAt: 1_800_000_000),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_800_000_000,
            associatedData: nil,
            now: 100
        )
        let secondCredentialId = try store.storeCredential(
            credential: sampleCredential(issuerSchemaId: 8, expiresAt: 1_900_000_000),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_900_000_000,
            associatedData: nil,
            now: 101
        )

        XCTAssertNotEqual(firstCredentialId, secondCredentialId)

        let records = try store.listCredentials(issuerSchemaId: Optional<UInt64>.none, now: 102)
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(Set(records.map(\.credentialId)), Set([firstCredentialId, secondCredentialId]))
    }

    func testListCredentialsFiltersByIssuerSchemaId() throws {
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

        try store.`init`(leafIndex: 42, now: 100)
        _ = try store.storeCredential(
            credential: sampleCredential(issuerSchemaId: 7, expiresAt: 1_800_000_000),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_800_000_000,
            associatedData: nil,
            now: 100
        )
        _ = try store.storeCredential(
            credential: sampleCredential(issuerSchemaId: 8, expiresAt: 1_900_000_000),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_900_000_000,
            associatedData: nil,
            now: 101
        )

        let filtered = try store.listCredentials(issuerSchemaId: 7, now: 102)
        XCTAssertEqual(filtered.count, 1)
        XCTAssertEqual(filtered[0].issuerSchemaId, 7)
    }

    func testExpiredCredentialsAreFilteredOut() throws {
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

        try store.`init`(leafIndex: 42, now: 100)
        _ = try store.storeCredential(
            credential: sampleCredential(issuerSchemaId: 7, expiresAt: 120),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 120,
            associatedData: nil,
            now: 100
        )
        _ = try store.storeCredential(
            credential: sampleCredential(issuerSchemaId: 8, expiresAt: 1_800_000_000),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_800_000_000,
            associatedData: nil,
            now: 101
        )

        let records = try store.listCredentials(issuerSchemaId: Optional<UInt64>.none, now: 121)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].issuerSchemaId, 8)
    }

    func testStoragePathsMatchWorldIdLayout() throws {
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

        let paths = try store.storagePaths()
        XCTAssertEqual(paths.rootPathString(), root.path)
        XCTAssertTrue(paths.worldidDirPathString().hasSuffix("/worldid"))
        XCTAssertTrue(paths.vaultDbPathString().hasSuffix("/worldid/account.vault.sqlite"))
        XCTAssertTrue(paths.cacheDbPathString().hasSuffix("/worldid/account.cache.sqlite"))
        XCTAssertTrue(paths.lockPathString().hasSuffix("/worldid/lock"))
    }

    func testMerkleCachePutRefreshesExistingEntry() throws {
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

        try store.`init`(leafIndex: 42, now: 100)
        try store.merkleCachePut(proofBytes: Data([1, 2, 3]), now: 100, ttlSeconds: 10)
        try store.merkleCachePut(proofBytes: Data([4, 5, 6]), now: 101, ttlSeconds: 60)

        let cached = try store.merkleCacheGet(validUntil: 120)
        XCTAssertEqual(cached, Data([4, 5, 6]))
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
