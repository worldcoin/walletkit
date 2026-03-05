import Foundation
import XCTest
@testable import WalletKit

final class CredentialStoreTests: XCTestCase {
    private let account = "test-account"

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

        let credentialId = try store.storeCredential(
            credential: sampleCredential(),
            blindingFactor: sampleBlindingFactor(),
            expiresAt: 1_800_000_000,
            associatedData: Data([4, 5, 6]),
            now: 100
        )

        XCTAssertEqual(credentialId, 1)

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
}
