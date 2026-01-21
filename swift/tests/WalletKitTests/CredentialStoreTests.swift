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

        let keystore = IOSDeviceKeystore(service: service, account: account)
        let worldidDir = root.appendingPathComponent("worldid", isDirectory: true)
        let blobStore = IOSAtomicBlobStore(baseURL: worldidDir)
        let paths = StoragePaths.fromRoot(root: root.path)

        let store = try CredentialStore.newWithComponents(
            paths: paths,
            keystore: keystore,
            blobStore: blobStore
        )

        try store.`init`(leafIndex: 42, now: 100)

        let credentialId = try store.storeCredential(
            issuerSchemaId: 7,
            status: .active,
            subjectBlindingFactor: Data(repeating: 0x11, count: 32),
            genesisIssuedAt: 1_700_000_000,
            expiresAt: 1_800_000_000,
            credentialBlob: Data([1, 2, 3]),
            associatedData: Data([4, 5, 6]),
            now: 100
        )

        XCTAssertEqual(credentialId.count, 16)

        let records = try store.listCredentials(issuerSchemaId: nil, now: 101)
        XCTAssertEqual(records.count, 1)
        let record = records[0]
        XCTAssertEqual(record.issuerSchemaId, 7)
        XCTAssertEqual(record.credentialId, credentialId)
        XCTAssertEqual(record.subjectBlindingFactor.count, 32)

        let rootHash = Data(repeating: 0x22, count: 32)
        let proofBytes = Data([9, 9, 9])
        try store.merkleCachePut(
            registryKind: 1,
            root: rootHash,
            proofBytes: proofBytes,
            now: 100,
            ttlSeconds: 60
        )
        let cached = try store.merkleCacheGet(
            registryKind: 1,
            root: rootHash,
            now: 110
        )
        XCTAssertEqual(cached, proofBytes)

        let requestId = Data(repeating: 0x01, count: 32)
        let nullifier = Data(repeating: 0x02, count: 32)
        let first = try store.beginProofDisclosure(
            requestId: requestId,
            nullifier: nullifier,
            proofBytes: Data([7, 7]),
            now: 120,
            ttlSeconds: 60
        )
        XCTAssertEqual(first.kind, .fresh)
        XCTAssertEqual(first.bytes, Data([7, 7]))

        let replay = try store.beginProofDisclosure(
            requestId: requestId,
            nullifier: nullifier,
            proofBytes: Data([8, 8]),
            now: 130,
            ttlSeconds: 60
        )
        XCTAssertEqual(replay.kind, .replay)
        XCTAssertEqual(replay.bytes, Data([7, 7]))
    }
}
