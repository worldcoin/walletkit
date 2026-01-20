import Foundation
import XCTest
@testable import WalletKit

final class AtomicBlobStoreTests: XCTestCase {
    func testWriteReadDelete() throws {
        let root = makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = IOSAtomicBlobStore(baseURL: root)
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
