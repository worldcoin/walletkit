import Foundation
import XCTest

@testable import WalletKit

private final class MemoryStorage: DeviceKeystore, AtomicBlobStore, @unchecked Sendable {
  private let lock = NSLock()
  private var blobs: [String: Data] = [:]
  func seal(associatedData: Data, plaintext: Data) throws -> Data { associatedData + plaintext }
  func openSealed(associatedData: Data, ciphertext: Data) throws -> Data {
    guard ciphertext.starts(with: associatedData) else {
      throw WalletKitBridgeError(code: "TestAuthenticationFailed")
    }
    return ciphertext.dropFirst(associatedData.count)
  }
  func read(path: String) -> Data? {
    lock.lock()
    defer { lock.unlock() }
    return blobs[path]
  }
  func writeAtomic(path: String, bytes: Data) {
    lock.lock()
    defer { lock.unlock() }
    blobs[path] = bytes
  }
  func delete(path: String) {
    lock.lock()
    defer { lock.unlock() }
    blobs.removeValue(forKey: path)
  }
}
private struct FailingKeystore: DeviceKeystore {
  func seal(associatedData: Data, plaintext: Data) throws -> Data {
    throw WalletKitBridgeError(code: "private-host-message")
  }
  func openSealed(associatedData: Data, ciphertext: Data) throws -> Data {
    throw WalletKitBridgeError(code: "private-host-message")
  }
}
private struct ActivityListener: ActivityChangedListener {
  let callback: @Sendable () -> Void
  func onActivityChanged() { callback() }
}

final class SimpleTest: XCTestCase {
  func testFieldElementAndUnsignedIntegerRoundTrip() throws {
    let field = try FieldElement.fromU64(value: UInt64.max)
    defer { field.close() }
    let bytes = try field.toBytes()
    XCTAssertEqual(bytes.count, 32)
    XCTAssertEqual(bytes.suffix(8), Data(repeating: 255, count: 8))
    let restored = try FieldElement.fromBytes(bytes: bytes)
    defer { restored.close() }
    XCTAssertEqual(try field.toHexString(), try restored.toHexString())
    let integer = try Uint256(hex: String(repeating: "f", count: 64))
    XCTAssertEqual(integer.bytes, Data(repeating: 255, count: 32))
    XCTAssertThrowsError(try Uint256(hex: "-1"))
    XCTAssertThrowsError(try FieldElement.fromBytes(bytes: Data(repeating: 255, count: 32)))
  }

  func testStorageCallbacksActivityAndReopen() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let paths = try StoragePaths.fromRoot(root: root.path)
    defer { paths.close() }
    let host = MemoryStorage()
    let store = try CredentialStore.newWithComponents(paths: paths, keystore: host, blobStore: host)
    defer { store.close() }
    try store.initialize(leafIndex: 42, now: 100)
    let changed = expectation(description: "activity callback")
    try store.setActivityChangedListener(listener: ActivityListener { changed.fulfill() })
    let entry = ActivityEntry(
      id: nil, rpId: UInt64.max, appIdentifier: "test", clientId: "request", protocol: .v4,
      timestamp: 100, outcome: .completed, issuerSchemaIds: [UInt64.max], failureReason: nil)
    let id = try store.recordActivity(entry: entry, now: 100)
    wait(for: [changed], timeout: 5)
    let activities = try store.listActivities(query: ActivityQuery(), limit: 10, offset: 0)
    XCTAssertEqual(activities.count, 1)
    XCTAssertEqual(activities.first?.id, id)
    XCTAssertEqual(activities.first?.rpId, UInt64.max)
    XCTAssertEqual(try store.activityMetadata().totalCount, 1)
    XCTAssertEqual(
      try store.listActivities(
        query: ActivityQuery().withIssuerSchemaId(issuerSchemaId: UInt64.max), limit: 10, offset: 0
      ).count, 1)
    XCTAssertTrue(
      try store.listActivities(query: ActivityQuery(issuerSchemaId: 1), limit: 10, offset: 0)
        .isEmpty)
    store.close()
    XCTAssertThrowsError(try store.activityMetadata())
    let reopened = try CredentialStore.newWithComponents(
      paths: paths, keystore: host, blobStore: host)
    defer { reopened.close() }
    try reopened.initialize(leafIndex: 42, now: 101)
    XCTAssertEqual(try reopened.activityMetadata().totalCount, 1)
  }

  func testHostFailureIsTypedAndDoesNotExposeHostMessage() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let paths = try StoragePaths.fromRoot(root: root.path)
    defer { paths.close() }
    let store = try CredentialStore.newWithComponents(
      paths: paths, keystore: FailingKeystore(), blobStore: MemoryStorage())
    defer { store.close() }
    XCTAssertThrowsError(try store.initialize(leafIndex: 42, now: 100)) { error in
      XCTAssertTrue(error is StorageError)
      XCTAssertFalse(String(describing: error).contains("private-host-message"))
    }
  }

  func testClosedAndStaleHandlesAreRejected() throws {
    let field = try FieldElement.fromU64(value: 42)
    field.close()
    field.close()
    XCTAssertThrowsError(try field.toHexString()) { error in
      XCTAssertEqual((error as? WalletKitBridgeError)?.code, "Closed")
    }
    let stale = FieldElement(handle: NativeHandle(UInt64.max))
    XCTAssertThrowsError(try stale.toHexString()) { error in
      XCTAssertEqual((error as? WalletKitBridgeError)?.code, "InvalidHandle")
    }
  }

  func testLegacyIntegerAndEnumBindings() throws {
    let expected = try Uint256(hex: "2a")
    let context = try ProofContext.newFromSignalHash(
      appId: "app_test", action: nil, credentialType: .orb, signalHash: expected)
    defer { context.close() }
    XCTAssertEqual(try context.getSignalHash().bytes, expected.bytes)
    guard case .orb = try context.getCredentialType() else {
      return XCTFail("incorrect enum variant")
    }
    XCTAssertEqual(try context.getExternalNullifier().bytes.count, 32)
  }

  func testMeasurementMapFailureRetainsDomainError() throws {
    let matcher = try FlamingoMatcher.create(hostUrl: "https://example.invalid")
    defer { matcher.close() }
    XCTAssertThrowsError(try matcher.withMeasurements(measurements: [0: Data([1])])) { error in
      guard case FlamingoError.configuration = error else {
        return XCTFail("incorrect domain error")
      }
    }
  }

  func testAsyncFailuresKeepTheirDomainType() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let paths = try StoragePaths.fromRoot(root: root.path)
    let host = MemoryStorage()
    let store = try CredentialStore.newWithComponents(paths: paths, keystore: host, blobStore: host)
    let artifacts = try EmbeddedZkArtifacts.create().asZkArtifactSource()
    do {
      _ = try await Authenticator.initialize(
        seed: Data(repeating: 7, count: 32), config: "not json", artifacts: artifacts, store: store)
      XCTFail("invalid configuration accepted")
    } catch WalletKitError.invalidInput(let attribute, _) {
      XCTAssertEqual(attribute, "config")
    }
  }

  func testCancellationBeforeStartingDoesNotReturnNativeResource() async throws {
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return try await NativeBridge.async { _ in try FieldElement.fromU64(value: 42) }
    }
    do {
      _ = try await task.value
      XCTFail("cancelled call returned a resource")
    } catch is CancellationError {
      // The result is released when the task reports cancellation.
    }
  }
}
