import Foundation
import XCTest

@testable import WalletKit

private final class Storage: DeviceKeystore, AtomicBlobStore, @unchecked Sendable {
  private let lock = NSLock()
  private var blobs: [String: Data] = [:]
  private let sealFailure: (any Error)?
  init(sealFailure: (any Error)? = nil) { self.sealFailure = sealFailure }
  func seal(associatedData: Data, plaintext: Data) throws -> Data {
    if let sealFailure { throw sealFailure }
    return associatedData + plaintext
  }
  func openSealed(associatedData: Data, ciphertext: Data) throws -> Data {
    ciphertext.dropFirst(associatedData.count)
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

private final class Recorder: Logger, ActivityChangedListener, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var messages: [(LogLevel, String)] = []
  let logged = DispatchSemaphore(value: 0)
  let activity = DispatchSemaphore(value: 0)
  func log(level: LogLevel, message: String) {
    lock.lock()
    messages.append((level, message))
    lock.unlock()
    if message.contains("typed-logger-check") { logged.signal() }
  }
  func onActivityChanged() { activity.signal() }
}

private final class Provider: RequestIntegrityProvider, RequestDigestSigner, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var digests: [Data] = []
  private let failure: RequestIntegrityError?
  init(failure: RequestIntegrityError? = nil) { self.failure = failure }
  func prepare() async throws -> RequestIntegritySession {
    try await Task.sleep(nanoseconds: 10_000_000)
    if let failure { throw failure }
    return RequestIntegritySession(token: "integrity-token", platform: .ios, signer: self)
  }
  func signDigest(clientDataHash: Data) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    digests.append(clientDataHash)
    return clientDataHash
  }
}

final class CallbackTests: XCTestCase {
  private func withStore(
    _ host: Storage = Storage(), _ body: (CredentialStore) throws -> Void
  ) throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let paths = try StoragePaths.fromRoot(root: root.path)
    defer { paths.close() }
    let store = try CredentialStore.newWithComponents(paths: paths, keystore: host, blobStore: host)
    defer { store.close() }
    try body(store)
  }

  func testActivityRecordsRoundTripThroughBinaryEncoding() throws {
    try withStore { store in
      try store.initialize(leafIndex: 42, now: 100)
      let entries = [
        ActivityEntry(
          id: nil, rpId: UInt64.max, appIdentifier: "zażółć 🚀", clientId: "", protocol: .v3,
          timestamp: nil, outcome: .failed, issuerSchemaIds: [UInt64.max, 0],
          failureReason: .relyingPartyRejected),
        ActivityEntry(
          id: nil, rpId: 1, appIdentifier: "app", clientId: "request", protocol: .v4,
          timestamp: 100, outcome: .incomplete, issuerSchemaIds: [], failureReason: nil)
      ]
      let ids = try entries.map { try store.recordActivity(entry: $0, now: 100) }
      let listed = try store.listActivities(query: ActivityQuery(), limit: 10, offset: 0)
      XCTAssertEqual(Set(listed.compactMap(\.id)), Set(ids))
      let unicode = try XCTUnwrap(listed.first { $0.rpId == UInt64.max })
      XCTAssertEqual(unicode.appIdentifier, "zażółć 🚀")
      XCTAssertEqual(unicode.issuerSchemaIds.sorted(), [0, UInt64.max])
      XCTAssertEqual(unicode.failureReason, .relyingPartyRejected)
      XCTAssertEqual(unicode.timestamp, 100)
      XCTAssertEqual(
        try store.listActivities(query: ActivityQuery(issuerSchemaId: 0), limit: 10, offset: 0)
          .count, 1)
      XCTAssertEqual(try store.clearActivities(), 2)
    }
  }

  func testHostStorageErrorKeepsItsVariant() throws {
    try withStore(Storage(sealFailure: StorageError.keystore(value0: "denied"))) { store in
      XCTAssertThrowsError(try store.initialize(leafIndex: 42, now: 100)) { error in
        guard case StorageError.keystore = error else {
          return XCTFail("unexpected error \(error)")
        }
      }
    }
  }

  func testLoggerAndListenersRunOnNativeThreads() throws {
    let recorder = Recorder()
    try initLogging(logger: recorder, level: .trace)
    try emitLog(level: .warn, message: "typed-logger-check")
    XCTAssertEqual(recorder.logged.wait(timeout: .now() + 5), .success)
    XCTAssertTrue(recorder.messages.contains { $0.0 == .warn && $0.1.contains("typed-logger-check") })
    try withStore { store in
      try store.initialize(leafIndex: 42, now: 100)
      try store.setActivityChangedListener(listener: recorder)
      _ = try store.recordActivity(
        entry: ActivityEntry(
          id: nil, rpId: 1, appIdentifier: "app", clientId: "id", protocol: .v4, timestamp: 1,
          outcome: .completed, issuerSchemaIds: [], failureReason: nil), now: 100)
      XCTAssertEqual(recorder.activity.wait(timeout: .now() + 5), .success)
    }
  }

  private let request = FlamingoMatchRequest.grayBadge(
    live: .vanilla(image: Data([1, 2, 3])), rtmsChallenge: Data([4]), matchThreshold: 0.5)

  func testAttestedMatchingSignsWithTheHostProvider() async throws {
    let provider = Provider()
    let matcher = try FlamingoMatcher.newAttested(
      hostUrl: "https://127.0.0.1:9", integrityProvider: provider
    ).dangerouslySkipMeasurements()
    do {
      _ = try await matcher.performMatch(request: request)
      XCTFail("unreachable verifier matched")
    } catch is FlamingoError {}
    XCTAssertEqual(provider.digests.map(\.count), [32])
  }

  func testIntegrityProviderFailuresKeepTheirType() async throws {
    let matcher = try FlamingoMatcher.newAttested(
      hostUrl: "https://127.0.0.1:9", integrityProvider: Provider(failure: .unavailable)
    ).dangerouslySkipMeasurements()
    do {
      _ = try await matcher.performMatch(request: request)
      XCTFail("failed provider matched")
    } catch FlamingoError.requestIntegrity(.unavailable) {}
    XCTAssertThrowsError(
      try FlamingoMatcher.newAttested(hostUrl: "http://127.0.0.1:9", integrityProvider: Provider())
    ) { error in
      guard case FlamingoError.configuration = error else {
        return XCTFail("unexpected error \(error)")
      }
    }
  }
}
