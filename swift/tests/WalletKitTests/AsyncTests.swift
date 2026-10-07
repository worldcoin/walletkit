import Foundation
import XCTest

@testable import WalletKit

#if canImport(Glibc)
  import Glibc
  private let streamSocket = Int32(SOCK_STREAM.rawValue)
#else
  import Darwin
  private let streamSocket = SOCK_STREAM
#endif

/// A loopback TCP server that accepts requests and never answers, so native calls stay in flight.
private final class SilentServer: @unchecked Sendable {
  let accepted = DispatchSemaphore(value: 0)
  let closedByClient = DispatchSemaphore(value: 0)
  private let listener: Int32
  let url: String

  init() throws {
    let descriptor = socket(AF_INET, streamSocket, 0)
    var address = sockaddr_in()
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        bind(descriptor, $0, length) == 0 && listen(descriptor, 512) == 0 && getsockname(descriptor, $0, &length) == 0
      }
    }
    guard bound else { throw WalletKitBridgeError(code: "TestServerUnavailable") }
    listener = descriptor
    url = "https://127.0.0.1:\(UInt16(bigEndian: address.sin_port))"
    let accepted = accepted
    let closedByClient = closedByClient
    Thread.detachNewThread {
      while true {
        let client = accept(descriptor, nil, nil)
        guard client >= 0 else { return }
        accepted.signal()
        Thread.detachNewThread {
          var byte: UInt8 = 0
          while read(client, &byte, 1) > 0 {}
          close(client)
          closedByClient.signal()
        }
      }
    }
  }

  deinit { shutdown(listener, Int32(SHUT_RDWR)) }
}

/// Waits off the cooperative pool for `count` signals.
private func signaled(_ semaphore: DispatchSemaphore, count: Int = 1) async -> Bool {
  await withCheckedContinuation { continuation in
    DispatchQueue.global().async {
      continuation.resume(
        returning: (0..<count).allSatisfy { _ in semaphore.wait(timeout: .now() + 10) == .success })
    }
  }
}

final class AsyncTests: XCTestCase {
  private func manager(_ server: SilentServer) throws -> RecoveryBindingManager {
    try RecoveryBindingManager.newWithBaseUrl(
      baseUrl: server.url, userAgentBuilder: try UserAgentBuilder.create())
  }

  func testCancellationStopsTheNativeCallInFlight() async throws {
    let server = try SilentServer()
    let manager = try manager(server)
    let call = Task { try await manager.getRecoveryBinding(leafIndex: 42) }
    let reached = await signaled(server.accepted)
    XCTAssertTrue(reached, "request reached the server")
    call.cancel()
    do {
      _ = try await call.value
      XCTFail("cancelled call returned")
    } catch is CancellationError {}
    let dropped = await signaled(server.closedByClient)
    XCTAssertTrue(dropped, "native future dropped its connection")
  }

  func testAdmissionRejectsCallsBeyondThePendingLimit() async throws {
    let server = try SilentServer()
    let manager = try manager(server)
    let calls = (0..<128).map { index in
      Task { try await manager.getRecoveryBinding(leafIndex: UInt64(index)) }
    }
    let busyWorkers = await signaled(server.accepted, count: 4)
    XCTAssertTrue(busyWorkers, "all four workers busy")
    try await Task.sleep(nanoseconds: 500_000_000)
    do {
      _ = try await manager.getRecoveryBinding(leafIndex: 0)
      XCTFail("call beyond the limit was admitted")
    } catch let error as WalletKitBridgeError {
      XCTAssertEqual(error.code, "Busy")
    }
    calls.forEach { $0.cancel() }
    for call in calls {
      do {
        _ = try await call.value
        XCTFail("cancelled call returned")
      } catch is CancellationError {}
    }
    XCTAssertEqual(try FieldElement.fromU64(value: 1).toBytes().count, 32)
  }

  func testClosingAnInputDuringACallDoesNotFreeIt() async throws {
    let server = try SilentServer()
    let manager = try manager(server)
    let call = Task { try await manager.getRecoveryBinding(leafIndex: 7) }
    let reached = await signaled(server.accepted)
    XCTAssertTrue(reached)
    manager.close()
    do {
      _ = try await manager.getRecoveryBinding(leafIndex: 7)
      XCTFail("closed resource accepted a call")
    } catch let error as WalletKitBridgeError {
      XCTAssertEqual(error.code, "Closed")
    }
    call.cancel()
    do {
      _ = try await call.value
      XCTFail("cancelled call returned")
    } catch is CancellationError {}
  }
}
