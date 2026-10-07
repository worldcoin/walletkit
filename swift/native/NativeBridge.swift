import Foundation
internal import walletkit_coreFFI

public struct WalletKitBridgeError: Error, Sendable, CustomStringConvertible {
  public let code: String
  public var description: String { "WalletKitBridge.\(code)" }
}

/// An unsigned 256-bit value, stored as exactly 32 big-endian bytes.
public struct Uint256: Sendable, Equatable, Hashable {
  public let bytes: Data
  public init(bytes: Data) throws {
    guard bytes.count == 32 else { throw WalletKitBridgeError(code: "InvalidInteger") }
    self.bytes = bytes
  }
  public init(hex: String) throws {
    let digits = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
    guard !digits.isEmpty, digits.count <= 64, digits.allSatisfy({ $0.isASCII && $0.isHexDigit })
    else {
      throw WalletKitBridgeError(code: "InvalidInteger")
    }
    let padded = String(repeating: "0", count: 64 - digits.count) + digits
    var bytes = Data()
    var index = padded.startIndex
    while index < padded.endIndex {
      let end = padded.index(index, offsetBy: 2)
      guard let byte = UInt8(padded[index..<end], radix: 16) else {
        throw WalletKitBridgeError(code: "InvalidInteger")
      }
      bytes.append(byte)
      index = end
    }
    self.bytes = bytes
  }
  public var hex: String { "0x" + bytes.map { String(format: "%02x", $0) }.joined() }

  init(native: WalletKitUint256) {
    bytes = withUnsafeBytes(of: native.bytes) { Data($0) }
  }
  var native: WalletKitUint256 {
    var native = WalletKitUint256()
    withUnsafeMutableBytes(of: &native.bytes) { _ = bytes.copyBytes(to: $0) }
    return native
  }
}

/// The sole owning reference to a Rust resource. Rust retains in-flight uses independently.
final class NativeHandle: @unchecked Sendable {
  private let lock = NSLock()
  private var id: UInt64
  init(_ id: UInt64) { self.id = id }
  /// Takes ownership of an optional result handle, where zero means absent.
  static func owning(_ id: UInt64) -> NativeHandle? { id == 0 ? nil : NativeHandle(id) }
  deinit { close() }
  func close() {
    lock.lock()
    let owned = id
    id = 0
    lock.unlock()
    if owned != 0 { walletkit_object_release(owned) }
  }
  /// Runs `body` with the live ID, keeping this handle alive until it returns.
  func withID<T>(_ body: (UInt64) throws -> T) throws -> T {
    try withExtendedLifetime(self) { try body(try liveID()) }
  }
  private func liveID() throws -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    guard id != 0 else { throw WalletKitBridgeError(code: "Closed") }
    return id
  }
}

private let abiVersion: UInt32 = 2

private let compatible = walletkit_abi_version() == abiVersion

/// Calls a fallible C function that writes its result to `out`.
func call<T>(
  _ initial: T, _ body: (UnsafeMutablePointer<T>, UnsafeMutablePointer<WalletKitBuffer>) -> Bool
) throws -> T {
  guard compatible else { throw WalletKitBridgeError(code: "IncompatibleVersion") }
  var value = initial
  var error = WalletKitBuffer(data: nil, len: 0)
  if body(&value, &error) { return value }
  throw try decodeNativeError(take(error) ?? Data())
}

/// Calls a fallible C function without a result.
func callUnit(_ body: (UnsafeMutablePointer<WalletKitBuffer>) -> Bool) throws {
  _ = try call(UInt8(0)) { _, error in body(error) }
}

/// Calls a C function that returns an owned buffer.
func callData(
  _ body: (UnsafeMutablePointer<WalletKitBuffer>, UnsafeMutablePointer<WalletKitBuffer>) -> Bool
) throws -> Data? {
  take(try call(WalletKitBuffer(data: nil, len: 0), body))
}

func callString(
  _ body: (UnsafeMutablePointer<WalletKitBuffer>, UnsafeMutablePointer<WalletKitBuffer>) -> Bool
) throws -> String {
  String(decoding: try callData(body) ?? Data(), as: UTF8.self)
}

func callOptionalString(
  _ body: (UnsafeMutablePointer<WalletKitBuffer>, UnsafeMutablePointer<WalletKitBuffer>) -> Bool
) throws -> String? {
  try callData(body).map { String(decoding: $0, as: UTF8.self) }
}

/// Takes ownership of a Rust buffer; a null buffer is an absent value.
func take(_ buffer: WalletKitBuffer) -> Data? {
  defer { walletkit_buffer_free(buffer) }
  guard let data = buffer.data else { return nil }
  return Data(bytes: data, count: buffer.len)
}

func withByteSlice<T>(_ data: Data, _ body: (WalletKitByteSlice) throws -> T) rethrows -> T {
  try data.withUnsafeBytes { bytes in
    try body(
      WalletKitByteSlice(data: bytes.bindMemory(to: UInt8.self).baseAddress, len: bytes.count))
  }
}

func withByteSlice<T>(_ string: String, _ body: (WalletKitByteSlice) throws -> T) rethrows -> T {
  var string = string
  return try string.withUTF8 { bytes in
    try body(WalletKitByteSlice(data: bytes.baseAddress, len: bytes.count))
  }
}

func withOptionalByteSlice<T>(
  _ data: Data?, _ body: (UnsafePointer<WalletKitByteSlice>?) throws -> T
) rethrows -> T {
  guard let data else { return try body(nil) }
  return try withByteSlice(data) { slice in try withUnsafePointer(to: slice) { try body($0) } }
}

func withOptionalByteSlice<T>(
  _ string: String?, _ body: (UnsafePointer<WalletKitByteSlice>?) throws -> T
) rethrows -> T {
  guard let string else { return try body(nil) }
  return try withByteSlice(string) { slice in try withUnsafePointer(to: slice) { try body($0) } }
}

func withOptional<T>(_ value: UInt64?, _ body: (UnsafePointer<UInt64>?) throws -> T) rethrows
  -> T
{
  guard let value else { return try body(nil) }
  return try withUnsafePointer(to: value) { try body($0) }
}

/// Runs blocking native calls for `async` methods on four workers with 128 pending calls;
/// further calls fail with `Busy`. Cancelling the task cancels the native operation, which
/// stops at its next yield point; the task reports cancellation once the call has returned.
enum NativeBridge {
  private static let queue: OperationQueue = {
    let queue = OperationQueue()
    queue.name = "org.world.walletkit.native"
    queue.maxConcurrentOperationCount = 4
    queue.qualityOfService = .userInitiated
    return queue
  }()
  private static let admission = Admission()

  static func async<T: Sendable>(
    _ body: @escaping @Sendable (WalletKitOperationHandle) throws -> T
  ) async throws -> T {
    try admission.enter()
    let operation: WalletKitOperationHandle
    do {
      operation = try call(WalletKitOperationHandle(id: 0)) { walletkit_operation_new($0, $1) }
    } catch {
      admission.leave()
      throw error
    }
    return try await withTaskCancellationHandler {
      let result: T = try await withCheckedThrowingContinuation { continuation in
        queue.addOperation {
          defer {
            walletkit_object_release(operation.id)
            admission.leave()
          }
          continuation.resume(with: Result { try body(operation) })
        }
      }
      try Task.checkCancellation()
      return result
    } onCancel: {
      walletkit_operation_cancel(operation)
    }
  }
}

private final class Admission: @unchecked Sendable {
  private let lock = NSLock()
  private var pending = 0
  func enter() throws {
    lock.lock()
    defer { lock.unlock() }
    guard pending < 128 else { throw WalletKitBridgeError(code: "Busy") }
    pending += 1
  }
  func leave() {
    lock.lock()
    defer { lock.unlock() }
    pending -= 1
  }
}
