import Foundation
internal import walletkit_coreFFI

/// A Rust-owned FlamingoMatcher resource. Closing rejects new calls; running calls retain their inputs.
public final class FlamingoMatcher: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension FlamingoMatcher {
  public static func create(hostUrl: String) throws -> FlamingoMatcher {
    try withByteSlice(hostUrl) { hostUrlSlice in
      FlamingoMatcher(
        handle: NativeHandle(
          try call(WalletKitFlamingoMatcherHandle(id: 0)) {
            walletkit_flamingo_matcher_new(hostUrlSlice, $0, $1)
          }.id))
    }
  }
  public static func newAttested(hostUrl: String, integrityProvider: any RequestIntegrityProvider)
    throws -> FlamingoMatcher
  {
    try withByteSlice(hostUrl) { hostUrlSlice in
      FlamingoMatcher(
        handle: NativeHandle(
          try call(WalletKitFlamingoMatcherHandle(id: 0)) {
            walletkit_flamingo_matcher_new_attested(
              hostUrlSlice, integrityProviderCallbacks(integrityProvider), $0, $1)
          }.id))
    }
  }
  public func withMeasurements(measurements: [UInt32: Data]) throws -> FlamingoMatcher {
    try handle.withID { matcherID in
      try withByteSlice(ByteWriter.encode { writeMeasurements(measurements, &$0) }) {
        measurementsSlice in
        FlamingoMatcher(
          handle: NativeHandle(
            try call(WalletKitFlamingoMatcherHandle(id: 0)) {
              walletkit_flamingo_matcher_with_measurements(
                WalletKitFlamingoMatcherHandle(id: matcherID), measurementsSlice, $0, $1)
            }.id))
      }
    }
  }
  /// Disables enclave measurement pins, accepting any otherwise valid attested code, including debug enclaves. Development only; never use in production.
  public func dangerouslySkipMeasurements() throws -> FlamingoMatcher {
    try handle.withID { matcherID in
      FlamingoMatcher(
        handle: NativeHandle(
          try call(WalletKitFlamingoMatcherHandle(id: 0)) {
            walletkit_flamingo_matcher_dangerously_skip_measurements(
              WalletKitFlamingoMatcherHandle(id: matcherID), $0, $1)
          }.id))
    }
  }
  public func withHeaders(headers: [String: String]) throws -> FlamingoMatcher {
    try handle.withID { matcherID in
      try withByteSlice(ByteWriter.encode { writeStringMap(headers, &$0) }) { headersSlice in
        FlamingoMatcher(
          handle: NativeHandle(
            try call(WalletKitFlamingoMatcherHandle(id: 0)) {
              walletkit_flamingo_matcher_with_headers(
                WalletKitFlamingoMatcherHandle(id: matcherID), headersSlice, $0, $1)
            }.id))
      }
    }
  }
  public func performMatch(request: FlamingoMatchRequest) async throws -> FlamingoMatchOutcome {
    try await NativeBridge.async { operation in
      try self.handle.withID { matcherID in
        try withByteSlice(ByteWriter.encode { request.write(&$0) }) { requestSlice in
          try ByteReader.decode(
            try callData {
              walletkit_flamingo_matcher_perform_match(
                operation, WalletKitFlamingoMatcherHandle(id: matcherID), requestSlice, $0, $1)
            } ?? Data()
          ) { try FlamingoMatchOutcome.read(&$0) }
        }
      }
    }
  }
}
