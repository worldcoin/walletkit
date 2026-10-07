import Foundation
internal import walletkit_coreFFI

/// A Rust-owned VerifiedMatchToken resource. Closing rejects new calls; running calls retain their inputs.
public final class VerifiedMatchToken: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension VerifiedMatchToken {
  public func matchCoefficient() throws -> Float {
    try handle.withID { tokenID in
      try call(Float(0)) {
        walletkit_verified_match_token_match_coefficient(
          WalletKitVerifiedMatchTokenHandle(id: tokenID), $0, $1)
      }
    }
  }
}
