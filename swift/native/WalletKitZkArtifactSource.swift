import Foundation
internal import walletkit_coreFFI

/// A Rust-owned WalletKitZkArtifactSource resource. Closing rejects new calls; running calls retain their inputs.
public final class WalletKitZkArtifactSource: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}
