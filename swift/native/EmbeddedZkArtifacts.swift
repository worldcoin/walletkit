import Foundation
internal import walletkit_coreFFI

/// A Rust-owned EmbeddedZkArtifacts resource. Closing rejects new calls; running calls retain their inputs.
public final class EmbeddedZkArtifacts: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension EmbeddedZkArtifacts {
  public static func create() throws -> EmbeddedZkArtifacts {
    EmbeddedZkArtifacts(
      handle: NativeHandle(
        try call(WalletKitEmbeddedZkArtifactsHandle(id: 0)) {
          walletkit_embedded_zk_artifacts_new($0, $1)
        }.id))
  }
  public func asZkArtifactSource() throws -> WalletKitZkArtifactSource {
    try handle.withID { artifactsID in
      WalletKitZkArtifactSource(
        handle: NativeHandle(
          try call(WalletKitZkArtifactSourceHandle(id: 0)) {
            walletkit_embedded_zk_artifacts_as_zk_artifact_source(
              WalletKitEmbeddedZkArtifactsHandle(id: artifactsID), $0, $1)
          }.id))
    }
  }
}
