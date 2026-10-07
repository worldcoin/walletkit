import Foundation
internal import walletkit_coreFFI

/// A Rust-owned CachingZkArtifacts resource. Closing rejects new calls; running calls retain their inputs.
public final class CachingZkArtifacts: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension CachingZkArtifacts {
  public static func create(storagePaths: StoragePaths) throws -> CachingZkArtifacts {
    try storagePaths.handle.withID { storagePathsID in
      CachingZkArtifacts(
        handle: NativeHandle(
          try call(WalletKitCachingZkArtifactsHandle(id: 0)) {
            walletkit_caching_zk_artifacts_new(
              WalletKitStoragePathsHandle(id: storagePathsID), $0, $1)
          }.id))
    }
  }
  public func asZkArtifactSource() throws -> WalletKitZkArtifactSource {
    try handle.withID { artifactsID in
      WalletKitZkArtifactSource(
        handle: NativeHandle(
          try call(WalletKitZkArtifactSourceHandle(id: 0)) {
            walletkit_caching_zk_artifacts_as_zk_artifact_source(
              WalletKitCachingZkArtifactsHandle(id: artifactsID), $0, $1)
          }.id))
    }
  }
  public func preload() throws {
    try handle.withID { artifactsID in
      try callUnit {
        walletkit_caching_zk_artifacts_preload(
          WalletKitCachingZkArtifactsHandle(id: artifactsID), $0)
      }
    }
  }
}
