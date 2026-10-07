import Foundation
internal import walletkit_coreFFI

/// A Rust-owned StoragePaths resource. Closing rejects new calls; running calls retain their inputs.
public final class StoragePaths: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension StoragePaths {
  public static func fromRoot(root: String) throws -> StoragePaths {
    try withByteSlice(root) { rootSlice in
      StoragePaths(
        handle: NativeHandle(
          try call(WalletKitStoragePathsHandle(id: 0)) {
            walletkit_storage_paths_from_root(rootSlice, $0, $1)
          }.id))
    }
  }
  public func rootPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_root_path_string(WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func worldidDirPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_worldid_dir_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func vaultDbPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_vault_db_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func cacheDbPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_cache_db_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func lockPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_lock_path_string(WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func groth16DirPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_groth16_dir_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func queryZkeyPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_query_zkey_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func nullifierZkeyPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_nullifier_zkey_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func queryGraphPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_query_graph_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
  public func nullifierGraphPathString() throws -> String {
    try handle.withID { pathsID in
      try callString {
        walletkit_storage_paths_nullifier_graph_path_string(
          WalletKitStoragePathsHandle(id: pathsID), $0, $1)
      }
    }
  }
}
