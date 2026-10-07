import Foundation
internal import walletkit_coreFFI

/// A Rust-owned CredentialStore resource. Closing rejects new calls; running calls retain their inputs.
public final class CredentialStore: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension CredentialStore {
  public static func newWithComponents(
    paths: StoragePaths, keystore: any DeviceKeystore, blobStore: any AtomicBlobStore
  ) throws -> CredentialStore {
    try paths.handle.withID { pathsID in
      CredentialStore(
        handle: NativeHandle(
          try call(WalletKitCredentialStoreHandle(id: 0)) {
            walletkit_credential_store_new_with_components(
              WalletKitStoragePathsHandle(id: pathsID), keystoreCallbacks(keystore),
              blobStoreCallbacks(blobStore), $0, $1)
          }.id))
    }
  }
  public func storagePaths() throws -> StoragePaths {
    try handle.withID { storeID in
      StoragePaths(
        handle: NativeHandle(
          try call(WalletKitStoragePathsHandle(id: 0)) {
            walletkit_credential_store_storage_paths(
              WalletKitCredentialStoreHandle(id: storeID), $0, $1)
          }.id))
    }
  }
  public func initialize(leafIndex: UInt64, now: UInt64) throws {
    try handle.withID { storeID in
      try callUnit {
        walletkit_credential_store_initialize(
          WalletKitCredentialStoreHandle(id: storeID), leafIndex, now, $0)
      }
    }
  }
  public func listCredentials(issuerSchemaId: UInt64?, now: UInt64) throws -> [CredentialRecord] {
    try handle.withID { storeID in
      try withOptional(issuerSchemaId) { issuerSchemaIdPointer in
        try ByteReader.decode(
          try callData {
            walletkit_credential_store_list_credentials(
              WalletKitCredentialStoreHandle(id: storeID), issuerSchemaIdPointer, now, $0, $1)
          } ?? Data()
        ) { try $0.list(CredentialRecord.read) }
      }
    }
  }
  public func fetchCredential(issuerSchemaId: UInt64, now: UInt64) throws -> Credential? {
    try handle.withID { storeID in
      NativeHandle.owning(
        try call(WalletKitCredentialHandle(id: 0)) {
          walletkit_credential_store_fetch_credential(
            WalletKitCredentialStoreHandle(id: storeID), issuerSchemaId, now, $0, $1)
        }.id
      ).map { Credential(handle: $0) }
    }
  }
  public func deleteCredential(credentialId: UInt64) throws {
    try handle.withID { storeID in
      try callUnit {
        walletkit_credential_store_delete_credential(
          WalletKitCredentialStoreHandle(id: storeID), credentialId, $0)
      }
    }
  }
  public func storeCredential(
    credential: Credential, blindingFactor: FieldElement, expiresAt: UInt64, associatedData: Data?,
    now: UInt64
  ) throws -> UInt64 {
    try handle.withID { storeID in
      try credential.handle.withID { credentialID in
        try blindingFactor.handle.withID { blindingFactorID in
          try withOptionalByteSlice(associatedData) { associatedDataSlice in
            try call(UInt64(0)) {
              walletkit_credential_store_store_credential(
                WalletKitCredentialStoreHandle(id: storeID),
                WalletKitCredentialHandle(id: credentialID),
                WalletKitFieldElementHandle(id: blindingFactorID), expiresAt, associatedDataSlice,
                now, $0, $1)
            }
          }
        }
      }
    }
  }
  /// Permanently deletes all stored credentials. Require an explicit user recovery/reset decision before calling.
  public func dangerDeleteAllCredentials() throws -> UInt64 {
    try handle.withID { storeID in
      try call(UInt64(0)) {
        walletkit_credential_store_danger_delete_all_credentials(
          WalletKitCredentialStoreHandle(id: storeID), $0, $1)
      }
    }
  }
  public func recordActivity(entry: ActivityEntry, now: UInt64) throws -> UInt64 {
    try handle.withID { storeID in
      try withByteSlice(ByteWriter.encode { entry.write(&$0) }) { entrySlice in
        try call(UInt64(0)) {
          walletkit_credential_store_record_activity(
            WalletKitCredentialStoreHandle(id: storeID), entrySlice, now, $0, $1)
        }
      }
    }
  }
  public func listActivities(query: ActivityQuery, limit: UInt32, offset: UInt32) throws
    -> [ActivityEntry]
  {
    try handle.withID { storeID in
      try withOptional(query.issuerSchemaId) { issuerSchemaId in
        try ByteReader.decode(
          try callData {
            walletkit_credential_store_list_activities(
              WalletKitCredentialStoreHandle(id: storeID), issuerSchemaId, limit, offset, $0, $1)
          } ?? Data()
        ) { try $0.list(ActivityEntry.read) }
      }
    }
  }
  public func activityMetadata() throws -> ActivityMetadata {
    try handle.withID { storeID in
      ActivityMetadata(
        totalCount: try call(UInt64(0)) {
          walletkit_credential_store_activity_metadata(
            WalletKitCredentialStoreHandle(id: storeID), $0, $1)
        })
    }
  }
  public func clearActivities() throws -> UInt64 {
    try handle.withID { storeID in
      try call(UInt64(0)) {
        walletkit_credential_store_clear_activities(
          WalletKitCredentialStoreHandle(id: storeID), $0, $1)
      }
    }
  }
  /// Deletes the key envelope, vault, and cache. The store becomes uninitialized. Use only for logout or account deletion.
  public func destroyStorage() throws {
    try handle.withID { storeID in
      try callUnit {
        walletkit_credential_store_destroy_storage(WalletKitCredentialStoreHandle(id: storeID), $0)
      }
    }
  }
  /// Exports the vault for backup. The host owns secure persistence/upload of the returned bytes; never log the payload.
  public func exportVaultForBackup() throws -> Data {
    try handle.withID { storeID in
      try callData {
        walletkit_credential_store_export_vault_for_backup(
          WalletKitCredentialStoreHandle(id: storeID), $0, $1)
      } ?? Data()
    }
  }
  public func importVaultFromBackup(backupBytes: Data) throws {
    try handle.withID { storeID in
      try withByteSlice(backupBytes) { backupBytesSlice in
        try callUnit {
          walletkit_credential_store_import_vault_from_backup(
            WalletKitCredentialStoreHandle(id: storeID), backupBytesSlice, $0)
        }
      }
    }
  }
  public func mergeVaultFromBackup(backupBytes: Data) throws -> UInt64 {
    try handle.withID { storeID in
      try withByteSlice(backupBytes) { backupBytesSlice in
        try call(UInt64(0)) {
          walletkit_credential_store_merge_vault_from_backup(
            WalletKitCredentialStoreHandle(id: storeID), backupBytesSlice, $0, $1)
        }
      }
    }
  }
  public func setVaultChangedListener(listener: any VaultChangedListener) throws {
    try handle.withID { storeID in
      try callUnit {
        walletkit_credential_store_set_vault_changed_listener(
          WalletKitCredentialStoreHandle(id: storeID), vaultListenerCallbacks(listener), $0)
      }
    }
  }
  public func setActivityChangedListener(listener: any ActivityChangedListener) throws {
    try handle.withID { storeID in
      try callUnit {
        walletkit_credential_store_set_activity_changed_listener(
          WalletKitCredentialStoreHandle(id: storeID), activityListenerCallbacks(listener), $0)
      }
    }
  }
}
