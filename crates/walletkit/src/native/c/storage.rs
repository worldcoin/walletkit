//! C functions for storage paths, the credential store, and constraint checks.

use super::{
    callbacks, complete, complete_unit, optional_bytes, optional_u64, Buffer,
    ByteSlice, CredentialHandle, CredentialStoreHandle, FieldElementHandle, Handle,
    ProofRequestHandle, StoragePathsHandle,
};
use crate::native::ops;

/// `StoragePaths.fromRoot`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_from_root(
    root: ByteSlice,
    out: *mut StoragePathsHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_from_root(root.string()?))
        })
    }
}

/// `StoragePaths.rootPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_root_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_root_path_string(paths.get()?))
        })
    }
}

/// `StoragePaths.worldidDirPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_worldid_dir_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_worldid_dir_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `StoragePaths.vaultDbPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_vault_db_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_vault_db_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `StoragePaths.cacheDbPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_cache_db_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_cache_db_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `StoragePaths.lockPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_lock_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_lock_path_string(paths.get()?))
        })
    }
}

/// `StoragePaths.groth16DirPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_groth16_dir_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_groth16_dir_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `StoragePaths.queryZkeyPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_query_zkey_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_query_zkey_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `StoragePaths.nullifierZkeyPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_nullifier_zkey_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_nullifier_zkey_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `StoragePaths.queryGraphPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_query_graph_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_query_graph_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `StoragePaths.nullifierGraphPathString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_storage_paths_nullifier_graph_path_string(
    paths: StoragePathsHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::storage::storage_paths_nullifier_graph_path_string(
                paths.get()?,
            ))
        })
    }
}

/// `CredentialStore.newWithComponents`.
///
/// Consumes the callback tables, including on failure.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_new_with_components(
    paths: StoragePathsHandle,
    keystore: callbacks::DeviceKeystoreCallbacks,
    blob_store: callbacks::AtomicBlobStoreCallbacks,
    out: *mut CredentialStoreHandle,
    out_error: *mut Buffer,
) -> bool {
    let keystore = callbacks::keystore(keystore);
    let blob_store = callbacks::blob_store(blob_store);
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_new_with_components(
                paths.get()?,
                keystore,
                blob_store,
            )
        })
    }
}

/// `CredentialStore.storagePaths`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_storage_paths(
    store: CredentialStoreHandle,
    out: *mut StoragePathsHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_storage_paths(store.get()?)
        })
    }
}

/// `CredentialStore.initialize`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_initialize(
    store: CredentialStoreHandle,
    leaf_index: u64,
    now: u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::storage::credential_store_initialize(store.get()?, leaf_index, now)
        })
    }
}

/// `CredentialStore.listCredentials`.
///
/// Writes the binary encoding to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_list_credentials(
    store: CredentialStoreHandle,
    issuer_schema_id: *const u64,
    now: u64,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_list_credentials(
                store.get()?,
                optional_u64(issuer_schema_id),
                now,
            )
        })
    }
}

/// `CredentialStore.fetchCredential`.
///
/// Writes the handle to `out`, or a zero handle when absent.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_fetch_credential(
    store: CredentialStoreHandle,
    issuer_schema_id: u64,
    now: u64,
    out: *mut CredentialHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_fetch_credential(
                store.get()?,
                issuer_schema_id,
                now,
            )
        })
    }
}

/// `CredentialStore.deleteCredential`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_delete_credential(
    store: CredentialStoreHandle,
    credential_id: u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::storage::credential_store_delete_credential(
                store.get()?,
                credential_id,
            )
        })
    }
}

/// `CredentialStore.storeCredential`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_store_credential(
    store: CredentialStoreHandle,
    credential: CredentialHandle,
    blinding_factor: FieldElementHandle,
    expires_at: u64,
    associated_data: *const ByteSlice,
    now: u64,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_store_credential(
                store.get()?,
                credential.get()?,
                blinding_factor.get()?,
                expires_at,
                optional_bytes(associated_data)?,
                now,
            )
        })
    }
}

/// `CredentialStore.dangerDeleteAllCredentials`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_danger_delete_all_credentials(
    store: CredentialStoreHandle,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_danger_delete_all_credentials(store.get()?)
        })
    }
}

/// `CredentialStore.recordActivity`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_record_activity(
    store: CredentialStoreHandle,
    entry: ByteSlice,
    now: u64,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_record_activity(
                store.get()?,
                entry.decode()?,
                now,
            )
        })
    }
}

/// `CredentialStore.listActivities`.
///
/// Writes the binary encoding to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_list_activities(
    store: CredentialStoreHandle,
    issuer_schema_id: *const u64,
    limit: u32,
    offset: u32,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_list_activities(
                store.get()?,
                optional_u64(issuer_schema_id),
                limit,
                offset,
            )
        })
    }
}

/// `CredentialStore.activityMetadata`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_activity_metadata(
    store: CredentialStoreHandle,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_activity_metadata(store.get()?)
        })
    }
}

/// `CredentialStore.clearActivities`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_clear_activities(
    store: CredentialStoreHandle,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_clear_activities(store.get()?)
        })
    }
}

/// `CredentialStore.destroyStorage`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_destroy_storage(
    store: CredentialStoreHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::storage::credential_store_destroy_storage(store.get()?)
        })
    }
}

/// `CredentialStore.exportVaultForBackup`.
///
/// Writes the bytes to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_export_vault_for_backup(
    store: CredentialStoreHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_export_vault_for_backup(store.get()?)
        })
    }
}

/// `CredentialStore.importVaultFromBackup`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_import_vault_from_backup(
    store: CredentialStoreHandle,
    backup_bytes: ByteSlice,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::storage::credential_store_import_vault_from_backup(
                store.get()?,
                backup_bytes.to_vec()?,
            )
        })
    }
}

/// `CredentialStore.mergeVaultFromBackup`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_merge_vault_from_backup(
    store: CredentialStoreHandle,
    backup_bytes: ByteSlice,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::credential_store_merge_vault_from_backup(
                store.get()?,
                backup_bytes.to_vec()?,
            )
        })
    }
}

/// `CredentialStore.setVaultChangedListener`.
///
/// Consumes the callback tables, including on failure.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_set_vault_changed_listener(
    store: CredentialStoreHandle,
    listener: callbacks::VaultChangedListenerCallbacks,
    out_error: *mut Buffer,
) -> bool {
    let listener = callbacks::vault_listener(listener);
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::storage::credential_store_set_vault_changed_listener(
                store.get()?,
                listener,
            );
            Ok(())
        })
    }
}

/// `CredentialStore.setActivityChangedListener`.
///
/// Consumes the callback tables, including on failure.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_store_set_activity_changed_listener(
    store: CredentialStoreHandle,
    listener: callbacks::ActivityChangedListenerCallbacks,
    out_error: *mut Buffer,
) -> bool {
    let listener = callbacks::activity_listener(listener);
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::storage::credential_store_set_activity_changed_listener(
                store.get()?,
                listener,
            );
            Ok(())
        })
    }
}

/// `WalletKit.checkCredentialsAgainstProofRequest`.
///
/// Writes the binary encoding to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_check_credentials_against_proof_request(
    request: ProofRequestHandle,
    store: CredentialStoreHandle,
    now: u64,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::storage::check_credentials_against_proof_request(
                request.get()?,
                store.get()?,
                now,
            )
        })
    }
}
