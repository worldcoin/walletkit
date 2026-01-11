//! PendingActionStore persistence for device-protected storage.
//!
//! The pending action store tracks in-progress proof disclosures to ensure
//! nullifier single-use. It is encrypted with the device key and stored
//! in the account's blob store.

use crate::credential_storage::{
    platform::{AtomicBlobStore, DeviceKeystore},
    AccountId, PendingActionStore, StorageError, StorageResult,
};


/// Filename for the encrypted pending actions blob.
pub const PENDING_ACTIONS_FILENAME: &str = "pending_actions.bin";


/// Builds associated data for pending actions device encryption.
///
/// Format: `account_id || device_id || "worldid:pending-actions"`
fn build_pending_actions_aad(account_id: &AccountId, device_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 16 + 23);
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(b"worldid:pending-actions");
    aad
}

// Serialization

/// Serializes a `PendingActionStore` to bytes using bincode.
fn serialize_pending_actions(store: &PendingActionStore) -> StorageResult<Vec<u8>> {
    bincode::serialize(store).map_err(|e| StorageError::serialization(e.to_string()))
}

/// Deserializes a `PendingActionStore` from bytes using bincode.
fn deserialize_pending_actions(bytes: &[u8]) -> StorageResult<PendingActionStore> {
    bincode::deserialize(bytes).map_err(|e| StorageError::deserialization(e.to_string()))
}

// Load / Save

/// Loads the pending action store from device-protected storage.
///
/// # Arguments
///
/// * `blob_store` - The atomic blob store for the account
/// * `keystore` - Device keystore for decryption
/// * `account_id` - Account ID for AAD construction
/// * `device_id` - Device ID for AAD construction
///
/// # Returns
///
/// The pending action store. If the file doesn't exist, returns a new empty store.
///
/// # Errors
///
/// Returns an error if decryption or deserialization fails.
pub fn load_pending_actions(
    blob_store: &dyn AtomicBlobStore,
    keystore: &dyn DeviceKeystore,
    account_id: &AccountId,
    device_id: &[u8; 16],
) -> StorageResult<PendingActionStore> {
    // Read the encrypted blob
    let ciphertext = match blob_store.read(PENDING_ACTIONS_FILENAME)? {
        Some(data) => data,
        None => {
            // No existing store - return empty
            return Ok(PendingActionStore::new(*account_id));
        }
    };

    // Build associated data
    let aad = build_pending_actions_aad(account_id, device_id);

    // Decrypt
    let plaintext = keystore.open(&aad, &ciphertext)?;

    // Deserialize
    let store = deserialize_pending_actions(&plaintext)?;

    // Verify account ID matches
    if store.account_id != *account_id {
        return Err(StorageError::AccountIdMismatch {
            expected: *account_id,
            found: store.account_id,
        });
    }

    Ok(store)
}

/// Saves the pending action store to device-protected storage.
///
/// # Arguments
///
/// * `store` - The pending action store to save
/// * `blob_store` - The atomic blob store for the account
/// * `keystore` - Device keystore for encryption
/// * `device_id` - Device ID for AAD construction
///
/// # Errors
///
/// Returns an error if serialization or encryption fails.
pub fn save_pending_actions(
    store: &PendingActionStore,
    blob_store: &dyn AtomicBlobStore,
    keystore: &dyn DeviceKeystore,
    device_id: &[u8; 16],
) -> StorageResult<()> {
    // Serialize
    let plaintext = serialize_pending_actions(store)?;

    // Build associated data
    let aad = build_pending_actions_aad(&store.account_id, device_id);

    // Encrypt with device key
    let ciphertext = keystore.seal(&aad, &plaintext)?;

    // Write atomically
    blob_store.write_atomic(PENDING_ACTIONS_FILENAME, &ciphertext)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_storage::{
        platform::memory::{MemoryBlobStore, MemoryKeystore},
        PendingActionEntry, PENDING_TTL_SECONDS,
    };

    fn create_test_entry(scope: u8, request: u8, nullifier: u8) -> PendingActionEntry {
        PendingActionEntry::new(
            [scope; 32],
            [request; 32],
            [nullifier; 32],
            vec![1, 2, 3, 4],
            1000,
        )
    }

    #[test]
    fn test_save_load_delete() {
        let keystore = MemoryKeystore::new();
        let blob_store = MemoryBlobStore::new();
        let account_id = AccountId::new([0x42u8; 32]);
        let device_id = [0x11u8; 16];
        let mut store = PendingActionStore::new(account_id);
        assert!(store.insert(create_test_entry(1, 1, 1)));
        save_pending_actions(&store, &blob_store, &keystore, &device_id).unwrap();
        let loaded = load_pending_actions(&blob_store, &keystore, &account_id, &device_id).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.find_by_scope(&[1u8; 32]).is_some());
        let mut loaded = loaded;
        loaded.remove(&[1u8; 32]);
        save_pending_actions(&loaded, &blob_store, &keystore, &device_id).unwrap();
        let final_store = load_pending_actions(&blob_store, &keystore, &account_id, &device_id).unwrap();
        assert!(final_store.entries.is_empty());
    }

    #[test]
    fn test_expiration() {
        let account_id = AccountId::new([0u8; 32]);
        let mut store = PendingActionStore::new(account_id);
        let entry = PendingActionEntry::new([1u8; 32], [2u8; 32], [3u8; 32], vec![], 1000);
        assert!(store.insert(entry));
        store.prune_expired(1000);
        assert_eq!(store.entries.len(), 1);
        store.prune_expired(1000 + PENDING_TTL_SECONDS);
        assert!(store.entries.is_empty());
    }
}
