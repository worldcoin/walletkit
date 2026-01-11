//! PendingActionStore persistence for device-protected storage.
//!
//! The pending action store tracks in-progress proof disclosures to ensure
//! nullifier single-use. It is encrypted with the device key and stored
//! in the account's blob store.

use crate::credential_storage::{
    platform::{AtomicBlobStore, DeviceKeystore},
    AccountId, PendingActionStore, StorageError, StorageResult,
};

// =============================================================================
// File Names
// =============================================================================

/// Filename for the encrypted pending actions blob.
pub const PENDING_ACTIONS_FILENAME: &str = "pending_actions.bin";

// =============================================================================
// Associated Data Construction
// =============================================================================

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

// =============================================================================
// Serialization
// =============================================================================

/// Serializes a `PendingActionStore` to bytes using bincode.
fn serialize_pending_actions(store: &PendingActionStore) -> StorageResult<Vec<u8>> {
    bincode::serialize(store).map_err(|e| StorageError::serialization(e.to_string()))
}

/// Deserializes a `PendingActionStore` from bytes using bincode.
fn deserialize_pending_actions(bytes: &[u8]) -> StorageResult<PendingActionStore> {
    bincode::deserialize(bytes).map_err(|e| StorageError::deserialization(e.to_string()))
}

// =============================================================================
// Load / Save
// =============================================================================

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

// =============================================================================
// Tests
// =============================================================================

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
    fn test_load_nonexistent_returns_empty() {
        let keystore = MemoryKeystore::new();
        let blob_store = MemoryBlobStore::new();
        let account_id = AccountId::new([0x42u8; 32]);
        let device_id = [0x11u8; 16];

        let store = load_pending_actions(&blob_store, &keystore, &account_id, &device_id).unwrap();

        assert_eq!(store.account_id, account_id);
        assert!(store.entries.is_empty());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let keystore = MemoryKeystore::new();
        let blob_store = MemoryBlobStore::new();
        let account_id = AccountId::new([0x42u8; 32]);
        let device_id = [0x11u8; 16];

        // Create store with entries
        let mut store = PendingActionStore::new(account_id);
        assert!(store.insert(create_test_entry(1, 1, 1)));
        assert!(store.insert(create_test_entry(2, 2, 2)));

        // Save
        save_pending_actions(&store, &blob_store, &keystore, &device_id).unwrap();

        // Verify file exists
        assert!(blob_store.exists(PENDING_ACTIONS_FILENAME).unwrap());

        // Load
        let loaded = load_pending_actions(&blob_store, &keystore, &account_id, &device_id).unwrap();

        assert_eq!(loaded.account_id, account_id);
        assert_eq!(loaded.entries.len(), 2);
        assert!(loaded.find_by_scope(&[1u8; 32]).is_some());
        assert!(loaded.find_by_scope(&[2u8; 32]).is_some());
    }

    #[test]
    fn test_save_overwrites_existing() {
        let keystore = MemoryKeystore::new();
        let blob_store = MemoryBlobStore::new();
        let account_id = AccountId::new([0x42u8; 32]);
        let device_id = [0x11u8; 16];

        // Save initial store
        let mut store = PendingActionStore::new(account_id);
        assert!(store.insert(create_test_entry(1, 1, 1)));
        save_pending_actions(&store, &blob_store, &keystore, &device_id).unwrap();

        // Load and modify
        let mut loaded = load_pending_actions(&blob_store, &keystore, &account_id, &device_id).unwrap();
        loaded.remove(&[1u8; 32]);
        assert!(loaded.insert(create_test_entry(9, 9, 9)));
        save_pending_actions(&loaded, &blob_store, &keystore, &device_id).unwrap();

        // Load again
        let final_store = load_pending_actions(&blob_store, &keystore, &account_id, &device_id).unwrap();
        assert_eq!(final_store.entries.len(), 1);
        assert!(final_store.find_by_scope(&[1u8; 32]).is_none());
        assert!(final_store.find_by_scope(&[9u8; 32]).is_some());
    }

    #[test]
    fn test_wrong_account_id_fails() {
        let keystore = MemoryKeystore::new();
        let blob_store = MemoryBlobStore::new();
        let account_id1 = AccountId::new([0x11u8; 32]);
        let account_id2 = AccountId::new([0x22u8; 32]);
        let device_id = [0xAAu8; 16];

        // Save with account_id1
        let store = PendingActionStore::new(account_id1);
        save_pending_actions(&store, &blob_store, &keystore, &device_id).unwrap();

        // Try to load with account_id2 - AAD mismatch will cause decryption to fail
        // (with real AEAD), or in our test keystore it will produce garbage and
        // deserialization will fail
        let result = load_pending_actions(&blob_store, &keystore, &account_id2, &device_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_store_roundtrip() {
        let keystore = MemoryKeystore::new();
        let blob_store = MemoryBlobStore::new();
        let account_id = AccountId::new([0x42u8; 32]);
        let device_id = [0x11u8; 16];

        let store = PendingActionStore::new(account_id);
        save_pending_actions(&store, &blob_store, &keystore, &device_id).unwrap();

        let loaded = load_pending_actions(&blob_store, &keystore, &account_id, &device_id).unwrap();
        assert!(loaded.entries.is_empty());
    }

    #[test]
    fn test_aad_format() {
        let account_id = AccountId::new([0x11u8; 32]);
        let device_id = [0x22u8; 16];

        let aad = build_pending_actions_aad(&account_id, &device_id);

        assert_eq!(aad.len(), 32 + 16 + 23);
        assert_eq!(&aad[0..32], &[0x11u8; 32]);
        assert_eq!(&aad[32..48], &[0x22u8; 16]);
        assert_eq!(&aad[48..], b"worldid:pending-actions");
    }

    #[test]
    fn test_pending_action_store_capacity() {
        let account_id = AccountId::new([0u8; 32]);
        let mut store = PendingActionStore::new(account_id);

        // Fill to capacity
        for i in 0..crate::credential_storage::MAX_PENDING_ENTRIES {
            let entry = create_test_entry(i as u8, 0, 0);
            assert!(store.insert(entry), "Should insert entry {i}");
        }

        // Should fail at capacity
        let overflow_entry = create_test_entry(0xFF, 0, 0);
        assert!(!store.insert(overflow_entry));
    }

    #[test]
    fn test_pending_action_store_prune_expired() {
        let account_id = AccountId::new([0u8; 32]);
        let mut store = PendingActionStore::new(account_id);

        // Add entry that will be expired
        let entry = PendingActionEntry::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            vec![],
            1000, // created_at
        );
        assert!(store.insert(entry));

        // At time 1000, not expired yet
        store.prune_expired(1000);
        assert_eq!(store.entries.len(), 1);

        // At time 1000 + TTL - 1, still not expired
        store.prune_expired(1000 + PENDING_TTL_SECONDS - 1);
        assert_eq!(store.entries.len(), 1);

        // At time 1000 + TTL, expired
        store.prune_expired(1000 + PENDING_TTL_SECONDS);
        assert!(store.entries.is_empty());
    }

    #[test]
    fn test_pending_action_store_find_and_remove() {
        let account_id = AccountId::new([0u8; 32]);
        let mut store = PendingActionStore::new(account_id);

        let scope = [0xABu8; 32];
        let entry = PendingActionEntry::new(scope, [0xCD; 32], [0xEF; 32], vec![1, 2, 3], 1000);
        assert!(store.insert(entry));

        // Find by scope
        let found = store.find_by_scope(&scope);
        assert!(found.is_some());
        assert_eq!(found.unwrap().request_id, [0xCD; 32]);

        // Remove
        let removed = store.remove(&scope);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().nullifier, [0xEF; 32]);

        // No longer found
        assert!(store.find_by_scope(&scope).is_none());
    }
}
