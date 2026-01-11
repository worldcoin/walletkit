//! Account state serialization and device-protected persistence.
//!
//! This module handles saving and loading the device-protected `AccountState`
//! to the platform's atomic blob store.

use crate::credential_storage::{
    platform::{AtomicBlobStore, DeviceKeystore},
    vault::VaultKey,
    AccountId, AccountState, StorageError, StorageResult, ACCOUNT_STATE_VERSION,
};

use super::derivation::{derive_account_id, generate_blind_seeds, generate_device_id};


/// Filename for the encrypted account state blob.
pub const ACCOUNT_STATE_FILENAME: &str = "account_state.bin";

/// Filename for the encrypted pending actions blob.
/// Note: Used in Phase 5 (Nullifier Protection).
#[allow(dead_code)]
pub const PENDING_ACTIONS_FILENAME: &str = "pending_actions.bin";


/// Creates a new `AccountState` for a fresh account.
///
/// This generates all required random values and derives the account ID.
///
/// # Arguments
///
/// * `vault_key` - The newly generated vault key
/// * `keystore` - Device keystore for wrapping the vault key
///
/// # Returns
///
/// A new `AccountState` ready to be persisted.
///
/// # Errors
///
/// Returns an error if vault key wrapping fails.
pub fn create_account_state(
    vault_key: &VaultKey,
    keystore: &dyn DeviceKeystore,
) -> StorageResult<AccountState> {
    let account_id = derive_account_id(vault_key);
    let device_id = generate_device_id();
    let (issuer_blind_seed, session_blind_seed) = generate_blind_seeds();

    let now = get_current_timestamp();

    // Wrap the vault key with device key
    let vault_key_wrap = wrap_vault_key(vault_key, &account_id, &device_id, keystore)?;

    Ok(AccountState {
        state_version: ACCOUNT_STATE_VERSION,
        account_id,
        leaf_index_cache: None,
        issuer_blind_seed,
        session_blind_seed,
        vault_key_wrap,
        device_id,
        updated_at: now,
    })
}


/// Wraps the vault key with the device keystore.
///
/// # Arguments
///
/// * `vault_key` - The vault key to wrap
/// * `account_id` - Account ID for associated data
/// * `device_id` - Device ID for associated data
/// * `keystore` - Device keystore to use
///
/// # Returns
///
/// The wrapped vault key bytes.
///
/// # Errors
///
/// Returns an error if the keystore seal operation fails.
pub fn wrap_vault_key(
    vault_key: &VaultKey,
    account_id: &AccountId,
    device_id: &[u8; 16],
    keystore: &dyn DeviceKeystore,
) -> StorageResult<Vec<u8>> {
    let aad = build_vault_key_wrap_aad(account_id, device_id);
    keystore.seal(&aad, vault_key.as_bytes())
}

/// Unwraps the vault key using the device keystore.
///
/// # Arguments
///
/// * `wrapped` - The wrapped vault key bytes
/// * `account_id` - Account ID for associated data
/// * `device_id` - Device ID for associated data
/// * `keystore` - Device keystore to use
///
/// # Returns
///
/// The unwrapped vault key.
///
/// # Errors
///
/// Returns an error if:
/// - The keystore open operation fails
/// - The unwrapped key is not exactly 32 bytes
pub fn unwrap_vault_key(
    wrapped: &[u8],
    account_id: &AccountId,
    device_id: &[u8; 16],
    keystore: &dyn DeviceKeystore,
) -> StorageResult<VaultKey> {
    let aad = build_vault_key_wrap_aad(account_id, device_id);
    let plaintext = keystore.open(&aad, wrapped)?;

    if plaintext.len() != 32 {
        return Err(StorageError::corrupted(format!(
            "invalid vault key length: expected 32, got {}",
            plaintext.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);
    Ok(VaultKey::from_bytes(key_bytes))
}

/// Builds associated data for vault key wrapping.
///
/// Format: `account_id || device_id || "worldid:vault-key-wrap"`
fn build_vault_key_wrap_aad(account_id: &AccountId, device_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 16 + 22);
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(b"worldid:vault-key-wrap");
    aad
}


/// Saves the account state to the blob store with device protection.
///
/// # Arguments
///
/// * `state` - The account state to save
/// * `blob_store` - The atomic blob store
/// * `keystore` - Device keystore for encryption
///
/// # Errors
///
/// Returns an error if serialization or encryption fails.
pub fn save_account_state(
    state: &AccountState,
    blob_store: &dyn AtomicBlobStore,
    keystore: &dyn DeviceKeystore,
) -> StorageResult<()> {
    // Serialize the state
    let plaintext = serialize_account_state(state)?;

    // Build associated data
    let aad = state.device_seal_aad();

    // Encrypt with device key
    let ciphertext = keystore.seal(&aad, &plaintext)?;

    // Write atomically
    blob_store.write_atomic(ACCOUNT_STATE_FILENAME, &ciphertext)
}

/// Loads the account state from the blob store.
///
/// # Arguments
///
/// * `blob_store` - The atomic blob store
/// * `keystore` - Device keystore for decryption
/// * `account_id` - Expected account ID (for AAD construction)
/// * `device_id` - Device ID (for AAD construction)
///
/// # Returns
///
/// The decrypted and deserialized account state, or `None` if not found.
///
/// # Errors
///
/// Returns an error if decryption or deserialization fails.
pub fn load_account_state(
    blob_store: &dyn AtomicBlobStore,
    keystore: &dyn DeviceKeystore,
    account_id: &AccountId,
    device_id: &[u8; 16],
) -> StorageResult<Option<AccountState>> {
    // Read the encrypted blob
    let Some(ciphertext) = blob_store.read(ACCOUNT_STATE_FILENAME)? else {
        return Ok(None);
    };

    // Build associated data
    let aad = build_device_seal_aad(account_id, device_id);

    // Decrypt
    let plaintext = keystore.open(&aad, &ciphertext)?;

    // Deserialize
    let state = deserialize_account_state(&plaintext)?;

    // Verify account ID matches
    if state.account_id != *account_id {
        return Err(StorageError::AccountIdMismatch {
            expected: *account_id,
            found: state.account_id,
        });
    }

    Ok(Some(state))
}

/// Builds associated data for device sealing of account state.
///
/// Format: `account_id || device_id || "worldid:device-state"`
fn build_device_seal_aad(account_id: &AccountId, device_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 16 + 20);
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(b"worldid:device-state");
    aad
}

// Serialization

/// Serializes an `AccountState` to bytes using bincode.
fn serialize_account_state(state: &AccountState) -> StorageResult<Vec<u8>> {
    bincode::serialize(state).map_err(|e| StorageError::serialization(e.to_string()))
}

/// Deserializes an `AccountState` from bytes using bincode.
fn deserialize_account_state(bytes: &[u8]) -> StorageResult<AccountState> {
    bincode::deserialize(bytes).map_err(|e| StorageError::deserialization(e.to_string()))
}

// Helpers

/// Returns the current Unix timestamp.
fn get_current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_storage::platform::memory::{MemoryBlobStore, MemoryKeystore};

    #[test]
    fn test_serialize_deserialize_account_state() {
        let state = AccountState {
            state_version: 1,
            account_id: AccountId::new([0x42u8; 32]),
            leaf_index_cache: Some(12345),
            issuer_blind_seed: [0xABu8; 32],
            session_blind_seed: [0xCDu8; 32],
            vault_key_wrap: vec![1, 2, 3, 4, 5],
            device_id: [0xEFu8; 16],
            updated_at: 1234567890,
        };
        let bytes = serialize_account_state(&state).unwrap();
        let decoded = deserialize_account_state(&bytes).unwrap();
        assert_eq!(decoded.account_id, state.account_id);
        assert_eq!(decoded.leaf_index_cache, state.leaf_index_cache);
    }

    #[test]
    fn test_leaf_index_cache_persistence() {
        let keystore = MemoryKeystore::new();
        let blob_store = MemoryBlobStore::new();
        let vault_key = VaultKey::generate();
        let mut state = create_account_state(&vault_key, &keystore).unwrap();
        let account_id = state.account_id;
        let device_id = state.device_id;
        save_account_state(&state, &blob_store, &keystore).unwrap();
        state.leaf_index_cache = Some(99999);
        state.updated_at = get_current_timestamp();
        save_account_state(&state, &blob_store, &keystore).unwrap();
        let loaded = load_account_state(&blob_store, &keystore, &account_id, &device_id).unwrap().unwrap();
        assert_eq!(loaded.leaf_index_cache, Some(99999));
    }
}
