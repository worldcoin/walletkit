//! Key hierarchy management for credential storage.

use rand::{rngs::OsRng, RngCore};

use super::{
    envelope::AccountKeyEnvelope,
    error::{StorageError, StorageResult},
    traits::{AtomicBlobStore, DeviceKeystore},
    ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_AD,
};

/// In-memory account keys derived from the account key envelope.
///
/// Keys are held in memory for the lifetime of the storage handle.
#[allow(clippy::struct_field_names)]
pub struct StorageKeys {
    intermediate_key: [u8; 32],
}

impl StorageKeys {
    /// Initializes storage keys by opening or creating the account key envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the envelope cannot be read, decrypted, or parsed,
    /// or if persistence to the blob store fails.
    pub fn init(
        keystore: &dyn DeviceKeystore,
        blob_store: &dyn AtomicBlobStore,
        now: u64,
    ) -> StorageResult<Self> {
        if let Some(bytes) = blob_store.read(ACCOUNT_KEYS_FILENAME)? {
            let envelope = AccountKeyEnvelope::deserialize(&bytes)?;
            let k_intermediate_bytes = keystore
                .open(ACCOUNT_KEY_ENVELOPE_AD, &envelope.wrapped_k_intermediate)?;
            let k_intermediate = parse_key_32(&k_intermediate_bytes, "K_intermediate")?;
            Ok(Self {
                intermediate_key: k_intermediate,
            })
        } else {
            let k_intermediate = random_key();
            let wrapped_k_intermediate =
                keystore.seal(ACCOUNT_KEY_ENVELOPE_AD, &k_intermediate)?;
            let envelope = AccountKeyEnvelope::new(wrapped_k_intermediate, now);
            let bytes = envelope.serialize()?;
            blob_store.write_atomic(ACCOUNT_KEYS_FILENAME, &bytes)?;
            Ok(Self {
                intermediate_key: k_intermediate,
            })
        }
    }

    /// Returns the intermediate key. Treat this as sensitive material.
    #[must_use]
    pub const fn intermediate_key(&self) -> [u8; 32] {
        self.intermediate_key
    }
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn parse_key_32(bytes: &[u8], label: &str) -> StorageResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(StorageError::InvalidEnvelope(format!(
            "{label} length mismatch: expected 32, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests_utils::{InMemoryBlobStore, InMemoryKeystore};

    #[test]
    fn test_storage_keys_round_trip() {
        let keystore = InMemoryKeystore::new();
        let blob_store = InMemoryBlobStore::new();
        let keys_first = StorageKeys::init(&keystore, &blob_store, 100).expect("init");
        let keys_second = StorageKeys::init(&keystore, &blob_store, 200).expect("init");

        assert_eq!(keys_first.intermediate_key, keys_second.intermediate_key);
    }

    #[test]
    fn test_storage_keys_keystore_mismatch_fails() {
        let keystore = InMemoryKeystore::new();
        let blob_store = InMemoryBlobStore::new();
        StorageKeys::init(&keystore, &blob_store, 123).expect("init");

        let other_keystore = InMemoryKeystore::new();
        match StorageKeys::init(&other_keystore, &blob_store, 456) {
            Err(
                StorageError::Crypto(_)
                | StorageError::InvalidEnvelope(_)
                | StorageError::Keystore(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn test_storage_keys_tampered_envelope_fails() {
        let keystore = InMemoryKeystore::new();
        let blob_store = InMemoryBlobStore::new();
        StorageKeys::init(&keystore, &blob_store, 123).expect("init");

        let mut bytes = blob_store
            .read(ACCOUNT_KEYS_FILENAME)
            .expect("read")
            .expect("present");
        bytes[0] ^= 0xFF;
        blob_store
            .write_atomic(ACCOUNT_KEYS_FILENAME, &bytes)
            .expect("write");

        match StorageKeys::init(&keystore, &blob_store, 456) {
            Err(
                StorageError::Serialization(_)
                | StorageError::Crypto(_)
                | StorageError::UnsupportedEnvelopeVersion(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
    }

}
