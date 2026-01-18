//! Key hierarchy management for credential storage.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use super::{
    envelope::AccountKeyEnvelope,
    error::{StorageError, StorageResult},
    traits::{AtomicBlobStore, DeviceKeystore},
    ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_AD, CACHE_INFO, CACHE_SALT,
    VAULT_KEY_AD,
};

/// In-memory account keys derived from the account key envelope.
///
/// Keys are held in memory for the lifetime of the storage handle.
#[allow(clippy::struct_field_names)]
pub struct StorageKeys {
    intermediate_key: [u8; 32],
    vault_key: [u8; 32],
    cache_key: [u8; 32],
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
            let k_vault = unwrap_vault_key(&k_intermediate, &envelope.wrapped_k_vault)?;
            let k_cache = derive_cache_key(&k_intermediate)?;
            Ok(Self {
                intermediate_key: k_intermediate,
                vault_key: k_vault,
                cache_key: k_cache,
            })
        } else {
            let k_intermediate = random_key();
            let k_vault = random_key();
            let wrapped_k_intermediate =
                keystore.seal(ACCOUNT_KEY_ENVELOPE_AD, &k_intermediate)?;
            let wrapped_k_vault = wrap_vault_key(&k_intermediate, &k_vault)?;
            let envelope =
                AccountKeyEnvelope::new(wrapped_k_intermediate, wrapped_k_vault, now);
            let bytes = envelope.serialize()?;
            blob_store.write_atomic(ACCOUNT_KEYS_FILENAME, &bytes)?;
            let k_cache = derive_cache_key(&k_intermediate)?;
            Ok(Self {
                intermediate_key: k_intermediate,
                vault_key: k_vault,
                cache_key: k_cache,
            })
        }
    }

    /// Returns the vault key used for the encrypted vault database.
    #[must_use]
    pub const fn vault_key(&self) -> [u8; 32] {
        self.vault_key
    }

    /// Returns the cache key derived from the intermediate key.
    #[must_use]
    pub const fn cache_key(&self) -> [u8; 32] {
        self.cache_key
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

fn wrap_vault_key(
    k_intermediate: &[u8; 32],
    k_vault: &[u8; 32],
) -> StorageResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(k_intermediate));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: k_vault,
                aad: VAULT_KEY_AD,
            },
        )
        .map_err(|err| StorageError::Crypto(err.to_string()))?;
    let mut out = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn unwrap_vault_key(
    k_intermediate: &[u8; 32],
    wrapped_k_vault: &[u8],
) -> StorageResult<[u8; 32]> {
    if wrapped_k_vault.len() < 24 {
        return Err(StorageError::InvalidEnvelope(
            "wrapped_K_vault too short".to_string(),
        ));
    }
    let (nonce_bytes, payload) = wrapped_k_vault.split_at(24);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(k_intermediate));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: payload,
                aad: VAULT_KEY_AD,
            },
        )
        .map_err(|err| StorageError::Crypto(err.to_string()))?;
    parse_key_32(&plaintext, "K_vault")
}

fn derive_cache_key(k_intermediate: &[u8; 32]) -> StorageResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(CACHE_SALT), k_intermediate);
    let mut okm = [0u8; 32];
    hk.expand(CACHE_INFO, &mut okm)
        .map_err(|err| StorageError::Crypto(err.to_string()))?;
    Ok(okm)
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
        assert_eq!(keys_first.vault_key, keys_second.vault_key);
        assert_eq!(keys_first.cache_key, keys_second.cache_key);
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

    #[test]
    fn test_cache_key_derivation_vector() {
        let k_intermediate = [0x11u8; 32];
        let derived = derive_cache_key(&k_intermediate).expect("derive");
        let expected = hex::decode(
            "6534249b820a9d3c382a2f2dfc6fc4dccbcf721c0b5aaae5704e7a554fb6cfef",
        )
        .expect("decode");
        assert_eq!(derived.to_vec(), expected);
    }
}
