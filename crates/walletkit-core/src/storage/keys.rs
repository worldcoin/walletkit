//! Key management for credential storage.
//!
//! [`StorageKeys`] opens (or creates on first use) the account key envelope via
//! `walletkit-db` and holds the resulting `K_intermediate` in memory for the lifetime
//! of the storage handle; both databases are opened with it. The sealing-key to
//! `K_intermediate` hierarchy and envelope encryption are described in the
//! `walletkit-db` README.

use secrecy::SecretBox;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    error::StorageResult,
    traits::{AtomicBlobStore, KeySealer},
    ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_CONTEXT,
};
use walletkit_db::Lock;

/// In-memory account keys derived from the account key envelope.
///
/// Keys are held in memory for the lifetime of the storage handle.
#[derive(Zeroize, ZeroizeOnDrop)]
#[allow(clippy::struct_field_names)]
pub struct StorageKeys {
    intermediate_key: SecretBox<[u8; 32]>,
}

impl StorageKeys {
    /// Initializes storage keys by opening or creating the account key envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the envelope cannot be read, decrypted, or parsed,
    /// or if persistence to the blob store fails.
    pub async fn init(
        key_sealer: &dyn KeySealer,
        blob_store: &dyn AtomicBlobStore,
        lock: &Lock,
        now: u64,
    ) -> StorageResult<Self> {
        let intermediate_key = walletkit_db::init_or_open_envelope_key(
            &KeySealerAdapter(key_sealer),
            &BlobStoreAdapter(blob_store),
            lock,
            ACCOUNT_KEYS_FILENAME,
            ACCOUNT_KEY_ENVELOPE_CONTEXT,
            now,
        )
        .await?;
        Ok(Self { intermediate_key })
    }

    /// Returns a reference to the intermediate key's [`SecretBox`].
    #[must_use]
    pub const fn intermediate_key(&self) -> &SecretBox<[u8; 32]> {
        &self.intermediate_key
    }
}

// Trait-object bridge from walletkit-core's uniffi-annotated traits onto
// walletkit-db's plain-Rust trait surface. Required because Rust's orphan
// rule prevents a blanket impl across crates. `KeySealer::seal` borrows its
// plaintext (see walletkit-db/src/traits.rs); `KeySealerAdapter::seal` is the single
// point where the secret is copied into an owned `Vec<u8>`, because
// walletkit-core's `KeySealer` is a uniffi callback interface and those only support
// pass-by-value parameters (no `&[u8]`). That copy — and any further copy
// the foreign (Swift/Kotlin/etc.) implementation makes on its own side — is
// outside Rust's control; this is an accepted uniffi limitation, not a bug.

struct KeySealerAdapter<'a>(&'a dyn KeySealer);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl walletkit_db::KeySealer for KeySealerAdapter<'_> {
    async fn seal(
        &self,
        context: &[u8],
        plaintext: &[u8],
    ) -> walletkit_db::StoreResult<Vec<u8>> {
        self.0
            .seal(context.to_vec(), plaintext.to_vec())
            .await
            .map_err(|e| walletkit_db::StoreError::Sealer(e.to_string()))
    }
    async fn unseal(
        &self,
        context: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> walletkit_db::StoreResult<Vec<u8>> {
        self.0
            .unseal(context, ciphertext)
            .await
            .map_err(|e| walletkit_db::StoreError::Sealer(e.to_string()))
    }
}

struct BlobStoreAdapter<'a>(&'a dyn AtomicBlobStore);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl walletkit_db::AtomicBlobStore for BlobStoreAdapter<'_> {
    async fn read(&self, path: String) -> walletkit_db::StoreResult<Option<Vec<u8>>> {
        self.0
            .read(path)
            .await
            .map_err(|e| walletkit_db::StoreError::BlobStore(e.to_string()))
    }
    async fn write_atomic(
        &self,
        path: String,
        bytes: Vec<u8>,
    ) -> walletkit_db::StoreResult<()> {
        self.0
            .write_atomic(path, bytes)
            .await
            .map_err(|e| walletkit_db::StoreError::BlobStore(e.to_string()))
    }
    async fn delete(&self, path: String) -> walletkit_db::StoreResult<()> {
        self.0
            .delete(path)
            .await
            .map_err(|e| walletkit_db::StoreError::BlobStore(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::error::StorageError;
    use crate::storage::tests_utils::{InMemoryBlobStore, InMemoryKeySealer};
    use secrecy::ExposeSecret;
    use uuid::Uuid;
    use walletkit_db::Lock;

    fn temp_lock_path() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-keys-lock-{}.lock", Uuid::new_v4()));
        path
    }

    #[tokio::test]
    async fn test_storage_keys_round_trip() {
        let key_sealer = InMemoryKeySealer::new();
        let blob_store = InMemoryBlobStore::new();
        let lock_path = temp_lock_path();
        let lock = Lock::open(&lock_path).expect("open lock");
        let keys_first = StorageKeys::init(&key_sealer, &blob_store, &lock, 100)
            .await
            .expect("init");
        let keys_second = StorageKeys::init(&key_sealer, &blob_store, &lock, 200)
            .await
            .expect("init");

        assert_eq!(
            keys_first.intermediate_key.expose_secret(),
            keys_second.intermediate_key.expose_secret()
        );
        let _ = std::fs::remove_file(lock_path);
    }

    #[tokio::test]
    async fn test_storage_keys_sealer_mismatch_fails() {
        let key_sealer = InMemoryKeySealer::new();
        let blob_store = InMemoryBlobStore::new();
        let lock_path = temp_lock_path();
        let lock = Lock::open(&lock_path).expect("open lock");
        StorageKeys::init(&key_sealer, &blob_store, &lock, 123)
            .await
            .expect("init");

        let other_key_sealer = InMemoryKeySealer::new();
        match StorageKeys::init(&other_key_sealer, &blob_store, &lock, 456).await {
            Err(
                StorageError::Crypto(_)
                | StorageError::InvalidEnvelope(_)
                | StorageError::Sealer(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
        let _ = std::fs::remove_file(lock_path);
    }

    #[tokio::test]
    async fn test_storage_keys_tampered_envelope_fails() {
        let key_sealer = InMemoryKeySealer::new();
        let blob_store = InMemoryBlobStore::new();
        let lock_path = temp_lock_path();
        let lock = Lock::open(&lock_path).expect("open lock");
        StorageKeys::init(&key_sealer, &blob_store, &lock, 123)
            .await
            .expect("init");

        let mut bytes = blob_store
            .read(ACCOUNT_KEYS_FILENAME.to_string())
            .await
            .expect("read")
            .expect("present");
        bytes[0] ^= 0xFF;
        blob_store
            .write_atomic(ACCOUNT_KEYS_FILENAME.to_string(), bytes)
            .await
            .expect("write");

        match StorageKeys::init(&key_sealer, &blob_store, &lock, 456).await {
            Err(
                StorageError::Serialization(_)
                | StorageError::Crypto(_)
                | StorageError::UnsupportedEnvelopeVersion(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
        let _ = std::fs::remove_file(lock_path);
    }
}
