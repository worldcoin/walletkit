//! Host-provided storage for PCP (personal custody package) blobs.

use std::sync::Arc;

use super::blob_id::{compute_blob_id, BlobId};
use super::error::{StorageError, StorageResult};

/// Host-implemented store for PCP blobs, addressed by [`BlobId`].
///
/// The host backs this with wherever it keeps PCPs. It exchanges plaintext PCP
/// packages, without the host's outer encryption. `WalletKit` verifies every
/// blob against its id, so implementations need not.
///
/// Only passed to credential-transfer calls; the credential vault never uses it.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BlobStore: Send + Sync {
    /// Returns the plaintext blob stored under `id`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn get(&self, id: Arc<BlobId>) -> StorageResult<Option<Vec<u8>>>;

    /// Stores `plaintext` under `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn put(&self, id: Arc<BlobId>, plaintext: Vec<u8>) -> StorageResult<()>;
}

/// Wraps a [`BlobStore`] so that bytes only cross it when they hash to their id.
pub struct VerifiedBlobStore {
    inner: Arc<dyn BlobStore>,
}

impl VerifiedBlobStore {
    /// Wraps `inner`.
    #[must_use]
    pub fn new(inner: Arc<dyn BlobStore>) -> Self {
        Self { inner }
    }

    /// Returns the blob stored under `id`, if present and intact.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::BlobStore`] if the host fails, or if the bytes it
    /// returned do not hash to `id`. The error never contains the bytes.
    pub async fn get(&self, id: &BlobId) -> StorageResult<Option<Vec<u8>>> {
        let Some(plaintext) = self.inner.get(Arc::new(*id)).await? else {
            return Ok(None);
        };
        if compute_blob_id(&plaintext) != *id {
            return Err(StorageError::BlobStore(
                "stored blob does not match its id".to_string(),
            ));
        }
        Ok(Some(plaintext))
    }

    /// Stores `plaintext` under `id`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidInput`] without calling the host if
    /// `plaintext` does not hash to `id`, or [`StorageError::BlobStore`] if the
    /// host fails.
    pub async fn put(&self, id: &BlobId, plaintext: Vec<u8>) -> StorageResult<()> {
        if compute_blob_id(&plaintext) != *id {
            return Err(StorageError::InvalidInput(
                "blob does not match its id".to_string(),
            ));
        }
        self.inner.put(Arc::new(*id), plaintext).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    const HELLO_PCP_ID: &str =
        "733ae41c33b82d2d18eba3b18f289f649f49a386362441f9bff74c613764b00f";

    #[derive(Default)]
    struct InMemoryBlobStore {
        blobs: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl InMemoryBlobStore {
        fn insert_unchecked(&self, id: &BlobId, bytes: &[u8]) {
            self.blobs
                .lock()
                .unwrap()
                .insert(id.to_bytes(), bytes.to_vec());
        }

        fn len(&self) -> usize {
            self.blobs.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for InMemoryBlobStore {
        async fn get(&self, id: Arc<BlobId>) -> StorageResult<Option<Vec<u8>>> {
            Ok(self.blobs.lock().unwrap().get(&id.to_bytes()).cloned())
        }

        async fn put(&self, id: Arc<BlobId>, plaintext: Vec<u8>) -> StorageResult<()> {
            self.blobs.lock().unwrap().insert(id.to_bytes(), plaintext);
            Ok(())
        }
    }

    fn hello_pcp_id() -> BlobId {
        let id = compute_blob_id(b"hello pcp");
        assert_eq!(id.to_hex_string(), HELLO_PCP_ID);
        id
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let inner = Arc::new(InMemoryBlobStore::default());
        let store = VerifiedBlobStore::new(inner.clone());
        let id = hello_pcp_id();

        store.put(&id, b"hello pcp".to_vec()).await.unwrap();

        assert_eq!(store.get(&id).await.unwrap(), Some(b"hello pcp".to_vec()));
        assert_eq!(inner.len(), 1);
    }

    #[tokio::test]
    async fn get_returns_none_when_absent() {
        let store = VerifiedBlobStore::new(Arc::new(InMemoryBlobStore::default()));

        assert_eq!(store.get(&hello_pcp_id()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_rejects_bytes_that_do_not_match_the_id() {
        let inner = Arc::new(InMemoryBlobStore::default());
        let id = hello_pcp_id();
        inner.insert_unchecked(&id, b"tampered pcp");
        let store = VerifiedBlobStore::new(inner);

        let err = store.get(&id).await.unwrap_err();

        assert!(matches!(err, StorageError::BlobStore(_)));
        assert!(!err.to_string().contains("tampered"));
    }

    #[tokio::test]
    async fn put_rejects_bytes_that_do_not_match_the_id() {
        let inner = Arc::new(InMemoryBlobStore::default());
        let store = VerifiedBlobStore::new(inner.clone());

        let err = store
            .put(&hello_pcp_id(), b"tampered pcp".to_vec())
            .await
            .unwrap_err();

        assert!(matches!(err, StorageError::InvalidInput(_)));
        assert!(!err.to_string().contains("tampered"));
        assert_eq!(inner.len(), 0);
    }
}
