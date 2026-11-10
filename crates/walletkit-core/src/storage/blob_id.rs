//! Content ids that link credentials to their PCP blobs.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::error::{StorageError, StorageResult};

const BLOB_ID_TAG: &[u8] = b"worldid:credential-blob:v1";

/// Content id of a credential's PCP (personal custody package).
///
/// `SHA-256(b"worldid:credential-blob:v1" || plaintext)`, where `plaintext` is
/// the PCP package without the host's outer encryption. Hosts compute the same
/// value independently, so the derivation must stay byte-stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, uniffi::Object)]
pub struct BlobId([u8; 32]);

#[uniffi::export]
impl BlobId {
    /// Wraps a 32-byte blob id.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidInput`] when `bytes` is not 32 bytes long.
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> StorageResult<Self> {
        let len = bytes.len();
        bytes.try_into().map(Self).map_err(|_| {
            StorageError::InvalidInput(format!(
                "expected 32 bytes for a blob id, got {len}"
            ))
        })
    }

    /// Returns the 32 id bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Returns the id as 64 lowercase hex characters.
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.0)
    }
}

impl BlobId {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Computes the [`BlobId`] of a plaintext PCP package.
#[must_use]
#[uniffi::export]
pub fn blob_id(plaintext: &[u8]) -> Arc<BlobId> {
    Arc::new(compute_blob_id(plaintext))
}

pub(crate) fn compute_blob_id(plaintext: &[u8]) -> BlobId {
    let mut hasher = Sha256::new();
    hasher.update(BLOB_ID_TAG);
    hasher.update(plaintext);
    BlobId(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(b"", "dbc45c9a56ec1cfe89c45c6bfbc3bffe9d574fcfbdb28f24442b0f6a698f529f" ; "empty")]
    #[test_case(b"hello pcp", "733ae41c33b82d2d18eba3b18f289f649f49a386362441f9bff74c613764b00f" ; "hello pcp")]
    fn blob_id_matches_frozen_vector(plaintext: &[u8], expected: &str) {
        assert_eq!(blob_id(plaintext).to_hex_string(), expected);
    }

    #[test]
    fn from_bytes_round_trips_and_rejects_other_lengths() {
        let id = compute_blob_id(b"hello pcp");
        assert_eq!(BlobId::from_bytes(id.to_bytes()).unwrap(), id);
        assert!(BlobId::from_bytes(vec![0; 31]).is_err());
        assert!(BlobId::from_bytes(vec![0; 33]).is_err());
    }
}
