//! Persistent envelope holding a `Keystore`-sealed intermediate key.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{StoreError, StoreResult};

const ENVELOPE_VERSION: u32 = 1;

/// Persisted envelope produced by [`crate::init_or_open_envelope_key`].
///
/// `wrapped_k_intermediate` is the intermediate key sealed by the
/// [`Keystore`](crate::Keystore). The envelope is serialised as `CBOR` and
/// written via an [`AtomicBlobStore`](crate::AtomicBlobStore).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyEnvelope {
    /// On-disk format version. Currently always `1`.
    pub version: u32,
    /// Keystore-sealed intermediate key bytes.
    pub wrapped_k_intermediate: Vec<u8>,
    /// Creation timestamp (seconds).
    pub created_at: u64,
    /// Last update timestamp (seconds).
    pub updated_at: u64,
}

impl KeyEnvelope {
    /// Creates a new envelope at version `1`.
    #[must_use]
    pub const fn new(wrapped_k_intermediate: Vec<u8>, now: u64) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            wrapped_k_intermediate,
            created_at: now,
            updated_at: now,
        }
    }

    /// Serialises the envelope to `CBOR`.
    ///
    /// # Errors
    ///
    /// Returns an error if `CBOR` encoding fails.
    pub fn serialize(&self) -> StoreResult<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|err| StoreError::Serialization(err.to_string()))?;
        Ok(bytes)
    }

    /// Deserialises an envelope from `CBOR` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnsupportedEnvelopeVersion`] if the version is
    /// unrecognised, or [`StoreError::Serialization`] if `CBOR` decoding
    /// fails.
    pub fn deserialize(bytes: &[u8]) -> StoreResult<Self> {
        let envelope: Self = ciborium::de::from_reader(bytes)
            .map_err(|err| StoreError::Serialization(err.to_string()))?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(StoreError::UnsupportedEnvelopeVersion(envelope.version));
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        let bytes = envelope.serialize().expect("serialize");
        let decoded = KeyEnvelope::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.version, ENVELOPE_VERSION);
        assert_eq!(decoded.wrapped_k_intermediate, vec![1, 2, 3]);
        assert_eq!(decoded.created_at, 123);
        assert_eq!(decoded.updated_at, 123);
    }

    #[test]
    fn version_mismatch() {
        let mut envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        envelope.version = ENVELOPE_VERSION + 1;
        let bytes = envelope.serialize().expect("serialize");
        match KeyEnvelope::deserialize(&bytes) {
            Err(StoreError::UnsupportedEnvelopeVersion(version)) => {
                assert_eq!(version, ENVELOPE_VERSION + 1);
            }
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
