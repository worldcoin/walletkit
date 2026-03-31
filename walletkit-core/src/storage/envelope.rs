//! Account key envelope persistence helpers.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::{StorageError, StorageResult};

const ENVELOPE_VERSION: u32 = 1;

/// Account key envelope persisted as `account_keys.bin`.
///
/// Stores `K_intermediate` sealed under `K_device` (via [`DeviceKeystore`](super::traits::DeviceKeystore)).
/// Opened once per storage initialization and kept in memory for the lifetime
/// of the storage handle. Device-local and not intended to be synced across devices.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AccountKeyEnvelope {
    /// Envelope format version.
    pub(crate) version: u32,
    /// `DeviceKeystore::seal(ad_i, K_intermediate)` where
    /// `ad_i = "worldid:account-key-envelope"`.
    pub(crate) wrapped_k_intermediate: Vec<u8>,
    /// Timestamp of initial envelope creation (unix seconds).
    pub(crate) created_at: u64,
    /// Timestamp of last envelope update (unix seconds).
    pub(crate) updated_at: u64,
}

impl AccountKeyEnvelope {
    pub(crate) const fn new(wrapped_k_intermediate: Vec<u8>, now: u64) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            wrapped_k_intermediate,
            created_at: now,
            updated_at: now,
        }
    }

    pub(crate) fn serialize(&self) -> StorageResult<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        Ok(bytes)
    }

    pub(crate) fn deserialize(bytes: &[u8]) -> StorageResult<Self> {
        let envelope: Self = ciborium::de::from_reader(bytes)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(StorageError::UnsupportedEnvelopeVersion(envelope.version));
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_round_trip() {
        let envelope = AccountKeyEnvelope::new(vec![1, 2, 3], 123);
        let bytes = envelope.serialize().expect("serialize");
        let decoded = AccountKeyEnvelope::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.version, ENVELOPE_VERSION);
        assert_eq!(decoded.wrapped_k_intermediate, vec![1, 2, 3]);
        assert_eq!(decoded.created_at, 123);
        assert_eq!(decoded.updated_at, 123);
    }

    #[test]
    fn test_envelope_version_mismatch() {
        let mut envelope = AccountKeyEnvelope::new(vec![1, 2, 3], 123);
        envelope.version = ENVELOPE_VERSION + 1;
        let bytes = envelope.serialize().expect("serialize");
        match AccountKeyEnvelope::deserialize(&bytes) {
            Err(StorageError::UnsupportedEnvelopeVersion(version)) => {
                assert_eq!(version, ENVELOPE_VERSION + 1);
            }
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
