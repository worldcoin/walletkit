//! Account key envelope persistence helpers.

use serde::{Deserialize, Serialize};

use super::error::{StorageError, StorageResult};

const ENVELOPE_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AccountKeyEnvelope {
    pub(crate) version: u32,
    pub(crate) wrapped_k_intermediate: Vec<u8>,
    pub(crate) wrapped_k_vault: Vec<u8>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

impl AccountKeyEnvelope {
    pub(crate) fn new(
        wrapped_k_intermediate: Vec<u8>,
        wrapped_k_vault: Vec<u8>,
        now: u64,
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            wrapped_k_intermediate,
            wrapped_k_vault,
            created_at: now,
            updated_at: now,
        }
    }

    pub(crate) fn serialize(&self) -> StorageResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|err| StorageError::Serialization(err.to_string()))
    }

    pub(crate) fn deserialize(bytes: &[u8]) -> StorageResult<Self> {
        let envelope: Self = bincode::deserialize(bytes)
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
        let envelope = AccountKeyEnvelope::new(vec![1, 2, 3], vec![4, 5, 6], 123);
        let bytes = envelope.serialize().expect("serialize");
        let decoded = AccountKeyEnvelope::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.version, ENVELOPE_VERSION);
        assert_eq!(decoded.wrapped_k_intermediate, vec![1, 2, 3]);
        assert_eq!(decoded.wrapped_k_vault, vec![4, 5, 6]);
        assert_eq!(decoded.created_at, 123);
        assert_eq!(decoded.updated_at, 123);
    }

    #[test]
    fn test_envelope_version_mismatch() {
        let mut envelope =
            AccountKeyEnvelope::new(vec![1, 2, 3], vec![4, 5, 6], 123);
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
