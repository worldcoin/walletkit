//! Sealed key envelope persisted via [`AtomicBlobStore`].
//!
//! A 32-byte intermediate key is sealed under a device-bound [`Keystore`] and
//! persisted as a CBOR-serialized [`KeyEnvelope`]. On subsequent runs the
//! envelope is read, opened, and the unsealed key returned in a [`SecretBox`].
//!
//! Each consumer chooses its own filename and associated-data namespace so
//! independent vaults (e.g. credential vault and `OrbPcpStore`) cannot share
//! intermediate keys.

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{StoreError, StoreResult};
use crate::lock::LockGuard;
use crate::traits::{AtomicBlobStore, Keystore};

const ENVELOPE_VERSION: u32 = 1;

/// CBOR-serialized envelope holding a sealed 32-byte intermediate key.
///
/// On-disk layout is byte-stable: changing field order, names, or types
/// breaks existing user databases.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyEnvelope {
    /// Envelope format version. Mismatch triggers
    /// [`StoreError::UnsupportedEnvelopeVersion`].
    pub version: u32,
    /// Output of [`Keystore::seal`] over the 32-byte intermediate key.
    pub wrapped_k_intermediate: Vec<u8>,
    /// Unix timestamp (seconds) recorded when the envelope was first written.
    pub created_at: u64,
    /// Unix timestamp (seconds) recorded on the most recent write.
    pub updated_at: u64,
}

impl KeyEnvelope {
    /// Constructs a fresh envelope for `wrapped_k_intermediate` at `now`.
    #[must_use]
    pub const fn new(wrapped_k_intermediate: Vec<u8>, now: u64) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            wrapped_k_intermediate,
            created_at: now,
            updated_at: now,
        }
    }

    /// CBOR-serializes the envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Serialization`] if encoding fails.
    pub fn serialize(&self) -> StoreResult<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|err| StoreError::Serialization(err.to_string()))?;
        Ok(bytes)
    }

    /// CBOR-deserializes an envelope and verifies its version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Serialization`] if decoding fails or
    /// [`StoreError::UnsupportedEnvelopeVersion`] if the version mismatches.
    pub fn deserialize(bytes: &[u8]) -> StoreResult<Self> {
        let envelope: Self = ciborium::de::from_reader(bytes)
            .map_err(|err| StoreError::Serialization(err.to_string()))?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(StoreError::UnsupportedEnvelopeVersion(envelope.version));
        }
        Ok(envelope)
    }
}

/// Initialize or open the envelope-sealed intermediate key.
///
/// On first run, generates a fresh 32-byte key, seals it under `keystore`
/// authenticated by `ad`, persists the envelope at `filename` via
/// `blob_store`, and returns the unsealed key.
///
/// On subsequent runs, reads the envelope at `filename`, opens it under
/// `keystore` authenticated by `ad`, and returns the unsealed key.
///
/// Holding `_lock` ensures the read-open / generate-write sequence is
/// serialized across processes.
///
/// # Errors
///
/// Propagates errors from the keystore, blob store, CBOR codec, or RNG.
pub fn init_or_open_envelope_key(
    keystore: &dyn Keystore,
    blob_store: &dyn AtomicBlobStore,
    _lock: &LockGuard,
    filename: &str,
    ad: &[u8],
    now: u64,
) -> StoreResult<SecretBox<[u8; 32]>> {
    if let Some(bytes) = blob_store.read(filename)? {
        let envelope = KeyEnvelope::deserialize(&bytes)?;
        let k_intermediate_bytes =
            Zeroizing::new(keystore.open_sealed(ad, &envelope.wrapped_k_intermediate)?);
        let k_intermediate = parse_key_32(&k_intermediate_bytes, "intermediate key")?;
        Ok(SecretBox::init_with(|| k_intermediate))
    } else {
        let mut k_intermediate = Zeroizing::new([0u8; 32]);
        getrandom::fill(k_intermediate.as_mut())
            .map_err(|err| StoreError::Crypto(format!("rng failure: {err}")))?;
        let wrapped = keystore.seal(ad, k_intermediate.as_ref())?;
        let envelope = KeyEnvelope::new(wrapped, now);
        let bytes = envelope.serialize()?;
        blob_store.write_atomic(filename, &bytes)?;
        let key_copy = *k_intermediate;
        Ok(SecretBox::init_with(move || key_copy))
    }
}

fn parse_key_32(bytes: &[u8], label: &str) -> StoreResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(StoreError::InvalidEnvelope(format!(
            "{label} length mismatch: expected 32, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
