//! Key envelope initialization helpers.
//!
//! Each consumer (`CredentialStore`, `OrbPcpStore`, …) calls
//! [`init_or_open_envelope_key`] once at startup with its own envelope
//! filename and associated-data namespace, producing an in-memory
//! intermediate key bound to that consumer's vault.
//!
//! Consumers MUST use distinct `(envelope_filename, associated_data)` pairs
//! so a compromise of one envelope does not leak another consumer's key.

use rand::{rngs::OsRng, RngCore};
use secrecy::SecretBox;
use zeroize::Zeroizing;

use crate::envelope::KeyEnvelope;
use crate::error::{StoreError, StoreResult};
use crate::lock::LockGuard;
use crate::traits::{AtomicBlobStore, Keystore};

/// Opens (or creates) a [`KeyEnvelope`] at `envelope_filename` and returns
/// the unsealed 32-byte intermediate key wrapped in a [`SecretBox`].
///
/// On first call the function generates a random key, seals it with
/// `keystore` (under `associated_data`), and persists the envelope via
/// `blob_store`. On subsequent calls it loads and unseals the existing
/// envelope.
///
/// # Errors
///
/// Returns an error if the envelope cannot be read, decrypted, parsed, or
/// persisted.
pub fn init_or_open_envelope_key(
    keystore: &dyn Keystore,
    blob_store: &dyn AtomicBlobStore,
    envelope_filename: &str,
    associated_data: &[u8],
    _lock: &LockGuard,
    now: u64,
) -> StoreResult<SecretBox<[u8; 32]>> {
    if let Some(bytes) = blob_store.read(envelope_filename.to_string())? {
        let envelope = KeyEnvelope::deserialize(&bytes)?;
        let wrapped_k_intermediate = envelope.wrapped_k_intermediate.clone();
        let k_intermediate_bytes = Zeroizing::new(
            keystore.open_sealed(associated_data.to_vec(), wrapped_k_intermediate)?,
        );
        let k_intermediate =
            parse_key_32(k_intermediate_bytes.as_slice(), "K_intermediate")?;
        Ok(SecretBox::init_with(|| k_intermediate))
    } else {
        let k_intermediate = random_key();
        // The key needs to be temporarily heap-allocated to bridge through
        // the keystore trait. The temporary copy is dropped immediately.
        let wrapped_k_intermediate =
            keystore.seal(associated_data.to_vec(), k_intermediate.to_vec())?;
        let envelope = KeyEnvelope::new(wrapped_k_intermediate, now);
        let bytes = envelope.serialize()?;
        blob_store.write_atomic(envelope_filename.to_string(), bytes)?;
        Ok(SecretBox::init_with(|| k_intermediate))
    }
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
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
