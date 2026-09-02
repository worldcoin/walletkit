//! Sealed key envelope persisted via [`AtomicBlobStore`].
//!
//! A 32-byte intermediate key is sealed by a host-provided [`KeySealer`] and
//! persisted as a CBOR-serialized [`KeyEnvelope`]. On subsequent runs the
//! envelope is read, unsealed, and the key returned in a [`SecretBox`].
//!
//! Each consumer chooses its own filename and sealing context so
//! independent vaults (e.g. credential vault and `OrbPcpStore`) cannot share
//! intermediate keys.

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{StoreError, StoreResult};
use crate::lock::Lock;
use crate::traits::{AtomicBlobStore, KeySealer};

const ENVELOPE_VERSION: u32 = 1;

/// CBOR-serialized envelope holding a sealed 32-byte intermediate key.
///
/// On-disk layout is byte-stable: changing field order, names, or types
/// breaks existing user databases.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyEnvelope {
    pub(crate) version: u32,
    pub(crate) wrapped_k_intermediate: Vec<u8>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
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
/// On first run, generates a fresh 32-byte key, seals it with `key_sealer`
/// bound to `context`, persists the envelope at `filename` via
/// `blob_store`, and returns the unsealed key.
///
/// On subsequent runs, reads the envelope at `filename`, opens it under
/// `key_sealer` bound to `context`, and returns the unsealed key.
///
/// `lock` is acquired internally to serialize the read-open / generate-write
/// sequence across processes, and released before this returns.
///
/// # Errors
///
/// Propagates errors from the lock, key sealer, blob store, CBOR codec, or
/// RNG.
pub async fn init_or_open_envelope_key(
    key_sealer: &dyn KeySealer,
    blob_store: &dyn AtomicBlobStore,
    lock: &Lock,
    filename: &str,
    context: &[u8],
    now: u64,
) -> StoreResult<SecretBox<[u8; 32]>> {
    let _guard = lock.lock()?;
    if let Some(bytes) = blob_store.read(filename.to_string()).await? {
        let envelope = KeyEnvelope::deserialize(&bytes)?;
        let k_intermediate_bytes = Zeroizing::new(
            key_sealer
                .unseal(context.to_vec(), envelope.wrapped_k_intermediate.clone())
                .await?,
        );
        let k_intermediate = parse_key_32(&k_intermediate_bytes, "intermediate key")?;
        Ok(SecretBox::init_with(|| k_intermediate))
    } else {
        let mut k_intermediate = Zeroizing::new([0u8; 32]);
        getrandom::fill(k_intermediate.as_mut())
            .map_err(|err| StoreError::Crypto(format!("rng failure: {err}")))?;
        // `key_sealer.seal` borrows the plaintext, so `k_intermediate` is
        // never copied into an un-zeroized `Vec<u8>` at this layer. A
        // `KeySealer` bridging to an owned-only interface (e.g. a uniffi
        // callback like walletkit-core's `KeySealer`) still needs one
        // owned copy to cross that boundary; that is an accepted,
        // uniffi-imposed limitation (callback interfaces only support
        // pass-by-value), not something fixable from this layer.
        let wrapped = key_sealer.seal(context, k_intermediate.as_slice()).await?;
        let envelope = KeyEnvelope::new(wrapped, now);
        let bytes = envelope.serialize()?;
        blob_store.write_atomic(filename.to_string(), bytes).await?;
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

#[cfg(test)]
mod tests {
    use super::{init_or_open_envelope_key, KeyEnvelope};
    use crate::{AtomicBlobStore, KeySealer, Lock, StoreError, StoreResult};
    use secrecy::ExposeSecret;
    use std::sync::Mutex;

    #[test]
    fn test_key_envelope_round_trip() {
        let envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        let bytes = envelope.serialize().expect("serialize");
        let decoded = KeyEnvelope::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.wrapped_k_intermediate, vec![1, 2, 3]);
        assert_eq!(decoded.created_at, 123);
        assert_eq!(decoded.updated_at, 123);
    }

    #[test]
    fn test_key_envelope_cbor_bytes_frozen() {
        // Frozen CBOR encoding for the canonical envelope. Round-trip alone
        // doesn't catch field-order or type drift; this byte-level check
        // does. Updating this hex without an on-disk format review breaks
        // every existing user database.
        let envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        let bytes = envelope.serialize().expect("serialize");
        // CBOR map of 4 entries: version=1, wrapped_k_intermediate=[1,2,3],
        // created_at=123, updated_at=123. Reproducible from the struct;
        // hex captured by serializing the canonical envelope above.
        let expected = hex::decode(
            "a46776657273696f6e0176777261707065645f6b5f696e7465726d656469617465830102036a637265617465645f6174187b6a757064617465645f6174187b",
        ).expect("decode hex");
        assert_eq!(
            bytes, expected,
            "KeyEnvelope CBOR layout changed; on-disk envelope format would drift"
        );
    }

    #[test]
    fn test_key_envelope_unsupported_version() {
        let mut envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        envelope.version = 99;
        let bytes = envelope.serialize().expect("serialize");
        match KeyEnvelope::deserialize(&bytes) {
            Err(StoreError::UnsupportedEnvelopeVersion(v)) => assert_eq!(v, 99),
            Err(err) => panic!("expected UnsupportedEnvelopeVersion, got: {err}"),
            Ok(_) => panic!("expected UnsupportedEnvelopeVersion, got Ok"),
        }
    }

    /// Stub `KeySealer` that XORs with a fixed pad. Good enough to verify
    /// the seal -> persist -> unseal round-trip on the envelope wiring.
    struct XorKeySealer {
        pad: [u8; 32],
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl KeySealer for XorKeySealer {
        async fn seal(
            &self,
            _context: &[u8],
            plaintext: &[u8],
        ) -> StoreResult<Vec<u8>> {
            Ok(plaintext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.pad[i % 32])
                .collect())
        }
        async fn unseal(
            &self,
            _context: Vec<u8>,
            ciphertext: Vec<u8>,
        ) -> StoreResult<Vec<u8>> {
            Ok(ciphertext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.pad[i % 32])
                .collect())
        }
    }

    struct InMemoryBlobs {
        inner: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }
    impl InMemoryBlobs {
        fn new() -> Self {
            Self {
                inner: Mutex::new(std::collections::HashMap::new()),
            }
        }
    }
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl AtomicBlobStore for InMemoryBlobs {
        async fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>> {
            Ok(self.inner.lock().unwrap().get(&path).cloned())
        }
        async fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()> {
            self.inner.lock().unwrap().insert(path, bytes);
            Ok(())
        }
        async fn delete(&self, path: String) -> StoreResult<()> {
            self.inner.lock().unwrap().remove(&path);
            Ok(())
        }
    }

    #[tokio::test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_init_or_open_envelope_key_round_trip() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let lock_path = dir.path().join("envelope.lock");
        let lock = Lock::open(&lock_path).expect("open lock");

        let key_sealer = XorKeySealer { pad: [0xAA; 32] };
        let blob_store = InMemoryBlobs::new();
        let key_a = init_or_open_envelope_key(
            &key_sealer,
            &blob_store,
            &lock,
            "k.bin",
            b"test-ad",
            100,
        )
        .await
        .expect("init");
        let key_b = init_or_open_envelope_key(
            &key_sealer,
            &blob_store,
            &lock,
            "k.bin",
            b"test-ad",
            200,
        )
        .await
        .expect("re-open");

        assert_eq!(key_a.expose_secret(), key_b.expose_secret());
    }
}
