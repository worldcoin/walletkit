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
use crate::lock::Lock;
use crate::traits::{AtomicBlobStore, Keystore};

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
/// On first run, generates a fresh 32-byte key, seals it under `keystore`
/// authenticated by `ad`, persists the envelope at `filename` via
/// `blob_store`, and returns the unsealed key.
///
/// On subsequent runs, reads the envelope at `filename`, opens it under
/// `keystore` authenticated by `ad`, and returns the unsealed key.
///
/// `lock` is acquired internally to serialize the read-open / generate-write
/// sequence across processes, and released before this returns.
///
/// # Errors
///
/// Propagates errors from the lock, keystore, blob store, CBOR codec, or
/// RNG.
pub fn init_or_open_envelope_key(
    keystore: &dyn Keystore,
    blob_store: &dyn AtomicBlobStore,
    lock: &Lock,
    filename: &str,
    ad: &[u8],
    now: u64,
) -> StoreResult<SecretBox<[u8; 32]>> {
    let _guard = lock.lock()?;
    if let Some(bytes) = blob_store.read(filename.to_string())? {
        let envelope = KeyEnvelope::deserialize(&bytes)?;
        let k_intermediate_bytes = Zeroizing::new(
            keystore
                .open_sealed(ad.to_vec(), envelope.wrapped_k_intermediate.clone())?,
        );
        let k_intermediate = parse_key_32(&k_intermediate_bytes, "intermediate key")?;
        Ok(SecretBox::init_with(|| k_intermediate))
    } else {
        let mut k_intermediate = Zeroizing::new([0u8; 32]);
        getrandom::fill(k_intermediate.as_mut())
            .map_err(|err| StoreError::Crypto(format!("rng failure: {err}")))?;
        // TODO: `keystore.seal(_, Vec<u8>)` requires the plaintext as an
        // owned heap allocation because the trait shape matches
        // walletkit-core's uniffi `DeviceKeystore` so the adapter stays
        // zero-copy. That `Vec<u8>` is NOT zeroized on drop — key bytes
        // can linger in the allocator's freelist. Improve by either
        // (a) changing the trait to take a stack reference and updating
        // the host bridges, or (b) wrapping the `to_vec()` result in
        // `Zeroizing` and ensuring `Keystore` impls don't clone it.
        let wrapped = keystore.seal(ad.to_vec(), k_intermediate.to_vec())?;
        let envelope = KeyEnvelope::new(wrapped, now);
        let bytes = envelope.serialize()?;
        blob_store.write_atomic(filename.to_string(), bytes)?;
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
    use crate::{AtomicBlobStore, Keystore, Lock, StoreError, StoreResult};
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

    /// Stub `Keystore` that XORs with a fixed pad. Good enough to verify
    /// the seal → persist → open round-trip on the envelope wiring.
    struct XorKeystore {
        pad: [u8; 32],
    }

    impl Keystore for XorKeystore {
        fn seal(&self, _ad: Vec<u8>, plaintext: Vec<u8>) -> StoreResult<Vec<u8>> {
            Ok(plaintext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.pad[i % 32])
                .collect())
        }
        fn open_sealed(
            &self,
            _ad: Vec<u8>,
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
    impl AtomicBlobStore for InMemoryBlobs {
        fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>> {
            Ok(self.inner.lock().unwrap().get(&path).cloned())
        }
        fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()> {
            self.inner.lock().unwrap().insert(path, bytes);
            Ok(())
        }
        fn delete(&self, path: String) -> StoreResult<()> {
            self.inner.lock().unwrap().remove(&path);
            Ok(())
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_init_or_open_envelope_key_round_trip() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let lock_path = dir.path().join("envelope.lock");
        let lock = Lock::open(&lock_path).expect("open lock");

        let keystore = XorKeystore { pad: [0xAA; 32] };
        let blob_store = InMemoryBlobs::new();
        let key_a = init_or_open_envelope_key(
            &keystore,
            &blob_store,
            &lock,
            "k.bin",
            b"test-ad",
            100,
        )
        .expect("init");
        let key_b = init_or_open_envelope_key(
            &keystore,
            &blob_store,
            &lock,
            "k.bin",
            b"test-ad",
            200,
        )
        .expect("re-open");

        assert_eq!(key_a.expose_secret(), key_b.expose_secret());
    }
}
