//! Test helpers for credential storage.

use std::{collections::HashMap, sync::Mutex};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

use super::{error::StorageError, traits::DeviceKeystore, AtomicBlobStore};

pub struct InMemoryKeystore {
    key: [u8; 32],
}

impl InMemoryKeystore {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }
}

impl Default for InMemoryKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceKeystore for InMemoryKeystore {
    fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|err| StorageError::Crypto(err.to_string()))?;
        let mut out = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open(
        &self,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        if ciphertext.len() < 24 {
            return Err(StorageError::InvalidEnvelope(
                "keystore ciphertext too short".to_string(),
            ));
        }
        let (nonce_bytes, payload) = ciphertext.split_at(24);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(
                XNonce::from_slice(nonce_bytes),
                Payload {
                    msg: payload,
                    aad: associated_data,
                },
            )
            .map_err(|err| StorageError::Crypto(err.to_string()))
    }
}

pub struct InMemoryBlobStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Self {
        Self {
            blobs: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicBlobStore for InMemoryBlobStore {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self
            .blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?;
        Ok(guard.get(path).cloned())
    }

    fn write_atomic(&self, path: &str, bytes: &[u8]) -> Result<(), StorageError> {
        self.blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?
            .insert(path.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<(), StorageError> {
        self.blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?
            .remove(path);
        Ok(())
    }
}
