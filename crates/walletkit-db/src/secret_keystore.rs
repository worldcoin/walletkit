//! Synchronous AEAD using a host-supplied secret. No browser callbacks.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use secrecy::{ExposeSecret, SecretBox};

use crate::{Keystore, StoreError, StoreResult};

// Sealed bytes: version (1 byte) || XChaCha nonce (24 bytes) || ciphertext/tag.
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;

/// Software keystore. The host must supply the same secret on every unlock.
/// This does not provide hardware-bound key isolation.
pub struct SecretKeystore {
    key: SecretBox<[u8; 32]>,
}

impl SecretKeystore {
    /// Takes ownership of the host's wrapping key.
    #[must_use]
    pub const fn new(key: SecretBox<[u8; 32]>) -> Self {
        Self { key }
    }

    fn seal_with_nonce(
        &self,
        aad: &[u8],
        plaintext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> StoreResult<Vec<u8>> {
        let ciphertext = XChaCha20Poly1305::new(self.key.expose_secret().into())
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| StoreError::Crypto("secret keystore seal failed".into()))?;
        let mut result = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        result.push(VERSION);
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
}

impl Keystore for SecretKeystore {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>> {
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| StoreError::Crypto(e.to_string()))?;
        self.seal_with_nonce(aad, plaintext, &nonce)
    }

    fn open_sealed(&self, aad: Vec<u8>, ciphertext: Vec<u8>) -> StoreResult<Vec<u8>> {
        if ciphertext.len() < 1 + NONCE_LEN + 16 || ciphertext[0] != VERSION {
            return Err(StoreError::InvalidEnvelope(
                "invalid secret keystore payload".into(),
            ));
        }
        XChaCha20Poly1305::new(self.key.expose_secret().into())
            .decrypt(
                XNonce::from_slice(&ciphertext[1..=NONCE_LEN]),
                Payload {
                    msg: &ciphertext[1 + NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                StoreError::Crypto("secret keystore authentication failed".into())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_bytes_are_frozen() {
        let ks = SecretKeystore::new(SecretBox::init_with(|| [7; 32]));
        let sealed = ks.seal_with_nonce(b"account", b"secret", &[9; 24]).unwrap();
        assert_eq!(hex::encode(sealed), "01090909090909090909090909090909090909090909090909cd1781f819deeeac4cc72e0b84d4612cb2daa5dedca9");
    }

    #[test]
    fn authenticates_key_aad_and_ciphertext() {
        let ks = SecretKeystore::new(SecretBox::init_with(|| [7; 32]));
        let sealed = ks.seal(b"account", b"secret").unwrap();
        assert_eq!(
            ks.open_sealed(b"account".to_vec(), sealed.clone()).unwrap(),
            b"secret"
        );
        assert!(ks.open_sealed(b"other".to_vec(), sealed.clone()).is_err());
        let other = SecretKeystore::new(SecretBox::init_with(|| [8; 32]));
        assert!(other
            .open_sealed(b"account".to_vec(), sealed.clone())
            .is_err());
        let mut tampered = sealed;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(ks.open_sealed(b"account".to_vec(), tampered).is_err());
        assert!(ks.open_sealed(vec![], vec![]).is_err());
    }
}
