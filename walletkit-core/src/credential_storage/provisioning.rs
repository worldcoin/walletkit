//! Vault provisioning envelope for adding new authenticators.
//!
//! This module implements the encrypted provisioning envelope that enables
//! secure transfer of vault capability to a new device.
//!
//! # Security Model
//!
//! The provisioning envelope uses X25519 ECDH key agreement combined with
//! XChaCha20-Poly1305 AEAD encryption (similar to libsodium's `crypto_box_seal`):
//!
//! 1. Sender generates an ephemeral X25519 key pair
//! 2. ECDH is performed between ephemeral secret and recipient's public key
//! 3. Shared secret is derived using HKDF-SHA256
//! 4. Payload is encrypted with XChaCha20-Poly1305
//!
//! # Envelope Format
//!
//! ```text
//! version: u32 (4 bytes)
//! ephemeral_public: [u8; 32] (32 bytes)
//! nonce: [u8; 24] (24 bytes)
//! ciphertext: [u8; ...] (variable length, includes auth tag)
//! ```
//!
//! # Payload Contents
//!
//! The encrypted payload contains:
//! - `vault_key`: 32 bytes
//! - `issuer_blind_seed`: 32 bytes
//! - `session_blind_seed`: 32 bytes

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// For generating random keys
struct OsRng;

impl rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|_| rand_core::Error::new("getrandom failed"))
    }
}

impl rand_core::CryptoRng for OsRng {}
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::credential_storage::{
    vault::{VaultKey, NONCE_SIZE},
    AccountId, StorageError, StorageResult, VaultProvisioningEnvelope,
};

// Constants

/// Current provisioning envelope format version.
pub const PROVISIONING_VERSION: u32 = 1;

/// Size of X25519 public key.
const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 secret key.
const X25519_SECRET_KEY_SIZE: usize = 32;

/// Label for HKDF key derivation.
const HKDF_LABEL: &[u8] = b"worldid:provisioning-envelope";

/// Label for AEAD associated data.
const AEAD_LABEL: &[u8] = b"worldid:vault-provisioning";

/// Minimum envelope size (version + ephemeral pubkey + nonce + auth tag).
const MIN_ENVELOPE_SIZE: usize = 4 + X25519_PUBLIC_KEY_SIZE + NONCE_SIZE + 16;


/// Contents of a decrypted provisioning envelope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ProvisioningPayload {
    /// The vault encryption key.
    #[zeroize(skip)]
    pub vault_key: VaultKey,
    /// Seed for deriving issuer blinding factors.
    pub issuer_blind_seed: [u8; 32],
    /// Seed for deriving session blinding factors.
    pub session_blind_seed: [u8; 32],
}

impl std::fmt::Debug for ProvisioningPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningPayload")
            .field("vault_key", &"[REDACTED]")
            .field("issuer_blind_seed", &"[REDACTED]")
            .field("session_blind_seed", &"[REDACTED]")
            .finish()
    }
}

/// Internal serialized payload format.
#[derive(Serialize, Deserialize)]
struct SerializedPayload {
    vault_key: [u8; 32],
    issuer_blind_seed: [u8; 32],
    session_blind_seed: [u8; 32],
}

// Device Key Pair

/// A device's X25519 key pair for receiving provisioning envelopes.
///
/// This represents the recipient's long-term device key pair.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceKeyPair {
    /// Private key (secret).
    secret: [u8; X25519_SECRET_KEY_SIZE],
    /// Public key.
    #[zeroize(skip)]
    public: [u8; X25519_PUBLIC_KEY_SIZE],
}

impl DeviceKeyPair {
    /// Generates a new random device key pair.
    ///
    /// # Panics
    ///
    /// Panics if the system's random number generator fails.
    #[must_use]
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; X25519_SECRET_KEY_SIZE];
        getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");

        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);

        Self {
            secret: secret_bytes,
            public: *public.as_bytes(),
        }
    }

    /// Creates a device key pair from existing secret key bytes.
    #[must_use]
    pub fn from_secret(secret_bytes: [u8; X25519_SECRET_KEY_SIZE]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);

        Self {
            secret: secret_bytes,
            public: *public.as_bytes(),
        }
    }

    /// Returns the public key bytes.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.public
    }

    /// Returns the secret key bytes.
    #[must_use]
    pub const fn secret_key(&self) -> &[u8; X25519_SECRET_KEY_SIZE] {
        &self.secret
    }
}

impl std::fmt::Debug for DeviceKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKeyPair")
            .field("secret", &"[REDACTED]")
            .field("public", &hex::encode(self.public))
            .finish()
    }
}


impl VaultProvisioningEnvelope {
    /// Creates a provisioning envelope for a new device.
    ///
    /// # Arguments
    ///
    /// * `vault_key` - The vault encryption key to transfer
    /// * `issuer_blind_seed` - The issuer blinding seed
    /// * `session_blind_seed` - The session blinding seed
    /// * `recipient_device_pubkey` - The recipient's X25519 public key (32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The recipient public key is not 32 bytes
    /// - Encryption fails
    pub fn export(
        vault_key: &VaultKey,
        issuer_blind_seed: &[u8; 32],
        session_blind_seed: &[u8; 32],
        recipient_device_pubkey: &[u8],
    ) -> StorageResult<Self> {
        // Validate recipient public key length
        if recipient_device_pubkey.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(StorageError::invalid_input(
                "recipient_device_pubkey",
                format!(
                    "Expected {} bytes, got {}",
                    X25519_PUBLIC_KEY_SIZE,
                    recipient_device_pubkey.len()
                ),
            ));
        }

        let recipient_pubkey: [u8; 32] = recipient_device_pubkey
            .try_into()
            .expect("length already validated");
        let recipient_public = PublicKey::from(recipient_pubkey);

        // Generate ephemeral key pair
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform ECDH
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        // Derive encryption key using HKDF
        let encryption_key = derive_encryption_key(
            shared_secret.as_bytes(),
            ephemeral_public.as_bytes(),
            &recipient_pubkey,
        )?;

        // Serialize payload
        let serialized = SerializedPayload {
            vault_key: *vault_key.as_bytes(),
            issuer_blind_seed: *issuer_blind_seed,
            session_blind_seed: *session_blind_seed,
        };

        let plaintext = bincode::serialize(&serialized).map_err(|e| {
            StorageError::serialization(format!("Failed to serialize provisioning payload: {e}"))
        })?;

        // Encrypt
        let (ciphertext, nonce) = encrypt_envelope(&encryption_key, &plaintext)?;

        // Build envelope: version || ephemeral_public || nonce || ciphertext
        let mut envelope = Vec::with_capacity(4 + 32 + NONCE_SIZE + ciphertext.len());
        envelope.extend_from_slice(&PROVISIONING_VERSION.to_le_bytes());
        envelope.extend_from_slice(ephemeral_public.as_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        Ok(Self(envelope))
    }

    /// Decrypts a provisioning envelope using the device's private key.
    ///
    /// # Arguments
    ///
    /// * `device_secret_key` - The device's X25519 private key (32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret key is not 32 bytes
    /// - The envelope format is invalid
    /// - Decryption fails
    pub fn import(&self, device_secret_key: &[u8]) -> StorageResult<ProvisioningPayload> {
        // Validate secret key length
        if device_secret_key.len() != X25519_SECRET_KEY_SIZE {
            return Err(StorageError::invalid_input(
                "device_secret_key",
                format!(
                    "Expected {} bytes, got {}",
                    X25519_SECRET_KEY_SIZE,
                    device_secret_key.len()
                ),
            ));
        }

        if self.0.len() < MIN_ENVELOPE_SIZE {
            return Err(StorageError::corrupted("Provisioning envelope too short"));
        }

        // Parse envelope
        let version = u32::from_le_bytes(
            self.0[0..4]
                .try_into()
                .map_err(|_| StorageError::corrupted("Invalid version bytes"))?,
        );

        if version > PROVISIONING_VERSION {
            return Err(StorageError::InvalidVersion {
                expected: PROVISIONING_VERSION,
                found: version,
            });
        }

        let ephemeral_public_bytes: [u8; 32] = self.0[4..36]
            .try_into()
            .map_err(|_| StorageError::corrupted("Invalid ephemeral public key"))?;

        let nonce: [u8; NONCE_SIZE] = self.0[36..36 + NONCE_SIZE]
            .try_into()
            .map_err(|_| StorageError::corrupted("Invalid nonce"))?;

        let ciphertext = &self.0[36 + NONCE_SIZE..];

        // Reconstruct device's key pair
        let device_secret_bytes: [u8; 32] = device_secret_key
            .try_into()
            .expect("length already validated");
        let device_secret = StaticSecret::from(device_secret_bytes);
        let device_public = PublicKey::from(&device_secret);

        // Parse ephemeral public key
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);

        // Perform ECDH
        let shared_secret = device_secret.diffie_hellman(&ephemeral_public);

        // Derive decryption key using HKDF
        let decryption_key = derive_encryption_key(
            shared_secret.as_bytes(),
            &ephemeral_public_bytes,
            device_public.as_bytes(),
        )?;

        // Decrypt
        let plaintext = decrypt_envelope(&decryption_key, &nonce, ciphertext)?;

        // Deserialize
        let serialized: SerializedPayload = bincode::deserialize(&plaintext).map_err(|e| {
            StorageError::serialization(format!(
                "Failed to deserialize provisioning payload: {e}"
            ))
        })?;

        Ok(ProvisioningPayload {
            vault_key: VaultKey::from_bytes(serialized.vault_key),
            issuer_blind_seed: serialized.issuer_blind_seed,
            session_blind_seed: serialized.session_blind_seed,
        })
    }

    /// Imports using a `DeviceKeyPair`.
    pub fn import_with_keypair(
        &self,
        device_keypair: &DeviceKeyPair,
    ) -> StorageResult<ProvisioningPayload> {
        self.import(device_keypair.secret_key())
    }

    /// Returns the account ID that will be derived from the vault key in this envelope.
    ///
    /// This requires decryption but is provided as a convenience method.
    pub fn account_id(&self, device_secret_key: &[u8]) -> StorageResult<AccountId> {
        let payload = self.import(device_secret_key)?;
        Ok(crate::credential_storage::account::derive_account_id(
            &payload.vault_key,
        ))
    }
}


/// Derives an encryption key from the ECDH shared secret using HKDF.
fn derive_encryption_key(
    shared_secret: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> StorageResult<[u8; 32]> {
    // Info = label || ephemeral_public || recipient_public
    let mut info = Vec::with_capacity(HKDF_LABEL.len() + 64);
    info.extend_from_slice(HKDF_LABEL);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| StorageError::encryption("HKDF expansion failed"))?;

    Ok(key)
}

/// Generates a random nonce.
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).expect("getrandom failed");
    nonce
}

/// Encrypts the provisioning payload.
fn encrypt_envelope(
    key: &[u8; 32],
    plaintext: &[u8],
) -> StorageResult<(Vec<u8>, [u8; NONCE_SIZE])> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("key length is always 32");

    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: AEAD_LABEL,
            },
        )
        .map_err(|_| StorageError::encryption("Provisioning envelope encryption failed"))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts the provisioning payload.
fn decrypt_envelope(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> StorageResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("key length is always 32");

    let nonce = XNonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: AEAD_LABEL,
            },
        )
        .map_err(|_| StorageError::decryption("Provisioning envelope decryption failed"))?;

    Ok(plaintext)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_keypair_generation() {
        let kp1 = DeviceKeyPair::generate();
        let kp2 = DeviceKeyPair::generate();
        assert_ne!(kp1.public_key(), kp2.public_key());
        assert_eq!(kp1.public_key().len(), 32);
        let recreated = DeviceKeyPair::from_secret(*kp1.secret_key());
        assert_eq!(kp1.public_key(), recreated.public_key());
    }

    #[test]
    fn test_envelope_create_import() {
        let vault_key = VaultKey::generate();
        let issuer_blind_seed = [0x11u8; 32];
        let session_blind_seed = [0x22u8; 32];
        let recipient = DeviceKeyPair::generate();
        let envelope = VaultProvisioningEnvelope::export(&vault_key, &issuer_blind_seed, &session_blind_seed, recipient.public_key()).unwrap();
        let payload = envelope.import(recipient.secret_key()).unwrap();
        assert_eq!(payload.vault_key.as_bytes(), vault_key.as_bytes());
        assert_eq!(payload.issuer_blind_seed, issuer_blind_seed);
        assert_eq!(payload.session_blind_seed, session_blind_seed);
    }

    #[test]
    fn test_derivation_preservation() {
        let vault_key = VaultKey::generate();
        let issuer_blind_seed = [0x33u8; 32];
        let session_blind_seed = [0x44u8; 32];
        let recipient = DeviceKeyPair::generate();
        let envelope = VaultProvisioningEnvelope::export(&vault_key, &issuer_blind_seed, &session_blind_seed, recipient.public_key()).unwrap();
        let payload = envelope.import(recipient.secret_key()).unwrap();
        let extracted_id = envelope.account_id(recipient.secret_key()).unwrap();
        let expected_id = crate::credential_storage::account::derive_account_id(&vault_key);
        assert_eq!(extracted_id, expected_id);
    }
}
