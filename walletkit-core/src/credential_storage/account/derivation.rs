//! Key derivation functions for World ID accounts.
//!
//! This module provides deterministic key derivation for:
//!
//! - Account ID from vault key
//! - Issuer blinding factors
//! - Session blinding factors (session R)
//! - Action scope and request ID computation

use sha2::{Digest, Sha256};

use crate::credential_storage::{vault::VaultKey, AccountId};

// Domain Separation Labels

/// Label for deriving account ID from vault key.
const LABEL_ACCOUNT_ID: &[u8] = b"worldid:account-id";

/// Label for deriving issuer blinding factors.
const LABEL_ISSUER_BLIND: &[u8] = b"worldid:issuer-blind";

/// Label for deriving session blinding factors.
const LABEL_SESSION_R: &[u8] = b"worldid:session-r";

/// Label for computing action scope.
const LABEL_ACTION_SCOPE: &[u8] = b"worldid:action-scope";

/// Label for computing request ID.
const LABEL_PROOF_REQUEST: &[u8] = b"worldid:proof-request";

// Account ID Derivation

/// Derives the account ID from the vault key.
///
/// The account ID uniquely identifies a World ID account and is computed as:
/// ```text
/// account_id = SHA256("worldid:account-id" || K_vault)
/// ```
///
/// # Arguments
///
/// * `vault_key` - The vault encryption key
///
/// # Returns
///
/// A 32-byte account ID.
#[must_use]
pub fn derive_account_id(vault_key: &VaultKey) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_ACCOUNT_ID);
    hasher.update(vault_key.as_bytes());
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    AccountId::new(bytes)
}

// Issuer Blind Derivation

/// Derives the issuer blinding factor for a specific issuer schema.
///
/// This is used to blind credentials during issuance to prevent correlation
/// even among issuers or in case of leaked credentials.
///
/// The blinding factor is computed using HKDF-SHA256:
/// ```text
/// issuer_blind = HKDF-Expand(
///     prk = issuer_blind_seed,
///     info = "worldid:issuer-blind" || issuer_schema_id (8 bytes LE),
///     len = 32
/// )
/// ```
///
/// # Arguments
///
/// * `issuer_blind_seed` - The 32-byte seed stored in account state
/// * `issuer_schema_id` - The issuer schema ID
///
/// # Returns
///
/// A 32-byte blinding factor.
#[must_use]
pub fn derive_issuer_blind(
    issuer_blind_seed: &[u8; 32],
    issuer_schema_id: u64,
) -> [u8; 32] {
    // Build info: label || issuer_schema_id
    let mut info = Vec::with_capacity(LABEL_ISSUER_BLIND.len() + 8);
    info.extend_from_slice(LABEL_ISSUER_BLIND);
    info.extend_from_slice(&issuer_schema_id.to_le_bytes());

    hkdf_expand_sha256(issuer_blind_seed, &info)
}

// Session R Derivation

/// Derives the session blinding factor for a specific RP and action.
///
/// This is used in proof generation to provide session binding while
/// maintaining unlinkability between different sessions.
///
/// The blinding factor is computed using HKDF-SHA256:
/// ```text
/// session_r = HKDF-Expand(
///     prk = session_blind_seed,
///     info = "worldid:session-r" || rp_id || action_id,
///     len = 32
/// )
/// ```
///
/// # Arguments
///
/// * `session_blind_seed` - The 32-byte seed stored in account state
/// * `rp_id` - The 32-byte relying party identifier
/// * `action_id` - The 32-byte action identifier
///
/// # Returns
///
/// A 32-byte blinding factor.
#[must_use]
pub fn derive_session_r(
    session_blind_seed: &[u8; 32],
    rp_id: &[u8; 32],
    action_id: &[u8; 32],
) -> [u8; 32] {
    // Build info: label || rp_id || action_id
    let mut info = Vec::with_capacity(LABEL_SESSION_R.len() + 64);
    info.extend_from_slice(LABEL_SESSION_R);
    info.extend_from_slice(rp_id);
    info.extend_from_slice(action_id);

    hkdf_expand_sha256(session_blind_seed, &info)
}

// Action Scope & Request ID

/// Computes the action scope from RP ID and action ID.
///
/// The action scope uniquely identifies an action context:
/// ```text
/// action_scope = SHA256("worldid:action-scope" || rp_id || action_id)
/// ```
///
/// # Arguments
///
/// * `rp_id` - The 32-byte relying party identifier
/// * `action_id` - The 32-byte action identifier
///
/// # Returns
///
/// A 32-byte action scope hash.
#[must_use]
pub fn compute_action_scope(rp_id: &[u8; 32], action_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_ACTION_SCOPE);
    hasher.update(rp_id);
    hasher.update(action_id);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    bytes
}

/// Computes the request ID from signed request bytes.
///
/// The request ID uniquely identifies a proof request:
/// ```text
/// request_id = SHA256("worldid:proof-request" || signed_request_bytes)
/// ```
///
/// # Arguments
///
/// * `signed_request_bytes` - The signed proof request
///
/// # Returns
///
/// A 32-byte request ID hash.
#[must_use]
pub fn compute_request_id(signed_request_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_PROOF_REQUEST);
    hasher.update(signed_request_bytes);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    bytes
}

// Random Generation

/// Generates random seeds for a new account.
///
/// # Returns
///
/// A tuple of (`issuer_blind_seed`, `session_blind_seed`).
///
/// # Panics
///
/// Panics if the system's random number generator fails.
#[must_use]
pub fn generate_blind_seeds() -> ([u8; 32], [u8; 32]) {
    let mut issuer_blind_seed = [0u8; 32];
    let mut session_blind_seed = [0u8; 32];

    getrandom::getrandom(&mut issuer_blind_seed).expect("getrandom failed");
    getrandom::getrandom(&mut session_blind_seed).expect("getrandom failed");

    (issuer_blind_seed, session_blind_seed)
}

/// Generates a random device ID.
///
/// # Returns
///
/// A 16-byte random device identifier.
///
/// # Panics
///
/// Panics if the system's random number generator fails.
#[must_use]
pub fn generate_device_id() -> [u8; 16] {
    let mut device_id = [0u8; 16];
    getrandom::getrandom(&mut device_id).expect("getrandom failed");
    device_id
}

/// HKDF-Expand using SHA-256 to derive a 32-byte key.
///
/// This is a simplified version that assumes:
/// - The PRK (pseudo-random key) is already 32 bytes
/// - We only need 32 bytes of output (one block)
///
/// # Arguments
///
/// * `prk` - The pseudo-random key (32 bytes)
/// * `info` - Context and application specific information
///
/// # Returns
///
/// A 32-byte derived key.
fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    // HKDF-Expand for one block (32 bytes):
    // T(1) = HMAC-Hash(PRK, info || 0x01)
    let mut hmac_input = Vec::with_capacity(info.len() + 1);
    hmac_input.extend_from_slice(info);
    hmac_input.push(0x01);

    hmac_sha256(prk, &hmac_input)
}

/// HMAC-SHA256 implementation.
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `message` - The message to authenticate
///
/// # Returns
///
/// A 32-byte HMAC tag.
fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;

    // Prepare key (pad or hash if necessary)
    let mut k_padded = [0u8; BLOCK_SIZE];
    if key.len() <= BLOCK_SIZE {
        k_padded[..key.len()].copy_from_slice(key);
    } else {
        let hash = Sha256::digest(key);
        k_padded[..32].copy_from_slice(&hash);
    }

    // Compute inner and outer padded keys
    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_pad[i] ^= k_padded[i];
        outer_pad[i] ^= k_padded[i];
    }

    // Inner hash: H(K XOR ipad || message)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner_pad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H(K XOR opad || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer_pad);
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_account_id() {
        let vault_key = VaultKey::from_bytes([0x42u8; 32]);
        let id1 = derive_account_id(&vault_key);
        let id2 = derive_account_id(&vault_key);
        assert_eq!(id1, id2);

        // Different keys produce different IDs
        let key2 = VaultKey::from_bytes([0x11u8; 32]);
        let id3 = derive_account_id(&key2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_derive_issuer_blind() {
        let seed = [0xABu8; 32];
        let blind1 = derive_issuer_blind(&seed, 42);
        let blind2 = derive_issuer_blind(&seed, 42);
        assert_eq!(blind1, blind2);

        // Different schemas produce different blinds
        let blind3 = derive_issuer_blind(&seed, 1);
        assert_ne!(blind1, blind3);

        // Different seeds produce different blinds
        let seed2 = [0x11u8; 32];
        let blind4 = derive_issuer_blind(&seed2, 42);
        assert_ne!(blind1, blind4);
    }

    #[test]
    fn test_derive_session_r() {
        let seed = [0xCDu8; 32];
        let rp_id = [0x11u8; 32];
        let action_id = [0x22u8; 32];
        let r1 = derive_session_r(&seed, &rp_id, &action_id);
        let r2 = derive_session_r(&seed, &rp_id, &action_id);
        assert_eq!(r1, r2);

        // Different RP produces different R
        let rp_id2 = [0x33u8; 32];
        let r3 = derive_session_r(&seed, &rp_id2, &action_id);
        assert_ne!(r1, r3);

        // Different action produces different R
        let action_id2 = [0x44u8; 32];
        let r4 = derive_session_r(&seed, &rp_id, &action_id2);
        assert_ne!(r1, r4);
    }

    #[test]
    fn test_hmac_sha256_known_vector() {
        // Test vector from RFC 4231
        let mut key = [0u8; 32];
        key[..20].copy_from_slice(&[0x0b; 20]);
        let message = b"Hi There";
        let result = hmac_sha256(&key, message);
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce,
            0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(result, expected);
    }
}
