//! World ID key proofs for the encrypted Auth bridge.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use p256_sign_in::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use web_time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::error::WalletKitError;

const KEY_DOMAIN: &[u8] = b"WORLD-ID/IDP/SIGN-IN-KEY/V1\0";
const PROOF_DOMAIN: &[u8] = b"WORLD-ID/IDP/KEY-PROOF/V1\0";

/// Public material proving possession of a World ID sign-in key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WorldIdKeyProof {
    /// Compressed SEC1 P-256 public key, encoded as unpadded base64url.
    pub public_key: String,
    /// Low-S DER ECDSA signature, encoded as unpadded base64url.
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    version: u8,
    issuer: String,
    ceremony_id: String,
    nonce: String,
    expires_at: i64,
}

/// Signs an Auth challenge using a key derived from the 32-byte World ID seed.
///
/// Requires user approval, but no Authenticator, credentials, or network calls.
/// `expected_issuer` must come from trusted app configuration. `challenge` is the
/// exact decoded JSON byte string from `key_proof_request.challenge`.
/// Devices restored from the same seed share this sign-in key.
///
/// # Errors
/// Rejects invalid seeds, foreign, expired, or malformed challenges, and reports
/// clock, derivation, or signing failures without including secret material.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "owned buffers give UniFFI Kotlin ByteArray and Swift Data parameters"
)]
pub fn create_world_id_key_proof(
    seed: Vec<u8>,
    challenge: Vec<u8>,
    expected_issuer: String,
) -> Result<WorldIdKeyProof, WalletKitError> {
    let seed = Zeroizing::new(seed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WalletKitError::Generic {
            error: "clock is before the Unix epoch".to_string(),
        })?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| WalletKitError::Generic {
        error: "clock exceeds the supported timestamp range".to_string(),
    })?;
    create_at(&seed, &challenge, &expected_issuer, now)
}

fn create_at(
    seed: &[u8],
    bytes: &[u8],
    expected_issuer: &str,
    now: i64,
) -> Result<WorldIdKeyProof, WalletKitError> {
    if seed.len() != 32 {
        return Err(WalletKitError::InvalidInput {
            attribute: "seed".to_string(),
            reason: "expected a 32-byte World ID seed".to_string(),
        });
    }
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(WalletKitError::InvalidInput {
            attribute: "challenge".to_string(),
            reason: "expected at most 1024 bytes of challenge JSON".to_string(),
        });
    }
    let challenge: Challenge =
        serde_json::from_slice(bytes).map_err(|_| WalletKitError::InvalidInput {
            attribute: "challenge".to_string(),
            reason: "invalid key proof challenge JSON".to_string(),
        })?;
    let issuer = reqwest::Url::parse(expected_issuer).map_err(|_| {
        WalletKitError::InvalidInput {
            attribute: "expected_issuer".to_string(),
            reason: "expected a trusted issuer origin".to_string(),
        }
    })?;
    let valid_origin = issuer.has_host()
        && issuer.username().is_empty()
        && issuer.password().is_none()
        && issuer.path() == "/"
        && issuer.query().is_none()
        && issuer.fragment().is_none()
        && (issuer.scheme() == "https"
            || (issuer.scheme() == "http"
                && matches!(issuer.host_str(), Some("127.0.0.1" | "localhost"))));
    let nonce = URL_SAFE_NO_PAD.decode(&challenge.nonce).map_err(|_| {
        WalletKitError::InvalidInput {
            attribute: "challenge".to_string(),
            reason: "invalid key proof nonce".to_string(),
        }
    })?;
    let ceremony = uuid::Uuid::parse_str(&challenge.ceremony_id).ok();
    if !valid_origin
        || challenge.version != 1
        || challenge.issuer != expected_issuer
        || !ceremony.is_some_and(|id| {
            !id.is_nil() && id.hyphenated().to_string() == challenge.ceremony_id
        })
        || nonce.len() != 32
        || URL_SAFE_NO_PAD.encode(&nonce) != challenge.nonce
        || challenge.expires_at <= now
        || challenge.expires_at.saturating_sub(now) > 330
    {
        return Err(WalletKitError::InvalidInput {
            attribute: "challenge".to_string(),
            reason: "invalid, foreign, or expired key proof challenge".to_string(),
        });
    }
    let key = derive_sign_in_key(seed)?;
    let digest = Sha256::new()
        .chain_update(PROOF_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let signature: p256_sign_in::ecdsa::Signature =
        key.sign_prehash(&digest)
            .map_err(|_| WalletKitError::Generic {
                error: "sign World ID key proof".to_string(),
            })?;
    Ok(WorldIdKeyProof {
        public_key: URL_SAFE_NO_PAD
            .encode(key.verifying_key().to_sec1_point(true).as_bytes()),
        signature: URL_SAFE_NO_PAD.encode(signature.normalize_s().to_der().as_bytes()),
    })
}

fn derive_sign_in_key(seed: &[u8]) -> Result<SigningKey, WalletKitError> {
    let hkdf = Hkdf::<Sha256>::new(Some(KEY_DOMAIN), seed);
    for counter in 0_u32..256 {
        let mut candidate = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&counter.to_be_bytes(), candidate.as_mut())
            .map_err(|_| WalletKitError::Generic {
                error: "expand World ID sign-in key".to_string(),
            })?;
        if let Ok(key) = SigningKey::from_slice(candidate.as_ref()) {
            return Ok(key);
        }
    }
    Err(WalletKitError::Generic {
        error: "could not derive a P-256 World ID sign-in key".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256_sign_in::ecdsa::signature::hazmat::PrehashVerifier;

    #[derive(Deserialize)]
    struct Vector {
        seed_hex: String,
        public_key: String,
        signature: String,
    }

    #[derive(Deserialize)]
    struct Fixture {
        now: i64,
        issuer: String,
        challenge: String,
        vectors: Vec<Vector>,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("key_proof/testdata/v1.json")).unwrap()
    }

    #[test]
    fn restored_seeds_match_cross_language_vectors() {
        let fixture = fixture();
        let proofs: Vec<_> = fixture
            .vectors
            .iter()
            .map(|vector| {
                create_at(
                    &hex::decode(&vector.seed_hex).unwrap(),
                    fixture.challenge.as_bytes(),
                    &fixture.issuer,
                    fixture.now,
                )
                .unwrap()
            })
            .collect();
        let expected: Vec<_> = fixture
            .vectors
            .iter()
            .map(|vector| WorldIdKeyProof {
                public_key: vector.public_key.clone(),
                signature: vector.signature.clone(),
            })
            .collect();
        assert_eq!(proofs, expected);
    }

    #[test]
    fn signs_without_an_authenticator_and_restores_the_same_sign_in_key() {
        let fixture = fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let challenge = fixture
            .challenge
            .replace("2000000300", &(now + 300).to_string());
        let seed = hex::decode(&fixture.vectors[0].seed_hex).unwrap();
        let proof = create_world_id_key_proof(
            seed.clone(),
            challenge.as_bytes().to_vec(),
            fixture.issuer.clone(),
        )
        .unwrap();
        assert_eq!(proof.public_key, fixture.vectors[0].public_key);
        let restored = create_world_id_key_proof(
            seed,
            challenge.as_bytes().to_vec(),
            fixture.issuer,
        )
        .unwrap();
        assert_eq!(restored, proof);
        let key = p256_sign_in::ecdsa::VerifyingKey::from_sec1_bytes(
            &URL_SAFE_NO_PAD.decode(&proof.public_key).unwrap(),
        )
        .unwrap();
        let signature = p256_sign_in::ecdsa::Signature::from_der(
            &URL_SAFE_NO_PAD.decode(&proof.signature).unwrap(),
        )
        .unwrap();
        let digest = Sha256::new()
            .chain_update(PROOF_DOMAIN)
            .chain_update(challenge)
            .finalize();
        key.verify_prehash(&digest, &signature).unwrap();
    }

    #[test]
    fn rejects_foreign_expired_and_malformed_challenges() {
        let fixture = fixture();
        let seed = hex::decode(&fixture.vectors[0].seed_hex).unwrap();
        assert!(create_at(
            &seed,
            fixture.challenge.as_bytes(),
            "https://foreign.example",
            fixture.now,
        )
        .is_err());
        for issuer in ["http://auth.world.org", "https://auth.world.org/path"] {
            let challenge = fixture.challenge.replace(&fixture.issuer, issuer);
            assert!(
                create_at(&seed, challenge.as_bytes(), issuer, fixture.now).is_err()
            );
        }
        for issuer in [
            "https://auth.world.org",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
        ] {
            let challenge = fixture.challenge.replace(&fixture.issuer, issuer);
            let proof =
                create_at(&seed, challenge.as_bytes(), issuer, fixture.now).unwrap();
            assert_eq!(
                proof.public_key,
                "A66IqHPC21NxH6PvdYOc4CiP0dUZ0YJU-c1P3Wnqc8Vg"
            );
        }
        assert!(create_at(
            &seed,
            fixture.challenge.as_bytes(),
            &fixture.issuer,
            fixture.now + 300
        )
        .is_err());
        for bytes in [
            fixture.challenge.replace("\"version\":1", "\"version\":2"),
            fixture
                .challenge
                .replace("\"version\":1", "\"version\":1,\"version\":1"),
            fixture.challenge.replace("2000000300", "2000000331"),
            fixture
                .challenge
                .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAA"),
        ] {
            assert!(
                create_at(&seed, bytes.as_bytes(), &fixture.issuer, fixture.now)
                    .is_err()
            );
        }
        for length in [0, 31, 33] {
            assert!(create_at(
                &vec![0; length],
                fixture.challenge.as_bytes(),
                &fixture.issuer,
                fixture.now
            )
            .is_err());
        }
    }
}
