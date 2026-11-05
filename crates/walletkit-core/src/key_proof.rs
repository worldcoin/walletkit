//! World ID key proofs for the encrypted Auth bridge.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use p256_sign_in::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
    #[serde(rename = "expires_at")]
    _expires_at: i64,
}

/// Signs an Auth challenge using a key derived from the 32-byte World ID seed.
///
/// Requires user approval, but no Authenticator, credentials, or network calls.
/// `expected_issuer` must come from trusted app configuration. `challenge` is the
/// exact decoded JSON byte string from `key_proof_request.challenge`.
/// The `IdP` enforces expiry using its server clock.
/// Devices restored from the same seed share this sign-in key.
///
/// # Errors
/// Rejects invalid seeds, issuer configuration, and foreign or malformed
/// challenges. Derivation and signing failures exclude secret material.
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
    if seed.len() != 32 {
        return Err(WalletKitError::InvalidInput {
            attribute: "seed".to_string(),
            reason: "expected a 32-byte World ID seed".to_string(),
        });
    }
    let invalid_challenge = |reason: &str| WalletKitError::InvalidInput {
        attribute: "challenge".to_string(),
        reason: reason.to_string(),
    };
    if challenge.is_empty() || challenge.len() > 1024 {
        return Err(invalid_challenge("expected 1–1024 bytes of challenge JSON"));
    }
    let invalid_issuer = |reason: &str| WalletKitError::InvalidInput {
        attribute: "expected_issuer".to_string(),
        reason: reason.to_string(),
    };
    let issuer = reqwest::Url::parse(&expected_issuer)
        .map_err(|err| invalid_issuer(&format!("invalid issuer URL: {err}")))?;
    let authority = expected_issuer.split_once("://").map(|(_, value)| value);
    if expected_issuer.trim() != expected_issuer
        || expected_issuer.chars().any(char::is_control)
        || !issuer.has_host()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.path() != "/"
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || authority
            .is_none_or(|value| value.contains(['/', '@']) || value.ends_with(':'))
    {
        return Err(invalid_issuer("expected an issuer origin without user information, a path, trailing slash, query, or fragment"));
    }
    let loopback = authority
        .and_then(|value| {
            value.strip_prefix('[').map_or_else(
                || value.split(':').next(),
                |ipv6| ipv6.split_once(']').map(|(host, _)| host),
            )
        })
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.to_canonical().is_loopback());
    if issuer.scheme() != "https" && !(issuer.scheme() == "http" && loopback) {
        return Err(invalid_issuer(
            "issuer must use HTTPS, except for loopback IP development origins",
        ));
    }
    let parsed: Challenge = serde_json::from_slice(&challenge).map_err(|err| {
        invalid_challenge(&format!(
            "invalid key proof challenge JSON ({:?} at line {}, column {})",
            err.classify(),
            err.line(),
            err.column()
        ))
    })?;
    if parsed.version != 1 {
        return Err(invalid_challenge("unsupported key proof challenge version"));
    }
    if parsed.issuer != expected_issuer {
        return Err(invalid_challenge(
            "key proof issuer does not match expected_issuer",
        ));
    }
    let ceremony = uuid::Uuid::parse_str(&parsed.ceremony_id)
        .map_err(|_| invalid_challenge("ceremony_id must be a UUID"))?;
    if ceremony.is_nil() || ceremony.hyphenated().to_string() != parsed.ceremony_id {
        return Err(invalid_challenge(
            "ceremony_id must be a canonical, non-nil UUID",
        ));
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&parsed.nonce)
        .map_err(|err| invalid_challenge(&format!("invalid key proof nonce: {err}")))?;
    if nonce.len() != 32 {
        return Err(invalid_challenge("key proof nonce must contain 32 bytes"));
    }
    let key = derive_sign_in_key(&seed)?;
    let digest = Sha256::new()
        .chain_update(PROOF_DOMAIN)
        .chain_update(challenge)
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
                create_world_id_key_proof(
                    hex::decode(&vector.seed_hex).unwrap(),
                    fixture.challenge.as_bytes().to_vec(),
                    fixture.issuer.clone(),
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
    fn signing_does_not_depend_on_the_device_clock_or_challenge_lifetime() {
        let fixture = fixture();
        let seed = hex::decode(&fixture.vectors[0].seed_hex).unwrap();
        for expires_at in [1, 2_000_000_330, 2_000_000_331, i64::MAX] {
            let challenge = fixture
                .challenge
                .replace("2000000300", &expires_at.to_string());
            let proof = create_world_id_key_proof(
                seed.clone(),
                challenge.as_bytes().to_vec(),
                fixture.issuer.clone(),
            )
            .unwrap();
            assert_eq!(
                proof.public_key,
                "A66IqHPC21NxH6PvdYOc4CiP0dUZ0YJU-c1P3Wnqc8Vg"
            );
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
    }

    #[test]
    fn issuer_origins_match_the_idp_policy() {
        let fixture = fixture();
        let seed = hex::decode(&fixture.vectors[0].seed_hex).unwrap();
        for issuer in [
            "https://auth.world.org",
            "https://auth.world.org:443",
            "https://auth.local.worldcoin.dev:5174",
            "http://127.0.0.1:5174",
            "http://127.0.0.2:5174",
            "http://[::1]:5174",
            "http://[::ffff:127.0.0.1]:5174",
        ] {
            let challenge = fixture.challenge.replace(&fixture.issuer, issuer);
            let proof = create_world_id_key_proof(
                seed.clone(),
                challenge.into_bytes(),
                issuer.to_string(),
            )
            .unwrap();
            assert_eq!(
                proof.public_key,
                "A66IqHPC21NxH6PvdYOc4CiP0dUZ0YJU-c1P3Wnqc8Vg"
            );
        }
        for issuer in [
            "not a URL",
            "http://localhost:5174",
            "http://127.1:5174",
            "http://2130706433:5174",
            "http://auth.world.org",
            "https://auth.world.org/",
            "https://auth.world.org/path",
            "https://auth.world.org/.",
            "https://user@auth.world.org",
            "https://@auth.world.org",
            "https://auth.world.org?",
            "https://auth.world.org#",
            "https://auth.world.org:",
            "https://auth.world.org\t",
        ] {
            let challenge = fixture.challenge.replace(&fixture.issuer, issuer);
            assert!(
                matches!(
                    create_world_id_key_proof(seed.clone(), challenge.into_bytes(), issuer.to_string()),
                    Err(WalletKitError::InvalidInput { attribute, reason })
                        if attribute == "expected_issuer" && !reason.is_empty()
                ),
                "issuer {issuer:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_challenges_with_specific_reasons() {
        let fixture = fixture();
        let seed = hex::decode(&fixture.vectors[0].seed_hex).unwrap();
        for (challenge, reason) in [
            (
                fixture.challenge.replace("\"version\":1", "\"version\":2"),
                "unsupported key proof challenge version",
            ),
            (
                fixture
                    .challenge
                    .replace(&fixture.issuer, "https://foreign.example"),
                "key proof issuer does not match expected_issuer",
            ),
            (
                fixture
                    .challenge
                    .replace("019af784-3d00-7000-8000-000000000001", "not-a-uuid"),
                "ceremony_id must be a UUID",
            ),
            (
                fixture.challenge.replace(
                    "019af784-3d00-7000-8000-000000000001",
                    "00000000-0000-0000-0000-000000000000",
                ),
                "ceremony_id must be a canonical, non-nil UUID",
            ),
            (
                fixture.challenge.replace(
                    "019af784-3d00-7000-8000-000000000001",
                    "019AF784-3D00-7000-8000-000000000001",
                ),
                "ceremony_id must be a canonical, non-nil UUID",
            ),
            (
                fixture
                    .challenge
                    .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAA"),
                "key proof nonce must contain 32 bytes",
            ),
            (
                "{".to_string(),
                "invalid key proof challenge JSON (Eof at line 1, column 1)",
            ),
        ] {
            assert!(
                matches!(
                    create_world_id_key_proof(seed.clone(), challenge.into_bytes(), fixture.issuer.clone()),
                    Err(WalletKitError::InvalidInput { attribute, reason: actual })
                        if attribute == "challenge" && actual == reason
                ),
                "expected {reason}"
            );
        }
        for challenge in [
            fixture
                .challenge
                .replace("\"version\":1", "\"version\":1,\"version\":1"),
            fixture
                .challenge
                .replace("2000000300", "\"not-a-timestamp\""),
            fixture.challenge.replace(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            ),
        ] {
            assert!(matches!(
                create_world_id_key_proof(seed.clone(), challenge.into_bytes(), fixture.issuer.clone()),
                Err(WalletKitError::InvalidInput { attribute, reason })
                    if attribute == "challenge" && (reason.starts_with("invalid key proof challenge JSON") || reason.starts_with("invalid key proof nonce:"))
            ));
        }
    }

    #[test]
    fn rejects_invalid_seed_and_challenge_lengths() {
        let fixture = fixture();
        for length in [0, 31, 33] {
            assert!(matches!(
                create_world_id_key_proof(vec![0; length], fixture.challenge.as_bytes().to_vec(), fixture.issuer.clone()),
                Err(WalletKitError::InvalidInput { attribute, reason })
                    if attribute == "seed" && reason == "expected a 32-byte World ID seed"
            ));
        }
        for challenge in [vec![], vec![b' '; 1025]] {
            assert!(matches!(
                create_world_id_key_proof(hex::decode(&fixture.vectors[0].seed_hex).unwrap(), challenge, fixture.issuer.clone()),
                Err(WalletKitError::InvalidInput { attribute, reason })
                    if attribute == "challenge" && reason == "expected 1–1024 bytes of challenge JSON"
            ));
        }
    }
}
