use ruint::{aliases::U256, uint};
use semaphore_rs_poseidon::poseidon::{hash1, hash2};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// BN254 scalar-field prime used to reduce derived hashes, matching semaphore-rs
// 0.6.0's MODULUS in src/field.rs. Kept local to avoid its native prover dependencies
// on WASM; uint! constructs this fixed 256-bit integer at compile time.
const BN254_SCALAR_MODULUS: U256 = uint!(
    21888242871839275222246405745257275088548364400416034343698204186575808495617_U256
);

/// Domain separation for an identity commitment.
#[derive(Clone, Copy)]
pub enum IdentityContext {
    /// The face enrollment identity domain used by Oxide.
    Face,
}

/// An identity whose secret stays in memory until the identity is dropped.
///
/// Derivation matches Oxide's `Identity::new(hex::encode(seed), IdentityContext::Face)`:
/// the 32-byte seed is encoded as lowercase hex without `0x`, then passed through
/// Semaphore's SHA-256 identity derivation with the `face_credential` context.
/// Only the public commitment is exposed; this does not generate ownership proofs.
pub struct Identity {
    hashed_secret_hex: Zeroizing<String>,
    context: IdentityContext,
}

/// Invalid input to face identity derivation.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The input must contain exactly 32 bytes.
    #[error("identity seed must contain exactly 32 bytes")]
    InvalidSeedLength,
}

impl Identity {
    /// Derives a face identity and erases the owned input buffer.
    ///
    /// # Errors
    /// Returns [`IdentityError::InvalidSeedLength`] unless `seed` has 32 bytes.
    pub fn from_seed(
        seed: Vec<u8>,
        context: IdentityContext,
    ) -> Result<Self, IdentityError> {
        let seed = Zeroizing::new(seed);
        if seed.len() != 32 {
            return Err(IdentityError::InvalidSeedLength);
        }
        let seed_hex = Zeroizing::new(hex::encode(&*seed));
        let digest =
            Zeroizing::new(<[u8; 32]>::from(Sha256::digest(seed_hex.as_bytes())));
        let hashed_secret_hex = Zeroizing::new(hex::encode(digest.as_slice()));
        Ok(Self {
            hashed_secret_hex,
            context,
        })
    }

    /// Returns the public commitment as `0x` followed by 64 lowercase hex digits.
    #[must_use]
    pub fn commitment(&self) -> String {
        let nullifier = self.derive_field(b"identity_nullifier");
        let trapdoor = match self.context {
            IdentityContext::Face => self.derive_field(b"face_credential"),
        };
        let secret_hash = Zeroizing::new(hash2(*nullifier, *trapdoor));
        format!("{:#066x}", hash1(*secret_hash))
    }

    // semaphore-rs packages identity derivation with native prover dependencies.
    // Keep its derivation here while reusing its Poseidon implementation on WASM.
    fn derive_field(&self, suffix: &[u8]) -> Zeroizing<U256> {
        let mut hasher = Sha256::new();
        hasher.update(self.hashed_secret_hex.as_bytes());
        hasher.update(suffix);
        let digest = Zeroizing::new(<[u8; 32]>::from(hasher.finalize()));
        Zeroizing::new(U256::from_be_bytes(*digest) % BN254_SCALAR_MODULUS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_seed_lengths() {
        for length in [0, 1, 31, 33, 64] {
            assert!(matches!(
                Identity::from_seed(vec![0; length], IdentityContext::Face),
                Err(IdentityError::InvalidSeedLength)
            ));
        }
    }

    #[test]
    fn derivation_is_stable_and_distinct() {
        let first = Identity::from_seed(vec![1; 32], IdentityContext::Face).unwrap();
        let same = Identity::from_seed(vec![1; 32], IdentityContext::Face).unwrap();
        let other = Identity::from_seed(vec![2; 32], IdentityContext::Face).unwrap();
        assert_eq!(first.commitment(), same.commitment());
        assert_ne!(first.commitment(), other.commitment());
        assert_eq!(first.commitment().len(), 66);
    }

    #[test]
    fn frozen_oxide_compatible_vectors() {
        // Generated independently using semaphore-rs 0.6.0's from_secret on
        // hex::encode(seed), with face_credential and the default Orb context.
        let vectors = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0x026b3875f92d39958477b2c9912e2f497d31f7b2de869359757efbb403d80074",
                "0x2d163ec90ea9c9e359f8a6676dcb820a6b2d7099dad84300a938aef8778ea01c",
            ),
            (
                "0101010101010101010101010101010101010101010101010101010101010101",
                "0x2d45a99aef68e94a73cc40b05ea26a6ab41c981313b7e997245222abf9ee6f56",
                "0x278eed21d071e32e7cc112eb59d80affd1bc2fb2a8307a6a1c354905f153c279",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "0x1084e9c76d6b51135882c5aa0980518cdcad4db91da69693575d47c72e9d6c56",
                "0x182230e08e17478a57fa41969af442956e31ea0f1b51598844a04e24ba109122",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "0x2f078810830125a9535a2625392f20d02c2e3f6470cd7dd0bc158506e52c9f22",
                "0x176c90d1c519259243afad87d1aac3ef811badd22a4c5a5a14d28d08150e0e89",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0x2476e7a9c3df676412a0dec1056d7ce2523de92f11a1c08e523f022f0af443c7",
                "0x0d59dcb9d657287345edc0a7435c12f818041151418e4e505ac6e0951302cd04",
            ),
            (
                "80000000000000000000000000000000000000000000000000000000000000ff",
                "0x16d3b61aa255da8e322d6833393d1101b11d40fe9965d1327814c3b0ca15b3e2",
                "0x2bacd094ae634471df74470f8167ea1b4d02078e6c7b715c6cf192081d8144ce",
            ),
        ];
        for (seed_hex, expected_face, expected_orb) in vectors {
            let identity = Identity::from_seed(
                hex::decode(seed_hex).unwrap(),
                IdentityContext::Face,
            )
            .unwrap();
            assert_eq!(identity.commitment(), expected_face);
            assert_ne!(identity.commitment(), expected_orb);
        }
    }

    #[cfg(feature = "v3")]
    #[test]
    fn matches_oxide_identity_and_is_separate_from_orb() {
        for seed in [
            [0; 32],
            [1; 32],
            [255; 32],
            std::array::from_fn(|i| u8::try_from(i).unwrap()),
        ] {
            let mut encoded = hex::encode(seed).into_bytes();
            let face = semaphore_rs::identity::Identity::from_secret(
                &mut encoded,
                Some(b"face_credential"),
            );
            let mut encoded = hex::encode(seed).into_bytes();
            let orb = semaphore_rs::identity::Identity::from_secret(&mut encoded, None);
            let actual = Identity::from_seed(seed.to_vec(), IdentityContext::Face)
                .unwrap()
                .commitment();
            assert_eq!(actual, format!("{:#066x}", face.commitment()));
            assert_ne!(actual, format!("{:#066x}", orb.commitment()));
        }
    }
}
