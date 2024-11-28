use semaphore::{identity::seed_hex, protocol::generate_nullifier_hash};

use crate::{credential_type::CredentialType, proof::Context, u256::U256Wrapper};

/// A base World ID identity which can be used to generate World ID Proofs for different credentials.
///
/// Most essential primitive for World ID.
///
/// # Security
/// TODO: Review with Security Team
/// 1. `sempahore-rs` zeroizes the bytes representing the World ID Secret and stores the trapdoor and nullifier in memory. This doesn't
///     add too much additional security versus keeping the secret in memory because for the context of Semaphore ZKPs, the nullifier and
///     trapdoor are what is actually used in the ZK circuit.
/// 2. Zeroize does not have good compatibility with `UniFFI` as `UniFFI` may make many copies of the bytes for usage in foreign code
///     ([reference](https://github.com/mozilla/uniffi-rs/issues/2080)). This needs to be further explored.
#[derive(Clone, PartialEq, Eq, Debug, uniffi::Object)]
pub struct Identity {
    /// The Semaphore-based identity specifically for the `CredentialType::Orb`
    canonical_orb_semaphore_identity: semaphore::identity::Identity,
    /// The hashed World ID secret, cast to 64 bytes (0-padded). Actual hashed secret is 32 bytes.
    secret_hex: [u8; 64],
}

#[uniffi::export]
impl Identity {
    #[must_use]
    #[uniffi::constructor]
    pub fn new(secret: &[u8]) -> Self {
        let secret_hex = seed_hex(secret);

        let mut secret_key = secret.to_vec();

        let canonical_orb_semaphore_identity =
            semaphore::identity::Identity::from_secret(&mut secret_key, None);

        Self {
            canonical_orb_semaphore_identity,
            secret_hex,
        }
    }

    /// Generates a nullifier hash for a particular context (i.e. app + action) and the identity.
    /// The nullifier hash is a unique pseudo-random number for the particular identity and context.
    /// More information can be found [here](https://docs.world.org/world-id/concepts#vocabulary)
    ///
    /// [Protocol Reference](https://docs.semaphore.pse.dev/V2/technical-reference/circuits#nullifier-hash).
    #[must_use]
    pub fn generate_nullifier_hash(&self, context: &Context) -> U256Wrapper {
        let identity = self.semaphore_identity_for_credential(&context.credential_type);
        generate_nullifier_hash(&identity, *context.external_nullifier).into()
    }

    /// Generates the `identity_commitment` for a specific World ID identity and for a specific credential.
    /// For the same World ID, each credential will generate a different `identity_commitment` for privacy reasons. This is
    /// accomplished by using a different `identity_trapdoor` internally.
    ///
    /// The identity commitment is the public part of a World ID. It is what gets inserted into the membership set on-chain. Identity commitments
    /// are not directly used in proof verification.
    #[must_use]
    pub fn get_identity_commitment(
        &self,
        credential_type: &CredentialType,
    ) -> U256Wrapper {
        let identity = self.semaphore_identity_for_credential(credential_type);
        identity.commitment().into()
    }
}

impl Identity {
    /// Retrieves the Semaphore identity for a specific `CredentialType` from memory or by computing it on the spot.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn semaphore_identity_for_credential(
        &self,
        credential_type: &CredentialType,
    ) -> semaphore::identity::Identity {
        if credential_type == &CredentialType::Orb {
            self.canonical_orb_semaphore_identity.clone()
        } else {
            // When the identity commitment for the non-canonical identity is requested, a new Semaphore identity needs to be initialized.
            let mut secret_hex = self.secret_hex;
            let identity = semaphore::identity::Identity::from_hashed_secret(
                &mut secret_hex,
                Some(credential_type.as_identity_trapdoor()),
            );
            identity
        }
    }
}

#[cfg(test)]
mod tests {

    use ruint::uint;
    use std::sync::Arc;

    use super::*;
    #[test]
    fn test() {
        let identity = Identity::new(b"not_a_real_secret");
        let context = Context::new("app_id", None, Arc::new(CredentialType::Orb));
        let nullifier_hash = identity.generate_nullifier_hash(&context);
        println!("{}", nullifier_hash.to_hex_string());
    }

    #[test]
    fn test_secret_hex_generation() {
        let identity = Identity::new(b"not_a_real_secret");

        // this is the expected SHA-256 of the secret (computed externally)
        let expected_hash: U256Wrapper = uint!(88026203285206540949013074047154212280150971633012190779810764227609557184952_U256).into();

        let bytes = expected_hash.to_hex_string();

        let mut result = [0_u8; 64];
        result[..].copy_from_slice(&bytes.as_bytes()[2..]); // we slice the first 2 chars to remove the 0x

        assert_eq!(result, identity.secret_hex);
    }

    #[test]
    fn test_identity_commitment_generation() {
        let identity = Identity::new(b"not_a_real_secret");
        let commitment = identity.get_identity_commitment(&CredentialType::Orb);

        assert_eq!(
            *commitment,
            uint!(
                0x000352340ece4a3509b5a053118e289300e9e9677d135ae1a625219a10923a7e_U256
            )
        );

        let secure_passport_commitment =
            identity.get_identity_commitment(&CredentialType::SecurePassport);

        assert_eq!(
            *secure_passport_commitment,
            uint!(
                4772776030911288417155544975787646998508849894109450205303839917538446765610_U256
            )
        );

        let semaphore_identity = semaphore::identity::Identity::from_secret(
            &mut b"not_a_real_secret".to_vec(),
            Some(b"secure_passport"),
        );
        assert_eq!(semaphore_identity.commitment(), *secure_passport_commitment);

        let device_commitment =
            identity.get_identity_commitment(&CredentialType::Device);

        assert!(device_commitment != commitment);
    }
}
