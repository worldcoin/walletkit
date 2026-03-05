use crate::{error::WalletKitError, u256::U256Wrapper, Environment};

use secrecy::{ExposeSecret, SecretBox};
use semaphore_rs::{identity::seed_hex, protocol::generate_nullifier_hash};
use subtle::ConstantTimeEq;

use super::{
    credential_type::CredentialType,
    merkle_tree::MerkleTreeProof,
    proof::generate_proof_with_semaphore_identity,
    proof::{ProofContext, ProofOutput},
};

/// A base World ID identity which can be used to generate World ID Proofs for different credentials.
///
/// Most essential primitive for World ID.
#[derive(Debug, uniffi::Object)]
pub struct WorldId {
    /// The hashed hex-encoded World ID secret (32 byte secret -> 64 byte hex-encoded)
    /// Note: we need to store this hex-encoded because `semaphore-rs` performs operations on it hex-encoded. Can be improved in the future.
    hashed_secret_hex: SecretBox<[u8; 64]>,
    /// The environment in which this identity is running. Generally an app/client will be a single environment.
    environment: Environment,
}

#[uniffi::export(async_runtime = "tokio")]
impl WorldId {
    /// Initializes a new `Identity` from a World ID secret. The identity is initialized for a specific environment.
    #[must_use]
    #[uniffi::constructor]
    pub fn new(secret: &[u8], environment: &Environment) -> Self {
        let hashed_secret_hex: SecretBox<[u8; 64]> =
            SecretBox::init_with(|| seed_hex(secret));
        // NOTE: `init_with_mut` cannot be used here because [u8; 64] does not implement Default.

        Self {
            hashed_secret_hex,
            environment: environment.clone(),
        }
    }

    /// Generates a nullifier hash for a particular context (i.e. app + action) and the identity.
    /// The nullifier hash is a unique pseudo-random number for the particular identity and context.
    /// More information can be found [here](https://docs.world.org/world-id/concepts#vocabulary)
    ///
    /// [Protocol Reference](https://docs.semaphore.pse.dev/V2/technical-reference/circuits#nullifier-hash).
    #[must_use]
    pub fn generate_nullifier_hash(&self, context: &ProofContext) -> U256Wrapper {
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

    /// Generates a World ID Zero-knowledge proof (ZKP) for a specific context (i.e. app + action) and the identity.
    /// This is equivalent to the user presenting their credential to a verifying party.
    ///
    /// **Requires the `semaphore` feature flag.**
    ///
    /// # Errors
    /// Will error if the Merkle Tree inclusion proof cannot be retrieved from the sign up sequencer or if
    /// something fails with the proof generation.
    ///
    /// # Example
    /// ```rust
    /// use walletkit_core::{proof::ProofContext, CredentialType, Environment, world_id::WorldId};
    /// use std::sync::Arc;
    ///
    /// # tokio_test::block_on(async {
    ///     let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
    ///     let context = ProofContext::new("app_ce4cb73cb75fc3b73b71ffb4de178410", Some("my_action".to_string()), None, CredentialType::Device);
    ///     let proof = world_id.generate_proof(&context).await.unwrap();
    ///     assert_eq!(proof.nullifier_hash.to_hex_string(), "0x302e253346d2b41a0fd71562ffc6e5ddcbab6d8ea3dd6d68e6a695b5639b1c37")
    /// # })
    /// ```
    /// note: running the doctest example above requires an HTTP connection to the sequencer.
    pub async fn generate_proof(
        &self,
        context: &ProofContext,
    ) -> Result<ProofOutput, WalletKitError> {
        let identity = self.semaphore_identity_for_credential(&context.credential_type);
        // fetch directly instead of `get_identity_commitment` to avoid duplicate computations
        let identity_commitment = identity.commitment().into();

        let sequencer_host = context
            .credential_type
            .get_sign_up_sequencer_host(&self.environment);

        let merkle_tree_proof = MerkleTreeProof::from_identity_commitment(
            &identity_commitment,
            sequencer_host,
            context.require_mined_proof,
        )
        .await?;

        generate_proof_with_semaphore_identity(&identity, &merkle_tree_proof, context)
    }

    /// Compares two `WorldId`s for equality.
    ///
    /// This function uses constant-time comparison to prevent timing attacks, but should be performant enough.
    ///
    /// Exposed for foreign use. Use `PartialEq` if comparing within Rust.
    ///
    /// # Returns
    ///
    /// `true` if the two `WorldId`s are equal, `false` otherwise.
    #[must_use]
    pub fn is_equal_to(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        let self_secret = self.hashed_secret_hex.expose_secret();
        let other_secret = other.hashed_secret_hex.expose_secret();
        self_secret.ct_eq(other_secret).into() && self.environment == other.environment
    }
}

impl WorldId {
    /// Generates the Semaphore identity for a specific `CredentialType`.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn semaphore_identity_for_credential(
        &self,
        credential_type: &CredentialType,
    ) -> semaphore_rs::identity::Identity {
        // we need to copy the secret because `from_hashed_secret` performs zeroizing on its own
        let mut secret_hex = *self.hashed_secret_hex.expose_secret();
        let identity = semaphore_rs::identity::Identity::from_hashed_secret(
            &mut secret_hex,
            Some(credential_type.as_identity_trapdoor()),
        );
        identity
    }
}

impl PartialEq for WorldId {
    fn eq(&self, other: &Self) -> bool {
        self.is_equal_to(other)
    }
}

#[cfg(test)]
mod tests {

    use ruint::uint;
    use semaphore_rs::protocol::verify_proof;

    use super::*;

    /// This test covers generating a default World ID ZKP in its simplest form.
    ///
    /// Additionally it tests computing the `nullifier_hash` correctly.
    #[tokio::test]
    async fn test_proof_generation() {
        let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
        let context = ProofContext::new("app_id", None, None, CredentialType::Orb);
        let nullifier_hash = world_id.generate_nullifier_hash(&context);
        assert_eq!(
            nullifier_hash.to_hex_string(),
            "0x1359a81e3a42dc1c34786cbefbcc672a3d730510dba7a3be9941b207b0cf52fa"
        );

        assert_eq!(
            world_id
                .get_identity_commitment(&CredentialType::Orb)
                .to_hex_string(),
            "0x000352340ece4a3509b5a053118e289300e9e9677d135ae1a625219a10923a7e"
        );

        assert_eq!(
            context.signal_hash.to_hex_string(),
            "0x00c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4"
        );

        let proof = world_id.generate_proof(&context).await.unwrap();
        assert_eq!(
            proof.nullifier_hash.to_hex_string(),
            "0x1359a81e3a42dc1c34786cbefbcc672a3d730510dba7a3be9941b207b0cf52fa"
        );

        let verify_result = verify_proof(
            proof.merkle_root.into(),
            nullifier_hash.into(),
            context.signal_hash.into(),
            context.external_nullifier.into(),
            &proof.raw_proof,
            30,
        )
        .unwrap();

        assert!(verify_result);
    }

    /// This test also covers using the alternative `CredentialType::Device`.
    #[tokio::test]
    async fn test_proof_generation_with_device_credential_and_string_signal() {
        let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
        let context = ProofContext::new(
            "app_id",
            None,
            Some("test-signal".to_string()),
            CredentialType::Device,
        );

        assert_eq!(
            world_id
                .get_identity_commitment(&CredentialType::Device)
                .to_hex_string(),
            // note this identity commitment is different from the `Orb` credential
            // (deliberate from the identity trapdoor, to maintain privacy between credentials)
            "0x1a060ef75540e13711f074b779a419c126ab5a89d2c2e7d01e64dfd121e44671"
        );

        assert_eq!(
            context.signal_hash.to_hex_string(),
            "0x00109ceebc907a38c59ec1c982a480d7d2373fc7c58b604a5430988fc08e346e"
        );

        let proof = world_id.generate_proof(&context).await.unwrap();
        assert_eq!(
            proof.nullifier_hash.to_hex_string(),
            // nullifier hash is the same as the `Orb` credential to maintain a single representation of the user
            "0x1359a81e3a42dc1c34786cbefbcc672a3d730510dba7a3be9941b207b0cf52fa"
        );

        let verify_result = verify_proof(
            proof.merkle_root.into(),
            proof.nullifier_hash.into(),
            context.signal_hash.into(),
            context.external_nullifier.into(),
            &proof.raw_proof,
            30,
        )
        .unwrap();

        assert!(verify_result);
    }

    #[test]
    fn test_secret_hex_generation() {
        let world_id: WorldId =
            WorldId::new(b"not_a_real_secret", &Environment::Staging);

        // this is the expected SHA-256 of the secret (computed externally)
        let expected_hash: U256Wrapper = uint!(88026203285206540949013074047154212280150971633012190779810764227609557184952_U256).into();

        let bytes = expected_hash.to_hex_string();

        let mut result = [0_u8; 64];
        result[..].copy_from_slice(&bytes.as_bytes()[2..]); // we slice the first 2 chars to remove the 0x

        assert_eq!(&result, world_id.hashed_secret_hex.expose_secret());
    }

    #[test]
    fn test_partial_eq_constant_time() {
        // Test that WorldId equality works correctly
        let world_id1 = WorldId::new(b"not_a_real_secret", &Environment::Staging);
        let world_id2 = WorldId::new(b"not_a_real_secret", &Environment::Staging);
        let world_id3 = WorldId::new(b"different_secret", &Environment::Staging);
        let world_id4 = WorldId::new(b"not_a_real_secret", &Environment::Production);

        // Same secret, same environment
        assert_eq!(world_id1, world_id2);

        assert_ne!(world_id1, world_id3); // Different secret, same environment
        assert_ne!(world_id1, world_id4); // Same secret, different environment
    }

    #[test]
    fn test_identity_commitment_generation() {
        let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
        let commitment = world_id.get_identity_commitment(&CredentialType::Orb);

        assert_eq!(
            *commitment,
            uint!(
                0x000352340ece4a3509b5a053118e289300e9e9677d135ae1a625219a10923a7e_U256
            )
        );

        let secure_document_commitment =
            world_id.get_identity_commitment(&CredentialType::SecureDocument);

        assert_eq!(
            *secure_document_commitment,
            uint!(
                4772776030911288417155544975787646998508849894109450205303839917538446765610_U256
            )
        );

        let semaphore_identity = semaphore_rs::identity::Identity::from_secret(
            &mut b"not_a_real_secret".to_vec(),
            Some(b"secure_passport"),
        );
        assert_eq!(semaphore_identity.commitment(), *secure_document_commitment);

        let device_commitment =
            world_id.get_identity_commitment(&CredentialType::Device);

        assert!(device_commitment != commitment);
    }
}
