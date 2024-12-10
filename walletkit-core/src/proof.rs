use crate::error::Error;
use std::sync::Arc;

use alloy_core::sol_types::SolValue;
use semaphore::{
    hash_to_field, identity,
    packed_proof::PackedProof,
    protocol::{generate_nullifier_hash, generate_proof, Proof},
};
use serde::Serialize;

use crate::{
    credential_type::CredentialType, merkle_tree::MerkleTreeProof, u256::U256Wrapper,
};

/// A `Proof::Context` contains the basic information on the verifier and the specific action a user will be proving.
///
/// It is required to generate a `Proof` and will generally be initialized from an `app_id` and `action`.
#[derive(Clone, PartialEq, Eq, Debug, uniffi::Object)]
pub struct Context {
    pub external_nullifier: U256Wrapper,
    pub credential_type: CredentialType,
    pub signal: U256Wrapper,
}

#[uniffi::export]
impl Context {
    /// Initializes a `Proof::Context`.
    ///
    /// Will compute the relevant external nullifier from the provided `app_id` and `action` as defined by the
    /// World ID Protocol. The external nullifier generation matches the logic in the
    /// [Developer Portal](https://github.com/worldcoin/developer-portal/blob/main/web/lib/hashing.ts).
    ///
    /// # Arguments
    ///
    /// * `app_id` - The ID of the application requesting proofs. This can be obtained from the Developer Portal.
    /// * `action` - Optional. Custom incognito action being requested.
    ///
    #[must_use]
    #[uniffi::constructor]
    pub fn new(
        app_id: &str,
        action: Option<String>,
        signal: Option<String>,
        credential_type: Arc<CredentialType>,
    ) -> Self {
        Self::new_from_bytes(
            app_id,
            action.map(std::string::String::into_bytes),
            signal.map(std::string::String::into_bytes),
            credential_type,
        )
    }

    /// Initializes a `Proof::Context` where the `action` is provided as raw bytes. This is useful for advanced cases
    /// where the `action` is an already ABI encoded value for on-chain usage.
    /// See _walletkit-core/tests/solidity.rs_ for an example.
    ///
    /// Will compute the relevant external nullifier from the provided `app_id` and `action`.
    ///
    /// # Arguments
    ///
    /// * `app_id` - The ID of the application requesting proofs. This can be obtained from the Developer Portal.
    /// * `action` - Optional. Custom incognito action being requested as raw bytes (*must be UTF-8*).
    ///
    #[must_use]
    #[uniffi::constructor]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new_from_bytes(
        app_id: &str,
        action: Option<Vec<u8>>,
        signal: Option<Vec<u8>>,
        credential_type: Arc<CredentialType>,
    ) -> Self {
        let mut pre_image = hash_to_field(app_id.as_bytes()).abi_encode_packed();

        if let Some(action) = action {
            pre_image.extend_from_slice(&action);
        }

        let external_nullifier = hash_to_field(&pre_image).into();

        Self {
            external_nullifier,
            credential_type: *credential_type,
            signal: hash_to_field(signal.unwrap_or_default().as_slice()).into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, uniffi::Object, Serialize)]
pub struct Output {
    pub merkle_root: U256Wrapper,
    pub nullifier_hash: U256Wrapper,
    #[serde(skip_serializing)]
    pub raw_proof: Proof,
    pub proof: PackedProof,
}

#[uniffi::export]
impl Output {
    fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::SerializationError)
    }
}

/// Generates a Semaphore ZKP for a specific Semaphore identity using the relevant provided context.
///
/// # Errors
/// Returns an error if proof generation fails
pub fn generate_proof_with_semaphore_identity(
    identity: &identity::Identity,
    merkle_tree_proof: MerkleTreeProof,
    context: &Context,
) -> Result<Output, Error> {
    let merkle_root = merkle_tree_proof.merkle_root; // clone the value

    let merkle_proof = semaphore::poseidon_tree::Proof::from(merkle_tree_proof);
    let external_nullifier_hash = context.external_nullifier.into();
    let nullifier_hash =
        generate_nullifier_hash(identity, external_nullifier_hash).into();

    let proof = generate_proof(
        identity,
        &merkle_proof,
        external_nullifier_hash,
        context.signal.into(),
    )?;

    Ok(Output {
        merkle_root,
        nullifier_hash,
        raw_proof: proof,
        proof: PackedProof::from(proof),
    })
}

#[cfg(test)]
mod external_nullifier_tests {
    use alloy_core::primitives::address;
    use ruint::{aliases::U256, uint};

    use super::*;

    #[test]
    fn test_context_and_external_nullifier_hash_generation() {
        let context = Context::new(
            "app_369183bd38f1641b6964ab51d7a20434",
            None,
            None,
            Arc::new(CredentialType::Orb),
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x0073e4a6b670e81dc619b1f8703aa7491dc5aaadf75409aba0ac2414014c0227"
        );

        // note the same external nullifier hash is generated for an empty string action
        let context = Context::new(
            "app_369183bd38f1641b6964ab51d7a20434",
            Some(String::new()),
            None,
            Arc::new(CredentialType::Orb),
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x0073e4a6b670e81dc619b1f8703aa7491dc5aaadf75409aba0ac2414014c0227"
        );
    }

    /// This test case comes from the real example in the docs.
    /// Reference: <https://github.com/worldcoin/world-id-docs/blob/main/src/pages/world-id/try.tsx>
    #[test]
    fn test_external_nullifier_hash_generation_string_action_staging() {
        let context = Context::new(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some("test-action-qli8g".to_string()),
            None,
            Arc::new(CredentialType::Orb),
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x00d8b157e767dc59faa533120ed0ce34fc51a71937292ea8baed6ee6f4fda866"
        );
    }

    #[test]
    fn test_external_nullifier_hash_generation_string_action() {
        let context = Context::new(
            "app_10eb12bd96d8f7202892ff25f094c803",
            Some("test-123123".to_string()),
            None,
            Arc::new(CredentialType::Orb),
        );
        assert_eq!(
            context.external_nullifier.0,
            uint!(
                // cspell:disable-next-line
                0x0065ebab05692ff2e0816cc4c3b83216c33eaa4d906c6495add6323fe0e2dc89_U256
            )
        );
    }

    #[test]
    fn test_external_nullifier_hash_generation_with_advanced_abi_encoded_values() {
        let custom_action = [
            address!("541f3cc5772a64f2ba0a47e83236CcE2F089b188").abi_encode_packed(),
            U256::from(1).abi_encode_packed(),
            "hello".abi_encode_packed(),
        ]
        .concat();

        let context = Context::new_from_bytes(
            "app_10eb12bd96d8f7202892ff25f094c803",
            Some(custom_action),
            None,
            Arc::new(CredentialType::Orb),
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            // expected output obtained from Solidity
            "0x00f974ff06219e8ca992073d8bbe05084f81250dbd8f37cae733f24fcc0c5ffd"
        );
    }

    #[test]
    fn test_external_nullifier_hash_generation_with_advanced_abi_encoded_values_staging(
    ) {
        let custom_action = [
            "world".abi_encode_packed(),
            U256::from(1).abi_encode_packed(),
            "hello".abi_encode_packed(),
        ]
        .concat();

        let context = Context::new_from_bytes(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some(custom_action),
            None,
            Arc::new(CredentialType::Orb),
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            // expected output obtained from Solidity
            "0x005b49f95e822c7c37f4f043421689b11f880e617faa5cd0391803bc9bcc63c0"
        );
    }
}

#[cfg(test)]
mod proof_tests {

    use regex::Regex;
    use semaphore::protocol::verify_proof;
    use serde_json::Value;

    use super::*;

    fn helper_load_merkle_proof() -> MerkleTreeProof {
        let json_merkle: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/inclusion_proof.json"
        ))
        .unwrap();
        MerkleTreeProof::from_json_proof(
            &serde_json::to_string(&json_merkle["proof"]).unwrap(),
            json_merkle["root"].as_str().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_proof_generation() {
        let context = Context::new(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some("test-action-89tcf".to_string()),
            None,
            CredentialType::Device.into(),
        );

        let mut secret = b"not_a_real_secret".to_vec();

        let identity = semaphore::identity::Identity::from_secret(
            &mut secret,
            Some(context.credential_type.as_identity_trapdoor()),
        );

        assert_eq!(
            U256Wrapper::from(identity.commitment()).to_hex_string(),
            "0x1a060ef75540e13711f074b779a419c126ab5a89d2c2e7d01e64dfd121e44671"
        );

        // Compute ZKP
        let zkp = generate_proof_with_semaphore_identity(
            &identity,
            helper_load_merkle_proof(),
            &context,
        )
        .unwrap();

        assert_eq!(
            zkp.merkle_root.to_hex_string(),
            "0x2f3a95b6df9074a19bf46e2308d7f5696e9dca49e0d64ef49a1425bbf40e0c02"
        );

        assert_eq!(
            zkp.nullifier_hash.to_hex_string(),
            "0x11d194ff98df5c8e239e6b6e33cce7fb1b419344cb13e064350a917970c8fea4"
        );

        // assert proof verifies locally
        assert!(verify_proof(
            *zkp.merkle_root,
            *zkp.nullifier_hash,
            hash_to_field(&[]),
            *context.external_nullifier,
            &zkp.raw_proof,
            30
        )
        .unwrap());
    }

    #[test]
    fn test_proof_json_encoding() {
        let context = Context::new(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some("test-action-89tcf".to_string()),
            None,
            CredentialType::Device.into(),
        );

        let mut secret = b"not_a_real_secret".to_vec();
        let identity = semaphore::identity::Identity::from_secret(
            &mut secret,
            Some(context.credential_type.as_identity_trapdoor()),
        );

        // Compute ZKP
        let zkp = generate_proof_with_semaphore_identity(
            &identity,
            helper_load_merkle_proof(),
            &context,
        )
        .unwrap();

        let parsed_json: Value = serde_json::from_str(&zkp.to_json().unwrap()).unwrap();

        assert_eq!(
            parsed_json["nullifier_hash"].as_str().unwrap(),
            "0x11d194ff98df5c8e239e6b6e33cce7fb1b419344cb13e064350a917970c8fea4"
        );
        assert_eq!(
            parsed_json["merkle_root"].as_str().unwrap(),
            "0x2f3a95b6df9074a19bf46e2308d7f5696e9dca49e0d64ef49a1425bbf40e0c02"
        );

        // ensure the proof is automatically encoded as packed
        let packed_proof_pattern = r"^0x[a-f0-9]{400,600}$";
        let re = Regex::new(packed_proof_pattern).unwrap();
        assert!(re.is_match(parsed_json["proof"].as_str().unwrap()));
    }
}
