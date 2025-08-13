use crate::error::WalletKitError;

use alloy_core::sol_types::SolValue;
use semaphore_rs::{
    hash_to_field, identity,
    packed_proof::PackedProof,
    protocol::{generate_nullifier_hash, generate_proof, Proof},
};

use semaphore_rs::MODULUS;

use serde::Serialize;

use crate::{
    credential_type::CredentialType, merkle_tree::MerkleTreeProof, u256::U256Wrapper,
};

/// A `ProofContext` contains the basic information on the verifier and the specific action a user will be proving.
///
/// It is required to generate a `Proof` and will generally be initialized from an `app_id` and `action`.
///
/// Note on naming: `ProofContext` is used to make it clear in FFIs which may not respect the module structure.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "ffi", derive(uniffi::Object))]
pub struct ProofContext {
    /// The `external_nullifier` is the computed result of a specific context for which a World ID Proof is generated.
    /// It is used in the Sempahore ZK circuit and in the computation of the `nullifier_hash` to guarantee uniqueness in a privacy-preserving way.
    pub external_nullifier: U256Wrapper,
    /// Represents the specific credential to be used for a World ID Proof.
    pub credential_type: CredentialType,
    /// The hashed signal which is included in the ZKP and committed to in the proof.
    /// When verifying the proof, the same signal must be provided.
    pub signal_hash: U256Wrapper,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
impl ProofContext {
    /// Initializes a `ProofContext`.
    ///
    /// Will compute the relevant external nullifier from the provided `app_id` and `action` as defined by the
    /// World ID Protocol. The external nullifier generation matches the logic in the
    /// [Developer Portal](https://github.com/worldcoin/developer-portal/blob/main/web/lib/hashing.ts).
    ///
    /// # Arguments
    ///
    /// * `app_id` - The ID of the application requesting proofs.  This can be obtained from the [Developer Portal](https://developer.world.org).
    /// * `action` - Optional. Custom incognito action being requested.
    /// * `signal` - Optional. The signal is included in the ZKP and is committed to in the proof. When verifying the proof, the
    ///   same signal must be provided to ensure the proof is valid. The signal can be used to prevent replay attacks, MITM or other cases.
    ///   More details available in the [docs](https://docs.world.org/world-id/further-reading/zero-knowledge-proofs).
    /// * `credential_type` - The type of credential being requested.
    ///
    #[must_use]
    #[cfg_attr(feature = "ffi", uniffi::constructor)]
    pub fn new(
        app_id: &str,
        action: Option<String>,
        signal: Option<String>,
        credential_type: CredentialType,
    ) -> Self {
        Self::new_from_bytes(
            app_id,
            action.map(std::string::String::into_bytes),
            signal.map(std::string::String::into_bytes),
            credential_type,
        )
    }

    /// Initializes a `Proof::ProofContext` where the `action` is provided as raw bytes. This is useful for advanced cases
    /// where the `action` is an already ABI encoded value for on-chain usage.
    /// See _walletkit-core/tests/solidity.rs_ for an example.
    ///
    /// Will compute the relevant external nullifier from the provided `app_id` and `action`.
    ///
    /// # Arguments
    ///
    /// See `ProofContext::new` for reference. The `action` and `signal` need to be provided as raw bytes.
    ///
    #[must_use]
    #[cfg_attr(feature = "ffi", uniffi::constructor)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new_from_bytes(
        app_id: &str,
        action: Option<Vec<u8>>,
        signal: Option<Vec<u8>>,
        credential_type: CredentialType,
    ) -> Self {
        let signal_hash =
            U256Wrapper::from(hash_to_field(signal.unwrap_or_default().as_slice()));

        Self::new_from_signal_hash_unchecked(
            app_id,
            action,
            credential_type,
            &signal_hash,
        )
    }

    /// Initializes a `ProofContext` from an already hashed signal.
    ///
    /// Please note it is imperative to hash into the Semaphore field. Not all U256 are part of the field.
    /// Use the `hash_to_field` function to hash into the field.
    ///
    /// # Usage
    /// - This may be used when the hash of the signal is computed externally.
    /// - For example, this is used for support of legacy `MiniKit` v1 commands in World App where `minikit-js` hashed the signal.
    ///
    /// # Arguments
    ///
    /// * `app_id` - The ID of the application requesting proofs.  This can be obtained from the [Developer Portal](https://developer.world.org).
    /// * `action` - Optional. Custom incognito action being requested as bytes.
    /// * `credential_type` - The type of credential being requested.
    /// * `signal` - The already hashed signal as a field element.
    ///
    /// # Errors
    ///
    /// - Returns an error if the signal is not a valid number in the field.
    #[cfg_attr(feature = "ffi", uniffi::constructor)]
    pub fn new_from_signal_hash(
        app_id: &str,
        action: Option<Vec<u8>>,
        credential_type: CredentialType,
        signal_hash: &U256Wrapper,
    ) -> Result<Self, WalletKitError> {
        if signal_hash.0 >= MODULUS {
            return Err(WalletKitError::InvalidNumber);
        }

        Ok(Self::new_from_signal_hash_unchecked(
            app_id,
            action,
            credential_type,
            signal_hash,
        ))
    }

    /// Get the raw external nullifier for this context.
    #[must_use]
    pub const fn get_external_nullifier(&self) -> U256Wrapper {
        self.external_nullifier
    }

    /// Get the signal hash for this context.
    #[must_use]
    pub const fn get_signal_hash(&self) -> U256Wrapper {
        self.signal_hash
    }

    /// Get the credential type for this context.
    #[must_use]
    pub const fn get_credential_type(&self) -> CredentialType {
        self.credential_type
    }
}

// This impl block is not exported to foreign bindings.
impl ProofContext {
    fn new_from_signal_hash_unchecked(
        app_id: &str,
        action: Option<Vec<u8>>,
        credential_type: CredentialType,
        signal_hash: &U256Wrapper,
    ) -> Self {
        let mut pre_image = hash_to_field(app_id.as_bytes()).abi_encode_packed();

        if let Some(action) = action {
            pre_image.extend_from_slice(&action);
        }

        let external_nullifier = hash_to_field(&pre_image).into();

        Self {
            external_nullifier,
            credential_type,
            signal_hash: *signal_hash,
        }
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
#[cfg(feature = "legacy-nullifiers")]
impl ProofContext {
    /// LEGACY AND ADVANCED USE ONLY.
    ///
    /// Initializes a `ProofContext` from an arbitrary pre-image for an external nullifier.
    ///
    /// This is used for legacy nullifiers which were constructed from arbitrary bytes which don't follow
    /// the `app_id` and `action` standard.
    ///
    /// # Usage (Non-exhaustive)
    ///
    /// - This is used for the World ID Address Book.
    ///
    /// # Arguments
    ///
    /// * `external_nullifier` - An arbitrary array of bytes that will be hashed to produce the external nullifier.
    /// * `credential_type` - The type of credential being requested.
    /// * `signal` - Optional. The signal is included in the ZKP and is committed to in the proof.
    #[must_use]
    #[cfg_attr(feature = "ffi", uniffi::constructor)]
    pub fn legacy_new_from_pre_image_external_nullifier(
        external_nullifier: &[u8],
        credential_type: CredentialType,
        signal: Option<Vec<u8>>,
    ) -> Self {
        let external_nullifier: U256Wrapper = hash_to_field(external_nullifier).into();
        Self {
            external_nullifier,
            credential_type,
            signal_hash: hash_to_field(signal.unwrap_or_default().as_slice()).into(),
        }
    }

    /// LEGACY AND ADVANCED USE ONLY.
    ///
    /// Initializes a `ProofContext` from a raw external nullifier.
    ///
    /// This is used for legacy nullifiers which were constructed from raw field elements.
    ///
    /// # Usage (Non-exhaustive)
    ///
    /// - This is used for Recurring Grant Claims (Worldcoin Airdrop).
    /// - This is used to verify a World App account.
    ///
    /// # Arguments
    ///
    /// * `external_nullifier` - The raw external nullifier. Must already be a number in the field. No additional hashing is performed.
    /// * `credential_type` - The type of credential being requested.
    /// * `signal` - Optional. The signal is included in the ZKP and is committed to in the proof.
    ///
    /// # Errors
    ///
    /// - Returns an error if the external nullifier is not a valid number in the field.
    #[cfg_attr(feature = "ffi", uniffi::constructor)]
    pub fn legacy_new_from_raw_external_nullifier(
        external_nullifier: &U256Wrapper,
        credential_type: CredentialType,
        signal: Option<Vec<u8>>,
    ) -> Result<Self, WalletKitError> {
        if external_nullifier.0 >= MODULUS {
            return Err(WalletKitError::InvalidNumber);
        }

        Ok(Self {
            external_nullifier: *external_nullifier,
            credential_type,
            signal_hash: hash_to_field(signal.unwrap_or_default().as_slice()).into(),
        })
    }
}

/// Represents the complete output of a World ID Proof (i.e. a credential persentation). This output
/// can be serialized to JSON and can be verified easily with the Developer Portal or Sign up Sequencer.
///
/// For on-chain verification, the `proof` (which is packed) should generally be deserialized into `uint256[8]`.
///
/// More information on: [On-Chain Verification](https://docs.world.org/world-id/id/on-chain)
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Object))]
#[allow(clippy::module_name_repetitions)]
pub struct ProofOutput {
    /// The root hash of the Merkle tree used to prove membership. This root hash should match published hashes in the World ID
    ///     protocol contract in Ethereum mainnet. See [address book](https://docs.world.org/world-id/reference/address-book).
    pub merkle_root: U256Wrapper,
    /// Represents the unique identifier for a specific context (app & action) and World ID. A World ID holder will always generate
    /// the same `nullifier_hash` for the same context.
    pub nullifier_hash: U256Wrapper,
    /// The raw zero-knowledge proof.
    #[serde(skip_serializing)]
    pub raw_proof: Proof,
    /// The ABI-encoded zero-knowledge proof represented as a string. This is the format generally used with other libraries and
    /// can be directly used with the Developer Portal for verification.
    pub proof: PackedProof,
    /// The credential type used to generate the proof.
    pub credential_type: CredentialType,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
impl ProofOutput {
    /// Converts the entire proof output to a JSON string with standard attribute names.
    ///
    /// # Errors
    /// Will error if serialization fails.
    pub fn to_json(&self) -> Result<String, WalletKitError> {
        serde_json::to_string(self).map_err(|_| WalletKitError::SerializationError)
    }

    /// Exposes the nullifier hash to foreign code. Struct fields are not directly exposed to foreign code.
    #[must_use]
    pub const fn get_nullifier_hash(&self) -> U256Wrapper {
        self.nullifier_hash
    }

    /// Exposes the merkle root to foreign code. Struct fields are not directly exposed to foreign code.
    #[must_use]
    pub const fn get_merkle_root(&self) -> U256Wrapper {
        self.merkle_root
    }

    /// Exposes the proof as a string to foreign code. Struct fields are not directly exposed to foreign code.
    #[must_use]
    pub fn get_proof_as_string(&self) -> String {
        self.proof.to_string()
    }

    /// Exposes the credential type to foreign code. Struct fields are not directly exposed to foreign code.
    #[must_use]
    pub const fn get_credential_type(&self) -> CredentialType {
        self.credential_type
    }
}

/// Generates a Semaphore ZKP for a specific Semaphore identity using the relevant provided context.
///
/// **Requires the `semaphore` feature flag.**
///
/// # Errors
/// Returns an error if proof generation fails
pub fn generate_proof_with_semaphore_identity(
    identity: &identity::Identity,
    merkle_tree_proof: &MerkleTreeProof,
    context: &ProofContext,
) -> Result<ProofOutput, WalletKitError> {
    #[cfg(not(feature = "semaphore"))]
    return Err(WalletKitError::SemaphoreNotEnabled);

    let merkle_root = merkle_tree_proof.merkle_root; // clone the value

    let external_nullifier_hash = context.external_nullifier.into();
    let nullifier_hash =
        generate_nullifier_hash(identity, external_nullifier_hash).into();

    let proof = generate_proof(
        identity,
        merkle_tree_proof.as_poseidon_proof(),
        external_nullifier_hash,
        context.signal_hash.into(),
    )?;

    Ok(ProofOutput {
        merkle_root,
        nullifier_hash,
        raw_proof: proof,
        proof: PackedProof::from(proof),
        credential_type: context.credential_type,
    })
}

#[cfg(test)]
mod external_nullifier_tests {
    use alloy_core::primitives::address;
    use ruint::{aliases::U256, uint};

    use super::*;

    #[test]
    fn test_context_and_external_nullifier_hash_generation() {
        let context = ProofContext::new(
            "app_369183bd38f1641b6964ab51d7a20434",
            None,
            None,
            CredentialType::Orb,
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x0073e4a6b670e81dc619b1f8703aa7491dc5aaadf75409aba0ac2414014c0227"
        );

        // note the same external nullifier hash is generated for an empty string action
        let context = ProofContext::new(
            "app_369183bd38f1641b6964ab51d7a20434",
            Some(String::new()),
            None,
            CredentialType::Orb,
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
        let context = ProofContext::new(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some("test-action-qli8g".to_string()),
            None,
            CredentialType::Orb,
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x00d8b157e767dc59faa533120ed0ce34fc51a71937292ea8baed6ee6f4fda866"
        );
    }

    #[test]
    fn test_external_nullifier_hash_generation_string_action() {
        let context = ProofContext::new(
            "app_10eb12bd96d8f7202892ff25f094c803",
            Some("test-123123".to_string()),
            None,
            CredentialType::Orb,
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

        let context = ProofContext::new_from_bytes(
            "app_10eb12bd96d8f7202892ff25f094c803",
            Some(custom_action),
            None,
            CredentialType::Orb,
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

        let context = ProofContext::new_from_bytes(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some(custom_action),
            None,
            CredentialType::Orb,
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            // expected output obtained from Solidity
            "0x005b49f95e822c7c37f4f043421689b11f880e617faa5cd0391803bc9bcc63c0"
        );
    }

    #[cfg(feature = "legacy-nullifiers")]
    #[test]
    fn test_proof_generation_with_legacy_nullifier_address_book() {
        let context = ProofContext::legacy_new_from_pre_image_external_nullifier(
            b"internal_addressbook",
            CredentialType::Device,
            None,
        );

        // the expected nullifier hash from the contract
        // reference: <https://worldchain-mainnet.explorer.alchemy.com/tx/0x974e70f125abe3b6abaa0b3fb9cb067c09cee359b08fa847487d6623377308fd>
        let expected = uint!(377593556987874043165400752883455722895901692332643678318174569531027326541_U256);
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            format!("{expected:#066x}")
        );
    }

    #[cfg(feature = "legacy-nullifiers")]
    #[test]
    fn test_proof_generation_with_legacy_nullifier_recurring_grant_drop() {
        let grant_id = 48;

        // The constant which is added to all the Grant IDs in World Chain.
        // Reference: <https://github.com/worldcoin/worldcoin-grants-contracts/blob/main/src/RecurringGrantDrop.sol#L22>
        let worldchain_nullifier_hash_constant = uint!(
            0x1E00000000000000000000000000000000000000000000000000000000000000_U256
        );
        let external_nullifier_hash =
            worldchain_nullifier_hash_constant + U256::from(grant_id);

        let context = ProofContext::legacy_new_from_raw_external_nullifier(
            &external_nullifier_hash.into(),
            CredentialType::Device,
            None,
        )
        .unwrap();

        // the expected nullifier hash from the contract
        // transaction example for RGD 48: <https://worldscan.org/tx/0xbad696a88c5425a22af18ea6d00efca78ae0f5c5cceade21597adf60126a5fc4>
        let expected = uint!(13569385457497991651199724805705614201555076328004753598373935625927319879728_U256);
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            format!("{expected:#066x}")
        );
    }

    #[cfg(feature = "legacy-nullifiers")]
    #[test]
    fn test_ensure_raw_external_nullifier_is_in_the_field() {
        let invalid_external_nullifiers = [MODULUS, MODULUS + U256::from(1)];
        for external_nullifier in invalid_external_nullifiers {
            let context = ProofContext::legacy_new_from_raw_external_nullifier(
                &external_nullifier.into(),
                CredentialType::Device,
                None,
            );
            assert!(context.is_err());
        }
    }
}

#[cfg(test)]
mod signal_tests {
    use ruint::aliases::U256;

    use super::*;

    #[test]
    fn test_ensure_raw_signal_hash_is_in_the_field() {
        let invalid_signals = [MODULUS, MODULUS + U256::from(1)];
        for signal_hash in invalid_signals {
            let context = ProofContext::new_from_signal_hash(
                "my_app_id",
                None,
                CredentialType::Device,
                &signal_hash.into(),
            );
            assert!(context.is_err());
        }
    }

    #[test]
    fn test_get_external_nullifier() {
        let context = ProofContext::new(
            "app_369183bd38f1641b6964ab51d7a20434",
            Some("test-action".to_string()),
            None,
            CredentialType::Orb,
        );

        let external_nullifier = context.get_external_nullifier();
        assert_eq!(external_nullifier, context.external_nullifier);
        assert_eq!(
            external_nullifier.to_hex_string(),
            "0x00dd12b56cebf29593d6d3208a061bbb19e60152c56045f277a15989d25d5215"
        );
    }

    #[test]
    fn test_get_signal_hash() {
        let signal = "test_signal_123".to_string();
        let context = ProofContext::new(
            "app_10eb12bd96d8f7202892ff25f094c803",
            None,
            Some(signal.clone()),
            CredentialType::Device,
        );

        let signal_hash = context.get_signal_hash();
        assert_eq!(signal_hash, context.signal_hash);

        let expected_hash = U256Wrapper::from(hash_to_field(signal.as_bytes()));
        assert_eq!(signal_hash, expected_hash);
    }

    #[test]
    fn test_get_credential_type() {
        let orb_context = ProofContext::new("app_123", None, None, CredentialType::Orb);
        assert_eq!(orb_context.get_credential_type(), CredentialType::Orb);

        let device_context =
            ProofContext::new("app_456", None, None, CredentialType::Device);
        assert_eq!(device_context.get_credential_type(), CredentialType::Device);
    }
}

#[cfg(test)]
mod proof_tests {

    use regex::Regex;
    use semaphore_rs::protocol::verify_proof;
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
        let context = ProofContext::new(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some("test-action-89tcf".to_string()),
            None,
            CredentialType::Device,
        );

        let mut secret = b"not_a_real_secret".to_vec();

        let identity = semaphore_rs::identity::Identity::from_secret(
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
            &helper_load_merkle_proof(),
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
        let context = ProofContext::new(
            "app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some("test-action-89tcf".to_string()),
            None,
            CredentialType::Device,
        );

        let mut secret = b"not_a_real_secret".to_vec();
        let identity = semaphore_rs::identity::Identity::from_secret(
            &mut secret,
            Some(context.credential_type.as_identity_trapdoor()),
        );

        // Compute ZKP
        let zkp = generate_proof_with_semaphore_identity(
            &identity,
            &helper_load_merkle_proof(),
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

        assert_eq!(parsed_json["credential_type"].as_str().unwrap(), "device");

        // ensure the proof is automatically encoded as packed
        let packed_proof_pattern = r"^0x[a-f0-9]{400,600}$";
        let re = Regex::new(packed_proof_pattern).unwrap();
        assert!(re.is_match(parsed_json["proof"].as_str().unwrap()));

        assert_eq!(
            zkp.get_nullifier_hash().to_hex_string(),
            parsed_json["nullifier_hash"].as_str().unwrap()
        );
        assert_eq!(
            zkp.get_merkle_root().to_hex_string(),
            parsed_json["merkle_root"].as_str().unwrap()
        );
        assert_eq!(
            zkp.get_proof_as_string(),
            parsed_json["proof"].as_str().unwrap()
        );
    }
}
