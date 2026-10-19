//! WIP-103 ownership proof inputs for a prover outside the authenticator.

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use world_id_core::{
    primitives::{
        merkle::{AccountInclusionProof, MerkleInclusionProof},
        poseidon::{self, ds},
        AuthenticatorPublicKeySet, TREE_DEPTH,
    },
    Credential as CoreCredential, EdDSAPrivateKey, EdDSASignature,
    FieldElement as CoreFieldElement,
};
use world_id_proof::circuit_inputs::OwnershipProofCircuitInput;

use super::{resolve_now, Authenticator};
use crate::{error::WalletKitError, FieldElement};

impl Authenticator {
    /// Builds the input of a WIP-103 Ownership Proof for `sub`, for a prover
    /// running outside this authenticator, such as an attested enclave. Use it
    /// where [`Self::prove_credential_sub`] can't run, e.g. on wasm32.
    ///
    /// # Warning
    /// The input links `sub` to this World ID account: it contains the leaf
    /// index, the account's key set, the blinding factor, and this
    /// authenticator's signature over `(sub, nonce, context)`. Send it only
    /// end-to-end encrypted to a prover trusted with that link, never to the
    /// issuer.
    ///
    /// The usage constraint of [`Self::prove_credential_sub`] applies: call
    /// this only from a direct user-initiated action.
    ///
    /// # Errors
    /// - [`WalletKitError::InvalidInput`] if `nonce` or `context` is zero, or
    ///   `sub` was not derived from this account and `blinding_factor`.
    /// - [`WalletKitError::UnauthorizedAuthenticator`] if this authenticator's
    ///   key is not in the account's key set.
    /// - A network error if the Merkle inclusion proof cannot be fetched.
    pub async fn danger_ownership_proof_input(
        &self,
        nonce: &FieldElement,
        context: &FieldElement,
        blinding_factor: &FieldElement,
        sub: &FieldElement,
        now: Option<u64>,
    ) -> Result<OwnershipProofInput, WalletKitError> {
        let now = resolve_now(now)?;
        let account_inclusion_proof =
            self.fetch_inclusion_proof_with_cache(now).await?;
        build_ownership_proof_input(
            self.signer.offchain_signer_private_key().expose_secret(),
            account_inclusion_proof,
            nonce.0,
            context.0,
            blinding_factor.0,
            sub.0,
        )
    }
}

/// The input of a WIP-103 Ownership Proof, as built by
/// [`Authenticator::danger_ownership_proof_input`].
///
/// It is secret: see the warning on that method.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OwnershipProofInput(
    #[serde(with = "OwnershipProofCircuitInputDef")]
    OwnershipProofCircuitInput<TREE_DEPTH>,
);

impl OwnershipProofInput {
    /// Encodes the input as CBOR.
    ///
    /// # Errors
    /// An encoding error is theoretically possible, should not happen in practice.
    pub fn encode(&self) -> Result<Vec<u8>, WalletKitError> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).map_err(|_| {
            WalletKitError::SerializationError {
                error: "unexpected error serializing `OwnershipProofInput`".to_string(),
            }
        })?;
        Ok(buffer)
    }

    /// Decodes an input encoded by [`Self::encode`].
    ///
    /// # Errors
    /// Returns [`WalletKitError::SerializationError`] if `bytes` is not an encoded input.
    pub fn decode(bytes: &[u8]) -> Result<Self, WalletKitError> {
        ciborium::from_reader(bytes).map_err(|_| WalletKitError::SerializationError {
            error: "invalid `OwnershipProofInput` encoding".to_string(),
        })
    }

    /// The circuit input to pass to the ownership prover.
    #[must_use]
    pub fn into_circuit_input(self) -> OwnershipProofCircuitInput<TREE_DEPTH> {
        self.0
    }
}

// Mirrors the upstream struct field by field, so an upstream field change fails to compile
// instead of silently changing the encoding.
#[derive(Serialize, Deserialize)]
#[serde(remote = "OwnershipProofCircuitInput::<TREE_DEPTH>")]
struct OwnershipProofCircuitInputDef {
    key_index: u64,
    key_set: AuthenticatorPublicKeySet,
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    nonce: CoreFieldElement,
    expected_commitment: CoreFieldElement,
    context: CoreFieldElement,
    signature: EdDSASignature,
    commitment_blinder: CoreFieldElement,
}

fn build_ownership_proof_input(
    signing_key: &EdDSAPrivateKey,
    account_inclusion_proof: AccountInclusionProof<TREE_DEPTH>,
    nonce: CoreFieldElement,
    context: CoreFieldElement,
    commitment_blinder: CoreFieldElement,
    sub: CoreFieldElement,
) -> Result<OwnershipProofInput, WalletKitError> {
    let invalid_input = |attribute: &str, reason: &str| WalletKitError::InvalidInput {
        attribute: attribute.to_string(),
        reason: reason.to_string(),
    };
    if nonce == CoreFieldElement::ZERO {
        return Err(invalid_input("nonce", "must not be zero"));
    }
    if context == CoreFieldElement::ZERO {
        return Err(invalid_input("context", "must not be zero"));
    }

    let AccountInclusionProof {
        inclusion_proof,
        authenticator_pubkeys: key_set,
    } = account_inclusion_proof;
    if CoreCredential::compute_sub(inclusion_proof.leaf_index, commitment_blinder)
        != sub
    {
        return Err(invalid_input(
            "sub",
            "does not match this account and blinding factor",
        ));
    }

    let public_key = signing_key.public();
    let key_index = key_set
        .iter()
        .position(|pk| pk.as_ref().is_some_and(|pk| pk.pk == public_key.pk))
        .ok_or(WalletKitError::UnauthorizedAuthenticator)? as u64;

    let message = poseidon::hash(ds::OWNERSHIP_PROOF, [sub, nonce, context]);

    Ok(OwnershipProofInput(OwnershipProofCircuitInput {
        key_index,
        key_set,
        inclusion_proof,
        nonce,
        expected_commitment: sub,
        context,
        signature: signing_key.sign(*message),
        commitment_blinder,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use world_id_proof::{
        artifacts::embedded::EmbeddedZkArtifacts,
        ownership_proof::{generate_ownership_proof, verify_ownership_proof},
    };

    const LEAF_INDEX: u64 = 5;

    fn signing_key() -> EdDSAPrivateKey {
        EdDSAPrivateKey::from_bytes([42u8; 32])
    }

    fn account_inclusion_proof(
        key_set: AuthenticatorPublicKeySet,
    ) -> AccountInclusionProof<TREE_DEPTH> {
        let siblings = [CoreFieldElement::ZERO; TREE_DEPTH];
        let root = siblings.iter().enumerate().fold(
            CoreFieldElement::from(key_set.leaf_hash()),
            |node, (depth, sibling)| {
                if (LEAF_INDEX >> depth) & 1 == 0 {
                    poseidon::compress(node, *sibling)
                } else {
                    poseidon::compress(*sibling, node)
                }
            },
        );
        AccountInclusionProof::new(
            MerkleInclusionProof::new(root, LEAF_INDEX, siblings),
            key_set,
        )
    }

    fn own_account() -> AccountInclusionProof<TREE_DEPTH> {
        let other = EdDSAPrivateKey::from_bytes([7u8; 32]).public();
        account_inclusion_proof(
            AuthenticatorPublicKeySet::new(vec![other, signing_key().public()])
                .unwrap(),
        )
    }

    fn input() -> OwnershipProofInput {
        let blinder = CoreFieldElement::from(999u64);
        build_ownership_proof_input(
            &signing_key(),
            own_account(),
            CoreFieldElement::from(1_234_567_890u64),
            CoreFieldElement::from(42u64),
            blinder,
            CoreCredential::compute_sub(LEAF_INDEX, blinder),
        )
        .unwrap()
    }

    #[test]
    fn decoded_input_proves_ownership() {
        let decoded = OwnershipProofInput::decode(&input().encode().unwrap()).unwrap();
        let circuit_input = decoded.into_circuit_input();
        assert_eq!(circuit_input.key_index, 1);
        let (nonce, sub, context) = (
            circuit_input.nonce,
            circuit_input.expected_commitment,
            circuit_input.context,
        );

        let proof = generate_ownership_proof(circuit_input, &EmbeddedZkArtifacts)
            .expect("proving should succeed");

        verify_ownership_proof(&proof, nonce, sub, context, &EmbeddedZkArtifacts)
            .expect("proof should verify");
        assert!(verify_ownership_proof(
            &proof,
            nonce,
            sub,
            CoreFieldElement::from(43u64),
            &EmbeddedZkArtifacts
        )
        .is_err());
    }

    #[test]
    fn encoding_is_stable() {
        let digest = Sha256::digest(input().encode().unwrap());
        assert_eq!(
            hex::encode(digest),
            "a0266e6548157a9a063f4cd7116b2f34f8eed516e2ae866360ff8dd9c614f39b"
        );
    }

    #[test]
    fn rejects_sub_of_another_blinding_factor() {
        let error = build_ownership_proof_input(
            &signing_key(),
            own_account(),
            CoreFieldElement::from(1u64),
            CoreFieldElement::from(2u64),
            CoreFieldElement::from(999u64),
            CoreCredential::compute_sub(LEAF_INDEX, CoreFieldElement::from(998u64)),
        )
        .err()
        .unwrap();
        assert!(
            matches!(error, WalletKitError::InvalidInput { attribute, .. } if attribute == "sub")
        );
    }

    #[test]
    fn rejects_zero_nonce_and_context() {
        let blinder = CoreFieldElement::from(999u64);
        let sub = CoreCredential::compute_sub(LEAF_INDEX, blinder);
        for (nonce, context, field) in [
            (
                CoreFieldElement::ZERO,
                CoreFieldElement::from(1u64),
                "nonce",
            ),
            (
                CoreFieldElement::from(1u64),
                CoreFieldElement::ZERO,
                "context",
            ),
        ] {
            let error = build_ownership_proof_input(
                &signing_key(),
                own_account(),
                nonce,
                context,
                blinder,
                sub,
            )
            .err()
            .unwrap();
            assert!(
                matches!(error, WalletKitError::InvalidInput { attribute, .. } if attribute == field)
            );
        }
    }

    #[test]
    fn rejects_authenticator_outside_the_key_set() {
        let other = EdDSAPrivateKey::from_bytes([7u8; 32]).public();
        let blinder = CoreFieldElement::from(999u64);
        let error = build_ownership_proof_input(
            &signing_key(),
            account_inclusion_proof(
                AuthenticatorPublicKeySet::new(vec![other]).unwrap(),
            ),
            CoreFieldElement::from(1u64),
            CoreFieldElement::from(2u64),
            blinder,
            CoreCredential::compute_sub(LEAF_INDEX, blinder),
        )
        .err()
        .unwrap();
        assert!(matches!(error, WalletKitError::UnauthorizedAuthenticator));
    }
}
