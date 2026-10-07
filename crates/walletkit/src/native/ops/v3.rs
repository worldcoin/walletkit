//! Legacy World ID v3: identities, proof contexts, proofs, and Merkle proofs.

use super::{reveal, Secret};
use crate::native::{error::Result, operation::Operation};
use std::sync::Arc;
use walletkit_core::{
    v3::{
        common_apps::AddressBook,
        proof::{ProofContext, ProofOutput},
        world_id::WorldId,
        CredentialType, MerkleTreeProof,
    },
    Environment, Uint256,
};
#[cfg(feature = "jni")]
use walletkit_jni_macros::jni_export;

/// `AddressBook.create`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn address_book_new() -> Arc<AddressBook> {
    Arc::new(AddressBook::new())
}

/// `AddressBook.generateProofContext`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn address_book_generate_proof_context(
    address_book: Arc<AddressBook>,
    address_to_verify: String,
    timestamp: u64,
) -> Result<Arc<ProofContext>> {
    let context = address_book.generate_proof_context(&address_to_verify, timestamp)?;
    Ok(Arc::new(context))
}

/// `WorldId.create`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn world_id_new(secret: Secret, environment: Environment) -> Arc<WorldId> {
    Arc::new(WorldId::new(reveal(secret), &environment))
}

/// `WorldId.generateNullifierHash`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn world_id_generate_nullifier_hash(
    world_id: Arc<WorldId>,
    context: Arc<ProofContext>,
) -> Uint256 {
    world_id.generate_nullifier_hash(&context)
}

/// `WorldId.getIdentityCommitment`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn world_id_get_identity_commitment(
    world_id: Arc<WorldId>,
    credential_type: CredentialType,
) -> Uint256 {
    world_id.get_identity_commitment(&credential_type)
}

/// `WorldId.generateProof`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn world_id_generate_proof(
    operation: Operation,
    world_id: Arc<WorldId>,
    context: Arc<ProofContext>,
) -> Result<Arc<ProofOutput>> {
    operation.run(async move { Ok(Arc::new(world_id.generate_proof(&context).await?)) })
}

/// `WorldId.isEqualTo`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn world_id_is_equal_to(world_id: Arc<WorldId>, other: Arc<WorldId>) -> bool {
    world_id.is_equal_to(&other)
}

/// `ProofContext.create`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_new(
    app_id: String,
    action: Option<String>,
    signal: Option<String>,
    credential_type: CredentialType,
) -> Arc<ProofContext> {
    Arc::new(ProofContext::new(&app_id, action, signal, credential_type))
}

/// `ProofContext.newFromBytes`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_new_from_bytes(
    app_id: String,
    action: Option<Vec<u8>>,
    signal: Option<Vec<u8>>,
    credential_type: CredentialType,
) -> Arc<ProofContext> {
    Arc::new(ProofContext::new_from_bytes(
        &app_id,
        action,
        signal,
        credential_type,
    ))
}

/// `ProofContext.newFromSignalHash`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_new_from_signal_hash(
    app_id: String,
    action: Option<Vec<u8>>,
    credential_type: CredentialType,
    signal_hash: Uint256,
) -> Result<Arc<ProofContext>> {
    let context = ProofContext::new_from_signal_hash(
        &app_id,
        action,
        credential_type,
        &signal_hash,
    )?;
    Ok(Arc::new(context))
}

/// `ProofContext.legacyNewFromPreImageExternalNullifier`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_legacy_new_from_pre_image_external_nullifier(
    external_nullifier: Vec<u8>,
    credential_type: CredentialType,
    signal: Option<Vec<u8>>,
    require_mined_proof: bool,
) -> Arc<ProofContext> {
    Arc::new(ProofContext::legacy_new_from_pre_image_external_nullifier(
        &external_nullifier,
        credential_type,
        signal,
        require_mined_proof,
    ))
}

/// `ProofContext.legacyNewFromRawExternalNullifier`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_legacy_new_from_raw_external_nullifier(
    external_nullifier: Uint256,
    credential_type: CredentialType,
    signal: Option<Vec<u8>>,
    require_mined_proof: bool,
) -> Result<Arc<ProofContext>> {
    let context = ProofContext::legacy_new_from_raw_external_nullifier(
        &external_nullifier,
        credential_type,
        signal,
        require_mined_proof,
    )?;
    Ok(Arc::new(context))
}

/// `ProofContext.getExternalNullifier`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_get_external_nullifier(context: Arc<ProofContext>) -> Uint256 {
    context.get_external_nullifier()
}

/// `ProofContext.getSignalHash`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_get_signal_hash(context: Arc<ProofContext>) -> Uint256 {
    context.get_signal_hash()
}

/// `ProofContext.getCredentialType`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_context_get_credential_type(context: Arc<ProofContext>) -> CredentialType {
    context.get_credential_type()
}

/// `ProofOutput.toJson`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_output_to_json(output: Arc<ProofOutput>) -> Result<String> {
    Ok(output.to_json()?)
}

/// `ProofOutput.getNullifierHash`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_output_get_nullifier_hash(output: Arc<ProofOutput>) -> Uint256 {
    output.get_nullifier_hash()
}

/// `ProofOutput.getMerkleRoot`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_output_get_merkle_root(output: Arc<ProofOutput>) -> Uint256 {
    output.get_merkle_root()
}

/// `ProofOutput.getProofAsString`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_output_get_proof_as_string(output: Arc<ProofOutput>) -> String {
    output.get_proof_as_string()
}

/// `ProofOutput.getCredentialType`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_output_get_credential_type(output: Arc<ProofOutput>) -> CredentialType {
    output.get_credential_type()
}

/// `MerkleTreeProof.fromIdentityCommitment`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn merkle_tree_proof_from_identity_commitment(
    operation: Operation,
    identity_commitment: Uint256,
    sequencer_host: String,
    require_mined_proof: bool,
) -> Result<Arc<MerkleTreeProof>> {
    operation.run(async move {
        let proof = MerkleTreeProof::from_identity_commitment(
            &identity_commitment,
            &sequencer_host,
            require_mined_proof,
        )
        .await?;
        Ok(Arc::new(proof))
    })
}

/// `MerkleTreeProof.fromJsonProof`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn merkle_tree_proof_from_json_proof(
    json_proof: String,
    merkle_root: String,
) -> Result<Arc<MerkleTreeProof>> {
    Ok(Arc::new(MerkleTreeProof::from_json_proof(
        &json_proof,
        &merkle_root,
    )?))
}
