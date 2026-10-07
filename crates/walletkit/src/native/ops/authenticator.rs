//! Authenticator registration, initialization, recovery, proofs, and proving artifacts.

use super::{reveal, Secret};
use crate::native::{codec::Binary, error::Result, operation::Operation};
use std::sync::Arc;
use walletkit_core::{
    authenticator::{
        artifacts::WalletKitZkArtifactSource, Authenticator, GatewayRequestStatus,
        InitializingAuthenticator, RecoveryData, RecoveryUpdateSignature,
        RegistrationStatus,
    },
    requests::{ProofRequest, ProofResponse},
    storage::credential_storage::CredentialStore,
    Environment, FieldElement, OwnershipProof, Region, Uint256,
};
#[cfg(feature = "jni")]
use walletkit_jni_macros::jni_export;

/// `Authenticator.initStorage`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_init_storage(
    authenticator: Arc<Authenticator>,
    now: u64,
) -> Result<()> {
    Ok(authenticator.init_storage(now)?)
}

/// `Authenticator.destroyStorage`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_destroy_storage(authenticator: Arc<Authenticator>) -> Result<()> {
    Ok(authenticator.destroy_storage()?)
}

/// `Authenticator.packedAccountData`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_packed_account_data(authenticator: Arc<Authenticator>) -> Uint256 {
    authenticator.packed_account_data()
}

/// `Authenticator.leafIndex`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_leaf_index(authenticator: Arc<Authenticator>) -> u64 {
    authenticator.leaf_index()
}

/// `Authenticator.onchainAddress`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_onchain_address(authenticator: Arc<Authenticator>) -> String {
    authenticator.onchain_address()
}

/// `Authenticator.getPackedAccountDataRemote`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_get_packed_account_data_remote(
    operation: Operation,
    authenticator: Arc<Authenticator>,
) -> Result<Uint256> {
    operation
        .run(async move { Ok(authenticator.get_packed_account_data_remote().await?) })
}

/// `Authenticator.generateCredentialBlindingFactorRemote`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_generate_credential_blinding_factor_remote(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    issuer_schema_id: u64,
) -> Result<Arc<FieldElement>> {
    operation.run(async move {
        let factor = authenticator
            .generate_credential_blinding_factor_remote(issuer_schema_id)
            .await?;
        Ok(Arc::new(factor))
    })
}

/// `Authenticator.computeCredentialSub`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_compute_credential_sub(
    authenticator: Arc<Authenticator>,
    blinding_factor: Arc<FieldElement>,
) -> Arc<FieldElement> {
    Arc::new(authenticator.compute_credential_sub(&blinding_factor))
}

/// `Authenticator.dangerSignChallenge`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_danger_sign_challenge(
    authenticator: Arc<Authenticator>,
    challenge: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(authenticator.danger_sign_challenge(challenge)?)
}

/// `Authenticator.dangerSignInitiateRecoveryAgentUpdate`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_danger_sign_initiate_recovery_agent_update(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    new_recovery_agent: String,
) -> Result<Binary<RecoveryUpdateSignature>> {
    operation.run(async move {
        let signature = authenticator
            .danger_sign_initiate_recovery_agent_update(new_recovery_agent)
            .await?;
        Ok(Binary(signature))
    })
}

/// `Authenticator.updateRecoveryAgent`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_update_recovery_agent(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    new_recovery_agent: String,
) -> Result<String> {
    operation.run(async move {
        Ok(authenticator
            .update_recovery_agent(new_recovery_agent)
            .await?)
    })
}

/// `Authenticator.revertRecoveryAgentUpdate`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_revert_recovery_agent_update(
    operation: Operation,
    authenticator: Arc<Authenticator>,
) -> Result<String> {
    operation
        .run(async move { Ok(authenticator.revert_recovery_agent_update().await?) })
}

/// `Authenticator.insertAuthenticator`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_insert_authenticator(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    new_authenticator_pubkey: String,
    new_authenticator_address: String,
) -> Result<String> {
    operation.run(async move {
        Ok(authenticator
            .insert_authenticator(new_authenticator_pubkey, new_authenticator_address)
            .await?)
    })
}

/// `Authenticator.hasAuthenticatorPubkey`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_has_authenticator_pubkey(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    authenticator_pubkey: String,
) -> Result<bool> {
    operation.run(async move {
        Ok(authenticator
            .has_authenticator_pubkey(authenticator_pubkey)
            .await?)
    })
}

/// `Authenticator.getAuthenticatorPubkeys`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_get_authenticator_pubkeys(
    operation: Operation,
    authenticator: Arc<Authenticator>,
) -> Result<Binary<Vec<Option<String>>>> {
    operation.run(async move {
        Ok(Binary(authenticator.get_authenticator_pubkeys().await?))
    })
}

/// `Authenticator.removeAuthenticator`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_remove_authenticator(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    authenticator_address: String,
    pubkey_id: u32,
    expected_authenticator_pubkey: String,
) -> Result<String> {
    operation.run(async move {
        Ok(authenticator
            .remove_authenticator(
                authenticator_address,
                pubkey_id,
                expected_authenticator_pubkey,
            )
            .await?)
    })
}

/// `Authenticator.pollStatus`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_poll_status(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    request_id: String,
) -> Result<Binary<GatewayRequestStatus>> {
    operation
        .run(async move { Ok(Binary(authenticator.poll_status(request_id).await?)) })
}

/// `Authenticator.initWithDefaults`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_init_with_defaults(
    operation: Operation,
    seed: Secret,
    rpc_url: Option<String>,
    environment: Environment,
    region: Option<Region>,
    artifacts: Arc<dyn WalletKitZkArtifactSource>,
    store: Arc<CredentialStore>,
) -> Result<Arc<Authenticator>> {
    operation.run(async move {
        let authenticator = Authenticator::init_with_defaults(
            reveal(seed),
            rpc_url,
            &environment,
            region,
            artifacts,
            store,
        )
        .await?;
        Ok(Arc::new(authenticator))
    })
}

/// `Authenticator.initWithOhttpDefaults`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_init_with_ohttp_defaults(
    operation: Operation,
    seed: Secret,
    rpc_url: Option<String>,
    environment: Environment,
    region: Option<Region>,
    artifacts: Arc<dyn WalletKitZkArtifactSource>,
    store: Arc<CredentialStore>,
) -> Result<Arc<Authenticator>> {
    operation.run(async move {
        let authenticator = Authenticator::init_with_ohttp_defaults(
            reveal(seed),
            rpc_url,
            &environment,
            region,
            artifacts,
            store,
        )
        .await?;
        Ok(Arc::new(authenticator))
    })
}

/// `Authenticator.initialize`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_init(
    operation: Operation,
    seed: Secret,
    config: String,
    artifacts: Arc<dyn WalletKitZkArtifactSource>,
    store: Arc<CredentialStore>,
) -> Result<Arc<Authenticator>> {
    operation.run(async move {
        let authenticator =
            Authenticator::init(reveal(seed), &config, artifacts, store).await?;
        Ok(Arc::new(authenticator))
    })
}

/// `Authenticator.generateProof`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_generate_proof(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    proof_request: Arc<ProofRequest>,
    now: Option<u64>,
) -> Result<Arc<ProofResponse>> {
    operation.run(async move {
        let response = authenticator.generate_proof(&proof_request, now).await?;
        Ok(Arc::new(response))
    })
}

/// `Authenticator.proveCredentialSub`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn authenticator_prove_credential_sub(
    operation: Operation,
    authenticator: Arc<Authenticator>,
    nonce: Arc<FieldElement>,
    context: Arc<FieldElement>,
    blinding_factor: Arc<FieldElement>,
    sub: Arc<FieldElement>,
) -> Result<Arc<OwnershipProof>> {
    operation.run(async move {
        let proof = authenticator
            .prove_credential_sub(&nonce, &context, &blinding_factor, &sub)
            .await?;
        Ok(Arc::new(proof))
    })
}

/// `InitializingAuthenticator.registerWithDefaults`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn initializing_authenticator_register_with_defaults(
    operation: Operation,
    seed: Secret,
    rpc_url: Option<String>,
    environment: Environment,
    region: Option<Region>,
    recovery_address: Option<String>,
) -> Result<Arc<InitializingAuthenticator>> {
    operation.run(async move {
        let authenticator = InitializingAuthenticator::register_with_defaults(
            reveal(seed),
            rpc_url,
            &environment,
            region,
            recovery_address,
        )
        .await?;
        Ok(Arc::new(authenticator))
    })
}

/// `InitializingAuthenticator.registerWithOhttpDefaults`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn initializing_authenticator_register_with_ohttp_defaults(
    operation: Operation,
    seed: Secret,
    rpc_url: Option<String>,
    environment: Environment,
    region: Option<Region>,
    recovery_address: Option<String>,
) -> Result<Arc<InitializingAuthenticator>> {
    operation.run(async move {
        let authenticator = InitializingAuthenticator::register_with_ohttp_defaults(
            reveal(seed),
            rpc_url,
            &environment,
            region,
            recovery_address,
        )
        .await?;
        Ok(Arc::new(authenticator))
    })
}

/// `InitializingAuthenticator.register`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn initializing_authenticator_register(
    operation: Operation,
    seed: Secret,
    config: String,
    recovery_address: Option<String>,
) -> Result<Arc<InitializingAuthenticator>> {
    operation.run(async move {
        let authenticator = InitializingAuthenticator::register(
            reveal(seed),
            &config,
            recovery_address,
        )
        .await?;
        Ok(Arc::new(authenticator))
    })
}

/// `InitializingAuthenticator.pollStatus`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn initializing_authenticator_poll_status(
    operation: Operation,
    authenticator: Arc<InitializingAuthenticator>,
) -> Result<Binary<RegistrationStatus>> {
    operation.run(async move { Ok(Binary(authenticator.poll_status().await?)) })
}

/// `validateAuthenticatorPubkey`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn validate_authenticator_pubkey(authenticator_pubkey: String) -> Result<String> {
    Ok(
        walletkit_core::authenticator::validate_authenticator_pubkey(
            &authenticator_pubkey,
        )?,
    )
}

/// `recoveryDataFromSeed`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn recovery_data_from_seed(seed: Secret) -> Result<Binary<RecoveryData>> {
    Ok(Binary(
        walletkit_core::authenticator::recovery_data_from_seed(reveal(seed))?,
    ))
}

/// `EmbeddedZkArtifacts.create`.
#[cfg(feature = "embed-zkeys")]
#[cfg_attr(feature = "jni", jni_export)]
pub fn embedded_zk_artifacts_new(
) -> Arc<walletkit_core::authenticator::artifacts::embedded::EmbeddedZkArtifacts> {
    Arc::new(
        walletkit_core::authenticator::artifacts::embedded::EmbeddedZkArtifacts::new(),
    )
}

/// `EmbeddedZkArtifacts.asZkArtifactSource`.
#[cfg(feature = "embed-zkeys")]
#[cfg_attr(feature = "jni", jni_export)]
pub fn embedded_zk_artifacts_as_zk_artifact_source(
    artifacts: Arc<
        walletkit_core::authenticator::artifacts::embedded::EmbeddedZkArtifacts,
    >,
) -> Arc<dyn WalletKitZkArtifactSource> {
    artifacts.as_zk_artifact_source()
}

/// `CachingZkArtifacts.create`.
#[cfg(feature = "embed-zkeys")]
#[cfg_attr(feature = "jni", jni_export)]
pub fn caching_zk_artifacts_new(
    storage_paths: Arc<walletkit_core::storage::paths::StoragePaths>,
) -> Arc<walletkit_core::authenticator::artifacts::caching::CachingZkArtifacts> {
    Arc::new(
        walletkit_core::authenticator::artifacts::caching::CachingZkArtifacts::new(
            storage_paths,
        ),
    )
}

/// `CachingZkArtifacts.asZkArtifactSource`.
#[cfg(feature = "embed-zkeys")]
#[cfg_attr(feature = "jni", jni_export)]
pub fn caching_zk_artifacts_as_zk_artifact_source(
    artifacts: Arc<
        walletkit_core::authenticator::artifacts::caching::CachingZkArtifacts,
    >,
) -> Arc<dyn WalletKitZkArtifactSource> {
    artifacts.as_zk_artifact_source()
}

/// `CachingZkArtifacts.preload`.
#[cfg(feature = "embed-zkeys")]
#[cfg_attr(feature = "jni", jni_export)]
pub fn caching_zk_artifacts_preload(
    artifacts: Arc<
        walletkit_core::authenticator::artifacts::caching::CachingZkArtifacts,
    >,
) -> Result<()> {
    Ok(artifacts.preload()?)
}
