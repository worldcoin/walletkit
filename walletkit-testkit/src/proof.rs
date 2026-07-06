//! Proof-request construction and on-chain verification.

use alloy::providers::ProviderBuilder;
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol;
use alloy_core::primitives::U160;
use eyre::WrapErr as _;
use rand::rngs::OsRng;
use uuid::Uuid;
use world_id_core::primitives::{rp::RpId, FieldElement, OprfKeyId, SessionId};
use world_id_core::requests::{
    ProofRequest, ProofResponse, ProofType, RequestItem, RequestVersion,
};

use crate::env::TestEnv;
use crate::utils::now_secs;

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface IWorldIDVerifier {
        function verify(
            uint256 nullifier,
            uint256 action,
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;

        function verifySession(
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256 sessionId,
            uint256[2] calldata sessionNullifier,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;
    }
);

/// Builds a proof [`ProofRequest`] signed by the RP key configured in `env`.
///
/// The request expires at `created_at + expires_in`. For uniqueness proofs an `action` of `1` is set and
/// included in the RP signature. Pass an existing `session_id` for `ProofType::Session` proofs.
///
/// # Errors
///
/// Returns an error if the RP signer cannot be constructed from the configured
/// key, if signing the RP message fails, or if `proof_type` and `session_id`
/// are inconsistent (e.g. `ProofType::Session` without a `session_id`).
pub fn build_test_request(
    env: &TestEnv,
    issuer_schema_id: u64,
    signal: &str,
    expires_in: u64,
    proof_type: ProofType,
    session_id: Option<SessionId>,
) -> eyre::Result<ProofRequest> {
    let nonce = FieldElement::random(&mut OsRng);
    let created_at = now_secs();
    let expires_at = created_at + expires_in;

    let signer = PrivateKeySigner::from_bytes(&env.rp_signing_key.into())
        .wrap_err("failed to create RP signer")?;

    let action =
        (proof_type == ProofType::Uniqueness).then(|| FieldElement::from(1u64));
    let msg = world_id_core::primitives::rp::compute_rp_signature_msg(
        *nonce,
        created_at,
        expires_at,
        action.map(|action| *action),
    );
    let signature = signer.sign_message_sync(&msg).wrap_err("signing failed")?;

    let item_id = Uuid::new_v4().to_string();

    let request_item = RequestItem::new(
        item_id,
        issuer_schema_id,
        Some(signal.as_bytes().to_vec()),
        None,
        None,
    );

    let id = Uuid::new_v4().to_string();

    let request = ProofRequest {
        id,
        version: RequestVersion::V1,
        proof_type,
        created_at,
        expires_at,
        rp_id: RpId::new(env.rp_id),
        oprf_key_id: OprfKeyId::new(U160::from(env.rp_id)),
        session_id,
        action,
        signature,
        nonce,
        requests: vec![request_item],
        constraints: None,
    };
    request
        .validate_proof_type()
        .wrap_err("inconsistent proof_type / session_id combination")?;
    Ok(request)
}

/// Result of verifying one proof-response item against the `WorldIDVerifier`.
#[derive(Debug, Clone)]
pub struct VerifyItemResult {
    /// Issuer schema ID of the verified credential.
    pub issuer_schema_id: u64,
    /// `Ok(())` if the on-chain `verify`/`verifySession` call succeeded,
    /// `Err` with the failure details from the contract call otherwise.
    pub result: Result<(), String>,
}

/// Verifies a proof request/response pair on-chain against the configured `WorldIDVerifier`,
/// returning one `VerifyItemResult` per response item.
///
/// # Errors
///
/// Returns an error if the response carries an error, if the response does not
/// match the request, if the RPC URL is invalid, or if a required field
/// (action, session id, nullifier, session nullifier) is missing for the
/// proof type.
pub async fn verify_proof_onchain(
    env: &TestEnv,
    proof_request: &ProofRequest,
    proof_response: &ProofResponse,
) -> eyre::Result<Vec<VerifyItemResult>> {
    if let Some(ref err) = proof_response.error {
        eyre::bail!("proof response contains error: {err}");
    }
    proof_request
        .validate_response(proof_response)
        .wrap_err("proof response does not match proof request")?;

    let provider = ProviderBuilder::new().connect_http(env.rpc_url.parse()?);
    let verifier_contract = IWorldIDVerifier::new(env.world_id_verifier, &provider);

    let nonce = proof_request.nonce;
    let rp_id = proof_request.rp_id.into_inner();

    let mut results = Vec::new();
    for response_item in &proof_response.responses {
        let request_item = proof_request
            .find_request_by_issuer_schema_id(response_item.issuer_schema_id)
            .ok_or_else(|| {
                eyre::eyre!(
                    "no matching request item for issuer_schema_id={}",
                    response_item.issuer_schema_id
                )
            })?;

        let credential_genesis_issued_at_min = request_item
            .genesis_issued_at_min
            .unwrap_or_default()
            .try_into()?;

        let result = match proof_request.proof_type {
            ProofType::Uniqueness => {
                let nullifier = response_item
                    .nullifier
                    .ok_or_else(|| eyre::eyre!("response item missing nullifier"))?;
                let action = proof_request
                    .action
                    .ok_or_else(|| eyre::eyre!("proof request has no action"))?;

                verifier_contract
                    .verify(
                        nullifier.into(),
                        action.into(),
                        rp_id,
                        nonce.into(),
                        request_item.signal_hash().into(),
                        response_item.expires_at_min,
                        response_item.issuer_schema_id,
                        credential_genesis_issued_at_min,
                        response_item.proof.as_ethereum_representation(),
                    )
                    .call()
                    .await
                    .map(|_| ())
            }
            ProofType::CreateSession | ProofType::Session => {
                let session_nullifier =
                    response_item.session_nullifier.ok_or_else(|| {
                        eyre::eyre!("response item missing session_nullifier")
                    })?;
                let session_id = proof_response.session_id.ok_or_else(|| {
                    eyre::eyre!("session proof response missing session_id")
                })?;

                verifier_contract
                    .verifySession(
                        rp_id,
                        nonce.into(),
                        request_item.signal_hash().into(),
                        response_item.expires_at_min,
                        response_item.issuer_schema_id,
                        credential_genesis_issued_at_min,
                        session_id.commitment.into(),
                        session_nullifier.as_ethereum_representation(),
                        response_item.proof.as_ethereum_representation(),
                    )
                    .call()
                    .await
                    .map(|_| ())
            }
        };

        results.push(VerifyItemResult {
            issuer_schema_id: response_item.issuer_schema_id,
            result: result.map_err(|e| format!("{e:#}")),
        });
    }
    Ok(results)
}
