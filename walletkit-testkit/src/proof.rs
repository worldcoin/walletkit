//! Proof-request construction and on-chain verification.
//!
//! [`build_test_request`] assembles a [`ProofRequest`] signed by the staging RP
//! key from a [`TestEnv`], replacing the hardcoded constants the CLI and
//! integration tests previously carried. On-chain verification (added alongside)
//! checks a request/response pair against the staging `WorldIDVerifier`.

use alloy::signers::{local::PrivateKeySigner, SignerSync};
use eyre::WrapErr as _;
use rand::rngs::OsRng;
use world_id_core::primitives::{rp::RpId, FieldElement, SessionId};
use world_id_core::requests::{ProofRequest, ProofType, RequestItem, RequestVersion};

use crate::env::TestEnv;

/// Builds a proof [`ProofRequest`] signed by the RP key configured in `env`.
///
/// `now` is the request's `created_at` (unix seconds); the request expires at
/// `now + expires_in`. For uniqueness proofs an `action` of `1` is set and
/// included in the RP signature; session proofs carry no action. Pass an
/// existing `session_id` for [`ProofType::Session`].
///
/// # Errors
///
/// Returns an error if the RP signer cannot be constructed from the configured
/// key, if signing the RP message fails, or if the `oprf_key_id` cannot be
/// derived from the RP id.
pub fn build_test_request(
    env: &TestEnv,
    issuer_schema_id: u64,
    signal: &str,
    now: u64,
    expires_in: u64,
    proof_type: ProofType,
    session_id: Option<SessionId>,
) -> eyre::Result<ProofRequest> {
    let nonce = FieldElement::random(&mut OsRng);
    let created_at = now;
    let expires_at = now + expires_in;

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

    let request_item = RequestItem::new(
        "test".to_string(),
        issuer_schema_id,
        Some(signal.as_bytes().to_vec()),
        None,
        None,
    );

    Ok(ProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        proof_type,
        created_at,
        expires_at,
        rp_id: RpId::new(env.rp_id),
        oprf_key_id: serde_json::from_value(serde_json::json!(format!(
            "0x{:040x}",
            env.rp_id
        )))
        .wrap_err("failed to construct oprf_key_id")?,
        session_id,
        action,
        signature,
        nonce,
        requests: vec![request_item],
        constraints: None,
    })
}
