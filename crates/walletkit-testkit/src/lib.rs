//! `walletkit-testkit` — reusable end-to-end test helpers for World ID v4.

pub mod authenticator;
pub mod env;
pub mod issuer;
pub mod proof;
pub mod storage;
pub mod utils;

use std::{
    future::Future,
    path::Path,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::primitives::Address;
pub use env::TestEnv;
use eyre::Context;
use walletkit_core::{
    storage::CredentialStore, Authenticator, Credential, FieldElement,
};
pub use world_id_core::primitives::SessionId;
pub use world_id_core::requests::ProofType;

use crate::{
    authenticator::{init_authenticator, register_account},
    issuer::{
        issue_custom_credential, issue_faux_credential, issue_local_credential,
        IssuedCredential,
    },
    proof::{build_test_request, verify_proof_onchain, VerifyItemResult},
    utils::now_secs,
};

/// Time-to-live applied to generated test proof requests.
const REQUEST_TTL_SECS: u64 = 300;

/// Initializes an authenticator and registers an account.
///
/// # Errors
///
/// Returns an error if account registration or authenticator initialization
/// fails.
pub async fn init_and_register_account(
    env: &TestEnv,
    seed: &[u8],
    root: &Path,
    recovery_address: Option<Address>,
) -> eyre::Result<(Authenticator, Arc<CredentialStore>)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    register_account(env, seed, recovery_address)
        .await
        .wrap_err("account registration failed")?;
    let (authenticator, store) = init_authenticator(env, seed, root, now)
        .await
        .wrap_err("authenticator initialization failed")?;

    Ok((authenticator, store))
}

/// Boxed future produced by a custom credential-issuing closure.
type CredentialFuture = Pin<Box<dyn Future<Output = eyre::Result<Credential>> + Send>>;

/// Boxed async closure that turns a derived `sub` into an issued credential.
type IssueCredentialFn = Box<dyn FnOnce(FieldElement) -> CredentialFuture + Send>;

/// Type of credential to issue.
pub enum CredentialType {
    /// Local credential issued by the local `EdDSA` issuer.
    Local {
        /// The time the credential was issued.
        genesis_issued_at: u64,
        /// The time the credential expires.
        expires_at: u64,
    },
    /// Faux credential issued by the faux issuer.
    Faux,
    /// Custom credential issued by a custom issuer.
    Custom {
        /// The schema ID of the credential.
        schema_id: u64,
        /// A closure that turns a derived `sub` into an issued credential.
        issue_fn: IssueCredentialFn,
    },
}

impl CredentialType {
    /// Returns the issuer schema ID a credential of this type will be issued under.
    #[must_use]
    pub const fn issuer_schema_id(&self, env: &TestEnv) -> u64 {
        match self {
            Self::Local { .. } => env.local_issuer_schema_id,
            Self::Faux => env.faux_issuer_schema_id,
            Self::Custom { schema_id, .. } => *schema_id,
        }
    }
}

/// Outcome of [`generate_and_verify_test_proof`].
#[derive(Debug, Clone)]
pub struct TestProofOutcome {
    /// Local store ID of the issued credential.
    pub credential_id: u64,
    /// On-chain verification result for the single issued credential.
    pub verification: VerifyItemResult,
    /// Session ID from the proof response (`None` for uniqueness proofs).
    ///
    /// For `ProofType::CreateSession` this is the newly created session, which
    /// can be passed to a follow-up `ProofType::Session` request.
    pub session_id: Option<SessionId>,
}

impl TestProofOutcome {
    /// Returns `true` if the issued credential's proof verified on-chain.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verification.result.is_ok()
    }
}

/// Issues a credential of the given type.
///
/// # Errors
///
/// Returns an error if the credential issuance fails.
pub async fn issue_credential(
    env: &TestEnv,
    credential_type: CredentialType,
    authenticator: &Authenticator,
    store: &CredentialStore,
) -> eyre::Result<IssuedCredential> {
    match credential_type {
        CredentialType::Local {
            genesis_issued_at,
            expires_at,
        } => {
            issue_local_credential(
                env,
                authenticator,
                store,
                genesis_issued_at,
                expires_at,
            )
            .await
        }
        CredentialType::Faux => issue_faux_credential(env, authenticator, store).await,
        CredentialType::Custom {
            schema_id,
            issue_fn,
        } => issue_custom_credential(authenticator, store, schema_id, issue_fn).await,
    }
}

/// Registers an account, issues a credential of this type, generates a proof
/// of `proof_type` for `signal`, and verifies it on-chain.
///
/// For `ProofType::Session`, pass the `session_id` of an existing session
/// (e.g. from a prior `ProofType::CreateSession` outcome); otherwise pass
/// `None`.
///
/// # Errors
///
/// Returns an error if account setup, credential issuance, proof generation,
/// on-chain verification setup fails, or if `proof_type` and `session_id`
/// are inconsistent.
pub async fn generate_and_verify_test_proof(
    credential_type: CredentialType,
    env: &TestEnv,
    seed: &[u8],
    root: &Path,
    signal: &str,
    proof_type: ProofType,
    session_id: Option<SessionId>,
) -> eyre::Result<TestProofOutcome> {
    let issuer_schema_id = credential_type.issuer_schema_id(env);

    let (authenticator, store) =
        init_and_register_account(env, seed, root, Some(Address::ZERO))
            .await
            .wrap_err("account setup failed")?;

    let credential_id = issue_credential(env, credential_type, &authenticator, &store)
        .await
        .wrap_err("credential issuance failed")?
        .credential_id;

    let core_request = build_test_request(
        env,
        issuer_schema_id,
        signal,
        REQUEST_TTL_SECS,
        proof_type,
        session_id,
    )
    .wrap_err("failed to build proof request")?;

    let walletkit_request: walletkit_core::requests::ProofRequest =
        core_request.clone().into();
    let proof_response = authenticator
        .generate_proof(&walletkit_request, Some(now_secs()))
        .await
        .wrap_err("proof generation failed")?;
    let response = proof_response.into_inner();

    let mut results = verify_proof_onchain(env, &core_request, &response)
        .await
        .wrap_err("on-chain verification failed")?;
    eyre::ensure!(
        results.len() == 1,
        "expected exactly one verification result, got {}",
        results.len()
    );

    Ok(TestProofOutcome {
        credential_id,
        verification: results.remove(0),
        session_id: response.session_id,
    })
}
