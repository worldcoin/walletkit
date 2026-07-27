//! Test credential acquisition.
use std::future::Future;

use eyre::WrapErr as _;
use walletkit_core::storage::CredentialStore;
use walletkit_core::{Authenticator, Credential, FieldElement};
use world_id_core::{
    Credential as CoreCredential, EdDSAPrivateKey, FieldElement as CoreFieldElement,
};

use crate::env::TestEnv;
use crate::utils::now_secs;

/// A credential issued by one of the issuer helpers, together with its local
/// store id and the blinding factor used to derive its subject.
pub struct IssuedCredential {
    /// Local store id of the issued credential.
    pub credential_id: u64,
    /// The issued credential.
    pub credential: Credential,
    /// Blinding factor used to derive the credential subject.
    pub blinding_factor: FieldElement,
}

/// Result of importing an externally-issued credential.
#[derive(Debug, Clone)]
pub struct ImportedCredential {
    /// Local store id of the imported credential.
    pub credential_id: u64,
    /// Blinding factor stored with the credential.
    pub blinding_factor: FieldElement,
}

/// Builds an unsigned base credential with subject derived from `leaf_index`
/// and `blinding_factor`.
///
/// The caller is responsible for setting the issuer and signature before use.
#[must_use]
pub fn build_base_credential(
    issuer_schema_id: u64,
    leaf_index: u64,
    genesis_issued_at: u64,
    expires_at: u64,
    blinding_factor: CoreFieldElement,
) -> CoreCredential {
    let sub = CoreCredential::compute_sub(leaf_index, blinding_factor);
    CoreCredential::new()
        .issuer_schema_id(issuer_schema_id)
        .subject(sub)
        .genesis_issued_at(genesis_issued_at)
        .expires_at(expires_at)
}

/// Imports an **externally-issued** credential into `store`.
///
/// If `blinding_factor` is `None`, it will be generated via OPRF.
///
/// # Errors
///
/// Returns an error if blinding-factor generation or storing the credential
/// fails.
pub async fn import_credential(
    store: &CredentialStore,
    authenticator: &Authenticator,
    credential: &Credential,
    blinding_factor: Option<&FieldElement>,
    associated_data: Option<Vec<u8>>,
) -> eyre::Result<ImportedCredential> {
    let blinding_factor = match blinding_factor {
        Some(bf) => bf.clone(),
        None => authenticator
            .generate_credential_blinding_factor_remote(credential.issuer_schema_id())
            .await
            .wrap_err("blinding factor generation failed")?,
    };

    let credential_id = store
        .store_credential(
            credential,
            &blinding_factor,
            credential.expires_at(),
            associated_data,
            now_secs(),
        )
        .wrap_err("store credential failed")?;

    Ok(ImportedCredential {
        credential_id,
        blinding_factor,
    })
}

/// Issues a credential from the faux issuer and stores it.
///
/// Generates a blinding factor via OPRF, requests a credential for the derived
/// subject.
///
/// # Errors
///
/// Returns an error if blinding-factor generation, the faux-issuer request, the
/// response parsing, or storing the credential fails.
pub async fn issue_faux_credential(
    env: &TestEnv,
    authenticator: &Authenticator,
    store: &CredentialStore,
) -> eyre::Result<IssuedCredential> {
    let blinding_factor = authenticator
        .generate_credential_blinding_factor_remote(env.faux_issuer_schema_id)
        .await
        .wrap_err("blinding factor generation failed")?;

    let sub_hex = authenticator
        .compute_credential_sub(&blinding_factor)
        .to_hex_string();

    let client = reqwest::Client::new();
    let resp = client
        .post(&env.faux_issuer_url)
        .json(&serde_json::json!({ "sub": sub_hex }))
        .send()
        .await
        .wrap_err("faux issuer request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eyre::bail!("faux issuer returned {status}: {body}");
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .wrap_err("failed to parse faux issuer response")?;

    let cred_value = body.get("credential").ok_or_else(|| {
        eyre::eyre!("faux issuer response missing 'credential' field")
    })?;

    let cred_bytes =
        serde_json::to_vec(cred_value).wrap_err("failed to serialize credential")?;
    let cred = Credential::from_bytes(cred_bytes)
        .wrap_err("invalid credential from faux issuer")?;
    let expires_at = cred.expires_at();

    let credential_id = store
        .store_credential(&cred, &blinding_factor, expires_at, None, now_secs())
        .wrap_err("store credential failed")?;

    Ok(IssuedCredential {
        credential_id,
        credential: cred,
        blinding_factor,
    })
}

/// Issues a credential signed locally by the staging issuer's `EdDSA` key
/// (schema 47) and stores it.
///
/// Generates a blinding factor via OPRF, builds a credential subject from
/// `leaf_index`, signs it with the configured issuer key, and stores it with
/// `genesis_issued_at` and `expires_at`.
///
/// # Errors
///
/// Returns an error if blinding-factor generation, credential hashing, or
/// storing the credential fails.
pub async fn issue_local_credential(
    env: &TestEnv,
    authenticator: &Authenticator,
    store: &CredentialStore,
    genesis_issued_at: u64,
    expires_at: u64,
) -> eyre::Result<IssuedCredential> {
    let issuer_secret_key = EdDSAPrivateKey::from_bytes(env.local_issuer_eddsa_key);
    let issuer_public_key = issuer_secret_key.public();

    let bf = authenticator
        .generate_credential_blinding_factor_remote(env.local_issuer_schema_id)
        .await
        .wrap_err("blinding factor generation failed")?;

    let mut credential = build_base_credential(
        env.local_issuer_schema_id,
        authenticator.leaf_index(),
        genesis_issued_at,
        expires_at,
        bf.0,
    );
    credential.issuer = issuer_public_key;
    let credential_hash = credential.hash().wrap_err("failed to hash credential")?;
    credential.signature = Some(issuer_secret_key.sign(*credential_hash));

    let walletkit_credential: Credential = credential.into();
    let credential_id = store
        .store_credential(&walletkit_credential, &bf, expires_at, None, now_secs())
        .wrap_err("store credential failed")?;

    Ok(IssuedCredential {
        credential_id,
        credential: walletkit_credential,
        blinding_factor: bf,
    })
}

/// Issues a credential from a custom issuer and stores it.
///
/// Generates a blinding factor via OPRF, builds a credential subject from
/// the blinding factor, and stores the returned credential.
///
/// # Errors
///
/// Returns an error if blinding-factor generation, credential issuance, or storing the credential fails.
pub async fn issue_custom_credential<F, Fut>(
    authenticator: &Authenticator,
    store: &CredentialStore,
    schema_id: u64,
    issue_credential: F,
) -> eyre::Result<IssuedCredential>
where
    F: FnOnce(FieldElement) -> Fut + Send,
    Fut: Future<Output = eyre::Result<Credential>> + Send,
{
    let bf = authenticator
        .generate_credential_blinding_factor_remote(schema_id)
        .await
        .wrap_err("blinding factor generation failed")?;
    let sub = authenticator.compute_credential_sub(&bf);
    let credential = issue_credential(sub)
        .await
        .wrap_err("Failed to issue credential")?;
    let credential_id = store
        .store_credential(&credential, &bf, credential.expires_at(), None, now_secs())
        .wrap_err("store credential failed")?;

    Ok(IssuedCredential {
        credential_id,
        credential,
        blinding_factor: bf,
    })
}
