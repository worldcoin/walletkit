//! Test credential acquisition.
//!
//! Three interchangeable credential sources, all producing a [`CredentialInfo`]
//! stored in the provided [`CredentialStore`]:
//!
//! - [`issue_faux_credential`] — calls the hosted faux issuer over HTTP
//!   (schema 128). Exercises the real hosted issuer service.
//! - [`issue_local_credential`] — signs a credential locally with the
//!   registered staging issuer's `EdDSA` key (schema 47). Deterministic and
//!   service-independent, but requires the account `leaf_index` (see
//!   [`crate::authenticator::register_account`]).
//! - [`import_credential`] — stores a credential issued **externally** (e.g. by
//!   the orb enrollment backend), pairing it with the blinding factor used to
//!   derive its `sub`. [`import_credential_rederiving_bf`] re-fetches that
//!   blinding factor from the OPRF nodes when the caller did not retain it.

use eyre::WrapErr as _;
use walletkit_core::storage::CredentialStore;
use walletkit_core::{Authenticator, Credential, FieldElement};
use world_id_core::{
    Credential as CoreCredential, EdDSAPrivateKey, FieldElement as CoreFieldElement,
};

use crate::env::TestEnv;

/// Small struct to return credential information for the issued/ stored credential.
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    /// Local store ID assigned to the stored credential.
    pub credential_id: u64,
    /// Issuer schema ID the credential was issued under.
    pub issuer_schema_id: u64,
    /// Blinding factor used to derive the credential subject.
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

/// Issues a credential from the faux issuer and stores it.
///
/// Generates a blinding factor via OPRF, requests a credential for the derived
/// subject, and stores the returned credential with `now` (unix seconds) as the
/// reference time.
///
/// # Errors
///
/// Returns an error if blinding-factor generation, the faux-issuer request, the
/// response parsing, or storing the credential fails.
pub async fn issue_faux_credential(
    env: &TestEnv,
    authenticator: &Authenticator,
    store: &CredentialStore,
    now: u64,
) -> eyre::Result<CredentialInfo> {
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
        .store_credential(&cred, &blinding_factor, expires_at, None, now)
        .wrap_err("store credential failed")?;

    Ok(CredentialInfo {
        credential_id,
        issuer_schema_id: env.faux_issuer_schema_id,
        blinding_factor,
    })
}

/// Issues a credential signed locally by the staging issuer's `EdDSA` key
/// (schema 47) and stores it.
///
/// Generates a blinding factor via OPRF, builds a credential subject from
/// `leaf_index`, signs it with the configured issuer key, and stores it with
/// `now` (unix seconds) as the reference time. `genesis_issued_at` and
/// `expires_at` are set explicitly on the credential.
///
/// # Errors
///
/// Returns an error if blinding-factor generation, credential hashing, or
/// storing the credential fails.
pub async fn issue_local_credential(
    env: &TestEnv,
    authenticator: &Authenticator,
    store: &CredentialStore,
    leaf_index: u64,
    now: u64,
    genesis_issued_at: u64,
    expires_at: u64,
) -> eyre::Result<CredentialInfo> {
    let issuer_secret_key = EdDSAPrivateKey::from_bytes(env.local_issuer_eddsa_key);
    let issuer_public_key = issuer_secret_key.public();

    let bf = authenticator
        .generate_credential_blinding_factor_remote(env.local_issuer_schema_id)
        .await
        .wrap_err("blinding factor generation failed")?;

    let mut credential = build_base_credential(
        env.local_issuer_schema_id,
        leaf_index,
        genesis_issued_at,
        expires_at,
        bf.0,
    );
    credential.issuer = issuer_public_key;
    let credential_hash = credential.hash().wrap_err("failed to hash credential")?;
    credential.signature = Some(issuer_secret_key.sign(*credential_hash));

    let walletkit_credential: Credential = credential.into();
    let credential_id = store
        .store_credential(&walletkit_credential, &bf, expires_at, None, now)
        .wrap_err("store credential failed")?;

    Ok(CredentialInfo {
        credential_id,
        issuer_schema_id: env.local_issuer_schema_id,
        blinding_factor: bf,
    })
}

/// Imports an **externally-issued** credential into `store`.
///
/// The credential is paired with the `blinding_factor` that was used to derive
/// its `sub` (the caller necessarily holds it, since the `sub` must be computed
/// and sent to the issuer before issuance). This is the third credential source
/// alongside [`issue_faux_credential`] / [`issue_local_credential`], e.g. for a
/// real credential obtained from the orb enrollment backend.
///
/// `now` (unix seconds) is the store reference time. `associated_data` is passed
/// through to `store_credential` (issuance uses `None`; orb-tools used an empty
/// `Some(vec![])`). `issuer_schema_id` and `expires_at` are read off the
/// credential.
///
/// # Errors
///
/// Returns an error if storing the credential fails.
pub fn import_credential(
    store: &CredentialStore,
    credential: &Credential,
    blinding_factor: &FieldElement,
    associated_data: Option<Vec<u8>>,
    now: u64,
) -> eyre::Result<CredentialInfo> {
    let credential_id = store
        .store_credential(
            credential,
            blinding_factor,
            credential.expires_at(),
            associated_data,
            now,
        )
        .wrap_err("store credential failed")?;

    Ok(CredentialInfo {
        credential_id,
        issuer_schema_id: credential.issuer_schema_id(),
        blinding_factor: blinding_factor.clone(),
    })
}

/// Re-derives the blinding factor from the OPRF nodes, then imports `credential`.
///
/// Use only when the blinding factor was not retained; prefer
/// [`import_credential`] otherwise (re-derivation costs an extra OPRF
/// round-trip). The OPRF-derived blinding factor is deterministic for a given
/// authenticator identity and schema id, so it can be reproduced.
///
/// `bf_schema_id` MUST be the `issuer_schema_id` that was passed when the
/// credential's `sub` was originally generated — this can differ from
/// [`Credential::issuer_schema_id`]. The re-derived factor is checked against
/// the credential's `sub` and a mismatch is an error, so a wrong `bf_schema_id`
/// fails loudly here rather than silently storing an unprovable credential.
///
/// # Errors
///
/// Returns an error if the blinding-factor re-derivation fails, if the
/// re-derived factor does not reproduce the credential's `sub`, or if storing
/// the credential fails.
pub async fn import_credential_rederiving_bf(
    authenticator: &Authenticator,
    store: &CredentialStore,
    credential: &Credential,
    bf_schema_id: u64,
    associated_data: Option<Vec<u8>>,
    now: u64,
) -> eyre::Result<CredentialInfo> {
    let bf = authenticator
        .generate_credential_blinding_factor_remote(bf_schema_id)
        .await
        .wrap_err("blinding factor re-derivation failed")?;

    if authenticator.compute_credential_sub(&bf).to_hex_string()
        != credential.sub().to_hex_string()
    {
        eyre::bail!(
            "re-derived blinding factor does not match credential sub \
             (wrong bf_schema_id={bf_schema_id}?)"
        );
    }

    import_credential(store, credential, &bf, associated_data, now)
}
