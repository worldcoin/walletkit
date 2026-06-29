//! Authenticator setup helpers.
//!
//! [`init_authenticator`] builds a filesystem-backed [`Authenticator`] ready to
//! generate proofs (cached Groth16 materials + `init_with_defaults` +
//! `init_storage`), mirroring the CLI's setup. [`register_account`] registers
//! (or initializes) the on-chain account via [`CoreAuthenticator::init_or_register`]
//! and returns its `leaf_index`, which the local-`EdDSA` issuer needs to build a
//! credential subject.

use std::path::Path;
use std::sync::Arc;

use alloy::primitives::Address;
use eyre::WrapErr as _;
use walletkit_core::storage::{cache_embedded_groth16_material, CredentialStore};
use walletkit_core::{defaults, Authenticator, Groth16Materials};
use world_id_core::Authenticator as CoreAuthenticator;

use crate::env::TestEnv;
use crate::storage::create_fs_credential_store;

/// Initializes a filesystem-backed [`Authenticator`] and its [`CredentialStore`].
///
/// Creates an [`crate::storage::FsStorageProvider`]-backed store rooted at
/// `root`, caches the embedded Groth16 materials, initializes the authenticator
/// with SDK defaults for `env`'s environment and RPC, and runs `init_storage`
/// with the given `now` (unix seconds).
/// Note: The on-chain account must already be registered in the `WorldIDRegistry`,
/// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
///
/// # Errors
///
/// Returns an error if the store, materials cache, authenticator init, or
/// storage init fails.
pub async fn init_authenticator(
    env: &TestEnv,
    seed: &[u8],
    root: &Path,
    now: u64,
) -> eyre::Result<(Arc<Authenticator>, Arc<CredentialStore>)> {
    let store = create_fs_credential_store(root)?;
    let paths = store.storage_paths()?;
    cache_embedded_groth16_material(&paths)?;
    let materials = Arc::new(
        Groth16Materials::from_cache(Arc::new(paths))
            .wrap_err("failed to load cached Groth16 materials")?,
    );

    let authenticator = Authenticator::init_with_config(
        seed,
        env.world_id_config.clone(),
        materials,
        store.clone(),
    )
    .await
    .wrap_err("authenticator init failed")?;

    authenticator
        .init_storage(now)
        .wrap_err("storage init failed")?;

    Ok((Arc::new(authenticator), store))
}

/// Registers (or initializes) the on-chain account and returns its `leaf_index`.
///
/// Wraps [`CoreAuthenticator::init_or_register`] against `env`'s environment and
/// RPC. I.e. the account is registered only if it doesn't exist yet. A new account
/// can be created by using a fresh seed.
///
/// # Errors
///
/// Returns an error if the staging config cannot be built or if account
/// creation/init fails.
pub async fn register_account(
    env: &TestEnv,
    seed: &[u8],
    recovery_address: Option<Address>,
) -> eyre::Result<u64> {
    let core_authenticator = CoreAuthenticator::init_or_register(
        seed,
        env.world_id_config.clone(),
        recovery_address,
    )
    .await
    .wrap_err("account creation/init failed")?;

    Ok(core_authenticator.leaf_index())
}
