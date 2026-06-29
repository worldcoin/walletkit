//! `walletkit-testkit` — reusable end-to-end test helpers for World ID v4.

pub mod authenticator;
pub mod env;
pub mod flow;
pub mod issuer;
pub mod proof;
pub mod storage;

use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::primitives::Address;
pub use env::TestEnv;
use eyre::Context;
use walletkit_core::{storage::CredentialStore, Authenticator};

use crate::authenticator::{init_authenticator, register_account};

/// Initializes an authenticator and registers an account.
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

pub async fn issue_credential
