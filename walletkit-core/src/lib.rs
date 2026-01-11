//! `walletkit-core` contains the basic primitives for using a World ID.
//! It enables basic usage of a World ID to generate ZKPs using different credentials.
//!
//! # Examples
//! ```rust
//! use walletkit_core::{proof::ProofContext, CredentialType, Environment, world_id::WorldId};
//! async fn example() {
//!     let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
//!     let context = ProofContext::new("app_ce4cb73cb75fc3b73b71ffb4de178410", Some("my_action".to_string()), None, CredentialType::Orb);
//!     let proof = world_id.generate_proof(&context).await.unwrap();
//!     println!("{}", proof.to_json().unwrap()); // the JSON output can be passed to the Developer Portal, World ID contracts, etc. for verification
//! }
//! ```
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

use strum::EnumString;

/// Represents the environment in which a World ID is being presented and used.
///
/// Each environment uses different sources of truth for the World ID credentials.
///
/// More information on testing for the World ID Protocol can be found in: `https://docs.world.org/world-id/quick-start/testing`
#[derive(Debug, Clone, PartialEq, Eq, EnumString, uniffi::Enum)]
#[strum(serialize_all = "lowercase")]
pub enum Environment {
    /// For testing purposes ONLY.
    Staging,
    /// Live production environment. World ID Tree: `id.worldcoin.eth`
    Production,
}

pub(crate) mod primitives;

mod credential_type;
pub use credential_type::CredentialType;

/// Contains error outputs from `WalletKit`
pub mod error;

/// Contains logging functionality that can be integrated with foreign language bindings.
pub mod logger;

mod u256;
pub use u256::U256Wrapper;

#[cfg(feature = "v4")]
mod authenticator;
#[cfg(feature = "v4")]
pub use authenticator::Authenticator;

#[cfg(feature = "v4")]
pub(crate) mod defaults;

////////////////////////////////////////////////////////////////////////////////
// Legacy modules
////////////////////////////////////////////////////////////////////////////////

/// Contains all components to interact and use a World ID
pub mod world_id;

/// This module handles World ID proof generation
pub mod proof;

/// This module exposes helper functions to interact with common apps & contracts related to the World ID Protocol.
#[cfg(feature = "common-apps")]
pub mod common_apps;

////////////////////////////////////////////////////////////////////////////////
// Private modules
////////////////////////////////////////////////////////////////////////////////

mod merkle_tree;
mod request;

/// Credential storage system for World ID v4.0.
///
/// This module provides secure, crash-safe storage for World ID credentials
/// with support for multi-device sync and privacy-preserving nullifier handling.
pub mod credential_storage;

uniffi::setup_scaffolding!("walletkit_core");
