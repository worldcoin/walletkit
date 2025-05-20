//! `walletkit-core` contains the basic primitives for using a World ID.
//! It enables basic usage of a World ID to generate ZKPs using different credentials.
//!
//! # Examples
//! ```rust
//! use walletkit::{proof::ProofContext, CredentialType, Environment, world_id::WorldId};
//! async fn example() {
//!     let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
//!     let context = ProofContext::new("app_ce4cb73cb75fc3b73b71ffb4de178410", Some("my_action".to_string()), None, CredentialType::Orb);
//!     let proof = world_id.generate_proof(&context).await.unwrap();
//!     dbg!(proof.to_json()); // the JSON output can be passed to the Developer Portal, World ID contracts, etc. for verification
//! }
//! ```
#![deny(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]

use strum::EnumString;

/// Represents the environment in which a World ID is being presented and used.
///
/// Each environment uses different sources of truth for the World ID credentials.
///
/// More information on testing for the World ID Protocol can be found in: `https://docs.world.org/world-id/quick-start/testing`
#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[strum(serialize_all = "lowercase")]
pub enum Environment {
    /// For testing purposes ONLY.
    Staging,
    /// Live production environment. World ID Tree: `id.worldcoin.eth`
    Production,
}

mod credential_type;
pub use credential_type::CredentialType;

/// Contains error outputs from `WalletKit`
pub mod error;

/// Contains all components to interact and use a World ID
pub mod world_id;

/// This module handles World ID proof generation
pub mod proof;

mod u256;
pub use u256::U256Wrapper;

////////////////////////////////////////////////////////////////////////////////
// Private modules
////////////////////////////////////////////////////////////////////////////////

mod merkle_tree;
mod request;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!("walletkit_core");
