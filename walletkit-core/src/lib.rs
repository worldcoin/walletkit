//! `walletkit-core` contains the basic primitives for using a World ID.
//! Enables basic usage of a World ID to generate ZKPs using different credentials.
#![deny(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]

use strum::EnumString;

/// Represents the environment in which a World ID is being presented and used.
///
/// Each environment uses different sources of truth for the World ID credentials.
///
/// More information on testing for the World ID Protocol can be found in: `https://docs.world.org/world-id/quick-start/testing`
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum, EnumString)]
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

uniffi::setup_scaffolding!("walletkit_core");
