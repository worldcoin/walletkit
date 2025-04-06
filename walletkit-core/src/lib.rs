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
pub use credential_type::*;

mod error;
pub use error::*;

mod world_id;
pub use world_id::*;

mod proof;
pub use proof::*;

mod u256;
pub use u256::*;

// private modules
mod merkle_tree;
mod request;

uniffi::setup_scaffolding!("walletkit_core");
