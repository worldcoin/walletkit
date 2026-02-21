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

/// Library initialization function called automatically on load.
///
/// Installs the ring crypto provider as the default for rustls.
/// Uses the `ctor` crate to ensure this runs when the dynamic library loads,
/// before any user code executes.
#[cfg(not(test))]
#[ctor::ctor]
fn init() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");
}

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

/// Region for node selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
pub enum Region {
    /// United States
    Us,
    /// Europe (default)
    #[default]
    Eu,
    /// Asia-Pacific
    Ap,
}

/// Contains error outputs from `WalletKit`
pub mod error;

/// Contains logging functionality that can be integrated with foreign language bindings.
pub mod logger;

mod u256;
pub use u256::U256Wrapper;

mod field_element;
pub use field_element::FieldElement;

mod credential;
pub use credential::Credential;

/// Credential storage primitives for World ID v4.
#[cfg(feature = "storage")]
pub mod storage;

mod authenticator;
pub use authenticator::{Authenticator, InitializingAuthenticator, RegistrationStatus};

/// Default configuration values for each [`Environment`].
pub mod defaults;

/// Proof requests and responses in World ID v4.
pub mod requests;

/// Credential issuers for World ID (NFC, etc.)
#[cfg(feature = "issuers")]
pub mod issuers;

/// Legacy World ID 3.0 Proofs
#[cfg(feature = "v3")]
pub mod v3;

////////////////////////////////////////////////////////////////////////////////
// Private modules
////////////////////////////////////////////////////////////////////////////////

mod http_request;
pub(crate) mod primitives;

uniffi::setup_scaffolding!("walletkit_core");
