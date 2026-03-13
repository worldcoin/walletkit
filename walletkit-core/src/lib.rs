//! `walletkit-core` contains the basic primitives for using a World ID.
//! It enables basic usage of a World ID to generate ZKPs using different credentials.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use walletkit_core::requests::ProofRequest;
//! use walletkit_core::storage::{
//!     cache_embedded_groth16_material, CredentialStore, StoragePaths,
//! };
//! use walletkit_core::{Authenticator, Environment};
//!
//! /// Platform layer provides a [`CredentialStore`] backed by a
//! /// device-specific [`StorageProvider`](walletkit_core::storage::StorageProvider).
//! async fn generate_world_id_proof(
//!     store: Arc<CredentialStore>,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     // Cache Groth16 proving material to disk (idempotent).
//!     let paths = StoragePaths::from_root("/data/walletkit".into());
//!     cache_embedded_groth16_material(&paths)?;
//!
//!     // Initialize an authenticator for an already-registered World ID.
//!     let seed = b"my_secret_seed_at_length_32_bytes!";
//!     let authenticator = Authenticator::init_with_defaults(
//!         seed,
//!         None, // uses default RPC URL
//!         &Environment::Staging,
//!         None, // uses default region
//!         &paths,
//!         store,
//!     )
//!     .await?;
//!
//!     // Parse an incoming proof request from a relying party.
//!     let json = r#"{ "id": "req_01", "version": 1, "credentials": [] }"#;
//!     let request = ProofRequest::from_json(json)?;
//!
//!     // Generate a zero-knowledge proof and serialise the response.
//!     let response = authenticator.generate_proof(&request, None).await?;
//!     println!("{}", response.to_json()?);
//!     Ok(())
//! }
//! ```

use strum::{Display, EnumString};

/// Library initialization function called automatically on load.
///
/// Installs the ring crypto provider as the default for rustls.
/// Uses the `ctor` crate to ensure this runs when the dynamic library loads,
/// before any user code executes.
///
/// On WASM targets, rustls is not used (reqwest uses the browser fetch API).
#[cfg(all(not(test), not(target_arch = "wasm32")))]
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
#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
#[strum(serialize_all = "lowercase")]
pub enum Environment {
    /// For testing purposes ONLY.
    Staging,
    /// Live production environment. World ID Tree: `id.worldcoin.eth`
    Production,
}

/// Methods exported to Swift/Kotlin via `UniFFI`.
#[uniffi::export]
impl Environment {
    /// Returns the `PoH` Recovery Agent contract address for this environment.
    ///
    /// The `PoH` Recovery Agent is a contract users can optionally designate when
    /// registering a World ID. If they lose access to all authenticators, the
    /// agent can sign a recovery transaction to restore their account.
    #[must_use]
    pub fn poh_recovery_agent_address(&self) -> String {
        defaults::poh_recovery_agent_address(self).to_string()
    }
}

/// Region for node selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString, Display)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
#[strum(serialize_all = "lowercase")]
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

mod field_element;
pub use field_element::FieldElement;

mod credential;
pub use credential::Credential;

/// Credential storage primitives for World ID v4.
pub mod storage;

mod authenticator;
pub use authenticator::{
    Authenticator, Groth16Materials, InitializingAuthenticator, RegistrationStatus,
};

/// Default configuration values for each [`Environment`].
pub mod defaults;

/// Proof requests and responses in World ID v4.
pub mod requests;

/// Credential issuers for World ID (NFC, etc.)
#[cfg(feature = "issuers")]
pub mod issuers;

/// Legacy World ID 3.0 Proofs
///
/// # Example
/// ```rust
/// use walletkit_core::v3::{proof::ProofContext, CredentialType, world_id::WorldId};
/// use walletkit_core::Environment;
/// async fn example() {
///     let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
///     let context = ProofContext::new("app_ce4cb73cb75fc3b73b71ffb4de178410", Some("my_action".to_string()), None, CredentialType::Orb);
///     let proof = world_id.generate_proof(&context).await.unwrap();
///     println!("{}", proof.to_json().unwrap()); // the JSON output can be passed to the Developer Portal, World ID contracts, etc. for verification
/// }
#[cfg(feature = "v3")]
pub mod v3;

////////////////////////////////////////////////////////////////////////////////
// Private modules
////////////////////////////////////////////////////////////////////////////////

#[cfg(any(feature = "issuers", feature = "v3"))]
mod http_request;
pub(crate) mod primitives;

#[cfg(not(target_arch = "wasm32"))]
uniffi::setup_scaffolding!("walletkit_core");

#[cfg(not(target_arch = "wasm32"))]
ruint_uniffi::register_types!(Uint256);
