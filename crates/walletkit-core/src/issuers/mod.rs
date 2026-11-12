//! Logic for different specific issuers of Credentials in World ID.

#[cfg(not(target_arch = "wasm32"))]
mod ownership_proof_challenge;
mod pop_backend_client;
mod recovery_bindings_manager;
mod tfh_nfc;
#[cfg(not(target_arch = "wasm32"))]
pub use ownership_proof_challenge::{
    fetch_ownership_proof_challenge, OwnershipProofChallenge,
};
pub use tfh_nfc::TfhNfcIssuer;

pub use pop_backend_client::PopBackendClient;
pub use recovery_bindings_manager::RecoveryBinding;
pub use recovery_bindings_manager::RecoveryBindingManager;
