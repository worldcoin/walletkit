//! Account management for World ID credential storage.
//!
//! This module provides the account lifecycle APIs including:
//!
//! - [`WorldIdStore`] — Root store managing multiple accounts on a device
//! - [`AccountHandle`] — Handle to an open account for credential operations
//!
//! # Account Lifecycle
//!
//! ```ignore
//! // Open the store
//! let store = WorldIdStore::open(platform)?;
//!
//! // Create a new account
//! let handle = store.create_account()?;
//! let account_id = handle.account_id();
//!
//! // Later, open an existing account
//! let handle = store.open_account(&account_id)?;
//!
//! // Use key derivation
//! let issuer_blind = handle.derive_issuer_blind(schema_id)?;
//! let session_r = handle.derive_session_r(rp_id, action_id)?;
//! ```
//!
//! # Storage Layout
//!
//! ```text
//! <root>/worldid/
//!   accounts/
//!     <account_id_hex>/
//!       account_state.bin     # AEAD(K_device, AccountState)
//!       pending_actions.bin   # AEAD(K_device, PendingActionStore)
//!       account.vault         # Custom container (see vault module)
//! ```

mod derivation;
mod handle;
mod state;
mod store;

pub use derivation::{
    compute_action_scope, compute_request_id, derive_account_id, derive_issuer_blind,
    derive_session_r, generate_blind_seeds, generate_device_id,
};
pub use handle::AccountHandle;
pub use state::{load_account_state, save_account_state, wrap_vault_key, unwrap_vault_key};
pub use store::WorldIdStore;
