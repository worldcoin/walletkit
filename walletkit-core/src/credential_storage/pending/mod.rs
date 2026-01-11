//! Pending action tracking for nullifier protection.
//!
//! This module implements the nullifier single-use enforcement required by
//! the World ID 4.0 protocol. It ensures that an Authenticator never discloses
//! the same nullifier in more than one distinct proof package.
//!
//! # Architecture
//!
//! The system has two components:
//!
//! 1. **PendingActionStore** — A device-protected store tracking in-progress
//!    proof disclosures. Entries are short-lived (15 min TTL) and limited
//!    to 16 concurrent pending actions.
//!
//! 2. **OnpClient** — Interface to the Oblivious Nullifier Pool (ONP) service
//!    for privacy-preserving nullifier consumption checks.
//!
//! # Invariant
//!
//! An Authenticator must not disclose the same nullifier in more than one
//! distinct proof package. The only permitted retransmission is returning
//! the **exact same** `proof_package` bytes for the same `request_id` while
//! an action is in progress.
//!
//! # Flow
//!
//! ```text
//! 1. begin_action_disclosure(rp_id, action_id, request, nullifier, proof)
//!    ├─ Check pending store for existing action
//!    │  ├─ Same request_id → Return stored proof (idempotent replay)
//!    │  └─ Different request_id, not expired → Error (action already pending)
//!    ├─ Check ONP if nullifier consumed → Error if consumed
//!    ├─ Store in pending store
//!    └─ Return proof_package
//!
//! 2. commit_action(rp_id, action_id)
//!    ├─ Get pending entry
//!    ├─ Mark nullifier consumed in ONP
//!    └─ Remove from pending store
//!
//! 3. cancel_action(rp_id, action_id)
//!    └─ Remove from pending store (no ONP interaction)
//! ```
//!
//! # Scoping
//!
//! - `action_scope = SHA256("worldid:action-scope" || rp_id || action_id)`
//! - `request_id = SHA256("worldid:proof-request" || signed_request_bytes)`

mod onp;
mod store;

pub use onp::{InMemoryOnpClient, OnpClient, StubOnpClient};
pub use store::{load_pending_actions, save_pending_actions, PENDING_ACTIONS_FILENAME};
