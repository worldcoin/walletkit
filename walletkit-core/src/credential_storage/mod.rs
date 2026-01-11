//! World ID Credential Storage v2
//!
//! This module implements secure, crash-safe storage for World ID credentials.
//! It provides a consistent API for storing different credential types across
//! multiple devices while preserving privacy and supporting device-to-device sync.
//!
//! # Architecture
//!
//! The storage system has three layers:
//!
//! 1. **Account State** (device-protected) — Small per-device state including seeds
//!    for deterministic derivation and a device-wrapped vault key.
//!
//! 2. **Account Vault** (shared, E2E encrypted) — A single per-account container file
//!    (`account.vault`) holding the credential corpus and canonical index.
//!
//! 3. **Merkle Proof Cache** (in-memory) — Short-lived cache for performance.
//!
//! # Platform Integration
//!
//! The storage engine depends on platform-provided capabilities through traits:
//!
//! - [`DeviceKeystore`] — Hardware-backed encryption for device-protected state
//! - [`AtomicBlobStore`] — Atomic file operations for small files
//! - [`VaultFileStore`] — Random-access file operations for the vault container
//! - [`AccountLockManager`] — Per-account locking for serialized writes
//!
//! # Account Management
//!
//! The account module provides high-level APIs for managing World ID accounts:
//!
//! - [`WorldIdStore`] — Root store managing multiple accounts on a device
//! - [`AccountHandle`] — Handle to an open account for credential operations
//!
//! # Vault Engine
//!
//! The vault engine provides crash-safe storage with the following guarantees:
//!
//! - **Atomic transactions**: All mutations occur within a transaction
//! - **Crash safety**: Interrupted transactions have no effect
//! - **Append-only**: Records are only appended, never modified in place
//! - **Dual superblocks**: A/B superblock scheme for atomic root updates
//!
//! See the [`vault`] module for details.
//!
//! # Example
//!
//! ```ignore
//! use walletkit_core::credential_storage::{
//!     WorldIdStore, AccountHandle, platform::MemoryPlatform,
//! };
//!
//! // Create a store with in-memory platform (for testing)
//! let store = WorldIdStore::new(keystore, platform, lock_manager);
//!
//! // Create a new account
//! let handle = store.create_account()?;
//! let account_id = handle.account_id();
//!
//! // Derive keys for credential operations
//! let issuer_blind = handle.derive_issuer_blind(schema_id);
//! let session_r = handle.derive_session_r(&rp_id, &action_id);
//!
//! // Access vault for credential storage
//! handle.vault_mut().with_txn(|txn| {
//!     // Store credentials...
//!     Ok(())
//! })?;
//! ```
//!
//! [`DeviceKeystore`]: platform::DeviceKeystore
//! [`AtomicBlobStore`]: platform::AtomicBlobStore
//! [`VaultFileStore`]: platform::VaultFileStore
//! [`AccountLockManager`]: platform::AccountLockManager
//! [`WorldIdStore`]: account::WorldIdStore
//! [`AccountHandle`]: account::AccountHandle

pub mod account;
mod error;
pub mod pending;
pub mod platform;
pub mod provisioning;
pub mod transfer;
mod types;
pub mod vault;

pub use error::StorageError;
pub use types::*;

// Re-export key vault types for convenience
pub use vault::{VaultFile, VaultKey, VaultTxn};

// Re-export key account types for convenience
pub use account::{AccountHandle, WorldIdStore};

// Re-export key pending types for convenience
pub use pending::{OnpClient, StubOnpClient};

// Re-export key provisioning types for convenience
pub use provisioning::{DeviceKeyPair, ProvisioningPayload};

// Re-export key transfer types for convenience
pub use transfer::{ImportDecision, TransferPayload, TRANSFER_VERSION};

/// Result type alias for credential storage operations.
pub type StorageResult<T> = Result<T, StorageError>;
