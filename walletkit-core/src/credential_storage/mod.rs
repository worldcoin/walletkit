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
//! [`DeviceKeystore`]: platform::DeviceKeystore
//! [`AtomicBlobStore`]: platform::AtomicBlobStore
//! [`VaultFileStore`]: platform::VaultFileStore
//! [`AccountLockManager`]: platform::AccountLockManager

mod error;
pub mod platform;
mod types;
pub mod vault;

pub use error::StorageError;
pub use types::*;

// Re-export key vault types for convenience
pub use vault::{VaultFile, VaultKey, VaultTxn};

/// Result type alias for credential storage operations.
pub type StorageResult<T> = Result<T, StorageError>;
