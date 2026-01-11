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
//! [`DeviceKeystore`]: platform::DeviceKeystore
//! [`AtomicBlobStore`]: platform::AtomicBlobStore
//! [`VaultFileStore`]: platform::VaultFileStore
//! [`AccountLockManager`]: platform::AccountLockManager

mod error;
pub mod platform;
mod types;

pub use error::StorageError;
pub use types::*;

/// Result type alias for credential storage operations.
pub type StorageResult<T> = Result<T, StorageError>;
