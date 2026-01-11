//! Platform abstraction traits for credential storage.
//!
//! This module defines the platform-provided capabilities that the storage
//! engine depends on. Each platform (iOS, Android, Node.js, Browser) must
//! provide implementations of these traits.
//!
//! # Overview
//!
//! The storage engine is designed to be platform-agnostic. All platform-specific
//! operations are abstracted behind traits:
//!
//! - [`DeviceKeystore`] — Hardware-backed encryption for device-protected state
//! - [`AtomicBlobStore`] — Atomic file operations for small configuration files
//! - [`VaultFileStore`] — Random-access file operations for the vault container
//! - [`AccountLockManager`] — Per-account locking for serialized writes
//!
//! # Platform Implementations
//!
//! Each platform should provide default implementations:
//!
//! ## iOS (Swift)
//! - `DeviceKeystore`: Keychain Services
//! - `AtomicBlobStore`: Application Support directory with atomic rename
//! - `VaultFileStore`: File handles in app container
//! - `AccountLockManager`: File locks
//!
//! ## Android (Kotlin)
//! - `DeviceKeystore`: Android Keystore
//! - `AtomicBlobStore`: Internal storage with atomic rename
//! - `VaultFileStore`: File handles in internal storage
//! - `AccountLockManager`: File locks
//!
//! ## Node.js
//! - `DeviceKeystore`: File-backed with device key
//! - `AtomicBlobStore`: Filesystem with atomic rename
//! - `VaultFileStore`: File handles
//! - `AccountLockManager`: File locks
//!
//! ## Browser (WASM)
//! - `DeviceKeystore`: `WebCrypto` with `IndexedDB`
//! - `AtomicBlobStore`: Origin-Private File System (OPFS)
//! - `VaultFileStore`: OPFS with `FileSystemSyncAccessHandle`
//! - `AccountLockManager`: Web Locks API

mod blob_store;
mod keystore;
mod lock_manager;
pub mod memory;
mod vault_store;

pub use blob_store::AtomicBlobStore;
pub use keystore::DeviceKeystore;
pub use lock_manager::AccountLockManager;
pub use vault_store::VaultFileStore;

// Re-export memory implementations for testing
pub use memory::MemoryPlatform;

// Platform-specific implementations

/// iOS platform implementation using Keychain and file system.
#[cfg(feature = "platform-ios")]
pub mod ios;

#[cfg(feature = "platform-ios")]
pub use ios::{IosBlobStore, IosKeystore, IosLockManager, IosPlatform, IosVaultStore};
