//! FFI bindings for credential storage.
//!
//! This module provides Swift and Kotlin bindings for the credential storage system.
//! All types exported here are designed to be FFI-safe and use simple data types
//! that can be easily represented in foreign languages.
//!
//! # Main Entry Points
//!
//! - [`WorldIdStore`] - Create and manage World ID accounts
//! - [`AccountHandle`] - Perform operations on a specific account
//!
//! # Example (Swift)
//!
//! ```swift
//! // Create the store (typically at app startup)
//! let store = try WorldIdStore(rootPath: appSupportPath)
//!
//! // Create a new account
//! let handle = try store.createAccount()
//! let accountId = handle.accountId()
//!
//! // Store a credential
//! let credId = generateCredentialId()
//! try handle.storeCredential(
//!     credentialId: credId,
//!     credentialBlob: Data("credential data".utf8),
//!     associatedData: nil
//! )
//!
//! // List credentials
//! let credentials = try handle.listCredentials(filter: CredentialFilter())
//! ```

mod error;
mod store;
mod types;

pub use error::StorageError;
pub use store::{AccountHandle, WorldIdStore};
pub use types::{
    generate_credential_id, generate_device_key_pair, AccountId, CredentialData,
    CredentialFilter, CredentialId, CredentialRecord, CredentialStatus, CredentialTransfer,
    DeviceKeyPair, ImportOutcome, PendingAction, ProvisioningEnvelope,
};
