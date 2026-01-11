//! Vault file engine for World ID credential storage.
//!
//! This module implements the crash-safe vault file format with append-only
//! records and atomic superblock commits.
//!
//! # File Structure
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │              FileHeader (48 bytes)       │  offset 0
//! ├──────────────────────────────────────────┤
//! │           SuperblockA (53 bytes)         │  offset 48
//! ├──────────────────────────────────────────┤
//! │           SuperblockB (53 bytes)         │  offset 101
//! ├──────────────────────────────────────────┤
//! │                                          │
//! │         Data Region (append-only)        │  offset 154+
//! │                                          │
//! │   - TxnBegin records                     │
//! │   - EncryptedBlobObject records          │
//! │   - EncryptedIndexSnapshot records       │
//! │   - TxnCommit records                    │
//! │                                          │
//! └──────────────────────────────────────────┘
//! ```
//!
//! # Transaction Semantics
//!
//! All mutations occur within a transaction:
//! 1. Append `TxnBegin`
//! 2. Append zero or more `EncryptedBlobObject` records
//! 3. Append exactly one `EncryptedIndexSnapshot`
//! 4. Append `TxnCommit` referencing the index
//! 5. Atomically publish by writing the next superblock (A or B)
//!
//! Crash behavior:
//! - Before superblock publish: transaction is ignored
//! - After superblock publish: vault opens at committed transaction

mod crypto;
mod file;
mod format;
mod header;
mod records;
mod transaction;

pub use crypto::{compute_content_id, vault_decrypt, vault_encrypt, VaultKey};
pub use file::VaultFile;
pub use format::*;
pub use header::{select_active_superblock, FileHeader, Superblock, SuperblockSlot};
pub use records::{
    EncryptedBlobObject, EncryptedIndexSnapshot, RecordEnvelope, TxnBegin, TxnCommit,
};
pub use transaction::VaultTxn;
