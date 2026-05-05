//! Storage lock for serializing writes.
//!
//! Re-export of the generic primitive provided by [`walletkit_secure_store`].
//! Kept under the `StorageLock` / `StorageLockGuard` names for stability
//! within `walletkit-core`.

pub use walletkit_secure_store::{Lock as StorageLock, LockGuard as StorageLockGuard};
