//! Oblivious Nullifier Pool (ONP) client interface.
//!
//! The ONP is a privacy-preserving service that tracks consumed nullifiers.
//! It uses Private Information Retrieval (PIR) to allow checking and marking
//! nullifiers as consumed without revealing which nullifier is being queried.
//!
//! # Protocol
//!
//! The ONP service maintains a flat list of consumed nullifiers. Clients can:
//!
//! 1. **Check** if a nullifier has been consumed (before disclosing a proof)
//! 2. **Mark** a nullifier as consumed (after the proof has been verified)
//!
//! # Privacy Properties
//!
//! The "oblivious" aspect means the ONP servers cannot learn which records
//! are being accessed, preventing them from correlating user activity.
//!
//! # Implementation Note
//!
//! The actual ONP implementation is external to WalletKit. This module defines
//! the trait interface that ONP clients must implement, plus a stub for testing.

use crate::credential_storage::StorageResult;

// =============================================================================
// OnpClient Trait
// =============================================================================

/// Client interface for the Oblivious Nullifier Pool.
///
/// The ONP service provides privacy-preserving nullifier consumption tracking.
/// Implementations must ensure:
///
/// 1. **Atomicity**: If `mark_consumed` returns `Ok`, the nullifier is durably
///    recorded as consumed.
/// 2. **Consistency**: `check_consumed` reflects all previously successful
///    `mark_consumed` calls (eventual consistency is acceptable).
/// 3. **Privacy**: The service should not learn which nullifiers are being
///    queried (via PIR or similar techniques).
///
/// # Example Implementation
///
/// ```ignore
/// struct HttpOnpClient {
///     endpoint: String,
///     // PIR parameters...
/// }
///
/// impl OnpClient for HttpOnpClient {
///     async fn check_consumed(&self, nullifier: &[u8; 32]) -> StorageResult<bool> {
///         // Perform PIR query to check nullifier status
///     }
///
///     async fn mark_consumed(&self, nullifier: &[u8; 32]) -> StorageResult<()> {
///         // Submit nullifier to be marked as consumed
///     }
/// }
/// ```
pub trait OnpClient: Send + Sync {
    /// Checks if a nullifier has been consumed.
    ///
    /// This is called before disclosing a proof to ensure the nullifier
    /// hasn't already been used.
    ///
    /// # Arguments
    ///
    /// * `nullifier` - The 32-byte nullifier to check
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the nullifier has been consumed
    /// - `Ok(false)` if the nullifier has not been consumed
    ///
    /// # Errors
    ///
    /// Returns an error if the ONP service is unavailable or the query fails.
    fn check_consumed(&self, nullifier: &[u8; 32]) -> StorageResult<bool>;

    /// Marks a nullifier as consumed.
    ///
    /// This is called after a proof has been successfully verified by the RP.
    /// Once marked, subsequent `check_consumed` calls for this nullifier
    /// should return `true`.
    ///
    /// # Arguments
    ///
    /// * `nullifier` - The 32-byte nullifier to mark as consumed
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ONP service is unavailable
    /// - The nullifier is already consumed (idempotent implementations may not error)
    /// - The operation cannot be durably recorded
    fn mark_consumed(&self, nullifier: &[u8; 32]) -> StorageResult<()>;
}

// =============================================================================
// StubOnpClient
// =============================================================================

/// Stub ONP client that always returns "not consumed".
///
/// This implementation is for testing and development environments without
/// access to a real ONP service. It provides no actual nullifier tracking.
///
/// # Warning
///
/// **DO NOT USE IN PRODUCTION** - This stub provides no nullifier protection.
/// Using it in production would allow nullifier reuse attacks.
///
/// # Example
///
/// ```
/// use walletkit_core::credential_storage::pending::StubOnpClient;
///
/// let client = StubOnpClient::new();
/// // All nullifiers will appear as not consumed
/// ```
#[derive(Debug, Clone, Default)]
pub struct StubOnpClient {
    _private: (),
}

impl StubOnpClient {
    /// Creates a new stub ONP client.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl OnpClient for StubOnpClient {
    fn check_consumed(&self, _nullifier: &[u8; 32]) -> StorageResult<bool> {
        // Stub: always returns not consumed
        Ok(false)
    }

    fn mark_consumed(&self, _nullifier: &[u8; 32]) -> StorageResult<()> {
        // Stub: no-op
        Ok(())
    }
}

// =============================================================================
// InMemoryOnpClient (for testing)
// =============================================================================

use std::collections::HashSet;
use std::sync::RwLock;

/// In-memory ONP client for testing.
///
/// This implementation tracks nullifiers in memory and provides actual
/// consumption tracking for integration tests.
///
/// # Thread Safety
///
/// This implementation is thread-safe and can be shared across threads.
///
/// # Example
///
/// ```
/// use walletkit_core::credential_storage::pending::{OnpClient, InMemoryOnpClient};
///
/// let client = InMemoryOnpClient::new();
///
/// // Initially not consumed
/// assert!(!client.check_consumed(&[0u8; 32]).unwrap());
///
/// // Mark as consumed
/// client.mark_consumed(&[0u8; 32]).unwrap();
///
/// // Now shows as consumed
/// assert!(client.check_consumed(&[0u8; 32]).unwrap());
/// ```
#[derive(Debug, Default)]
pub struct InMemoryOnpClient {
    /// Set of consumed nullifiers.
    consumed: RwLock<HashSet<[u8; 32]>>,
}

impl InMemoryOnpClient {
    /// Creates a new in-memory ONP client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            consumed: RwLock::new(HashSet::new()),
        }
    }

    /// Returns the number of consumed nullifiers.
    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed.read().unwrap().len()
    }

    /// Clears all consumed nullifiers.
    pub fn clear(&self) {
        self.consumed.write().unwrap().clear();
    }

    /// Checks if a specific nullifier is in the consumed set.
    #[must_use]
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.consumed.read().unwrap().contains(nullifier)
    }
}

impl OnpClient for InMemoryOnpClient {
    fn check_consumed(&self, nullifier: &[u8; 32]) -> StorageResult<bool> {
        Ok(self.consumed.read().unwrap().contains(nullifier))
    }

    fn mark_consumed(&self, nullifier: &[u8; 32]) -> StorageResult<()> {
        self.consumed.write().unwrap().insert(*nullifier);
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_onp_always_not_consumed() {
        let client = StubOnpClient::new();

        // All nullifiers should appear not consumed
        assert!(!client.check_consumed(&[0u8; 32]).unwrap());
        assert!(!client.check_consumed(&[1u8; 32]).unwrap());
        assert!(!client.check_consumed(&[0xFFu8; 32]).unwrap());
    }

    #[test]
    fn test_stub_onp_mark_consumed_noop() {
        let client = StubOnpClient::new();
        let nullifier = [0x42u8; 32];

        // Mark as consumed
        client.mark_consumed(&nullifier).unwrap();

        // Still shows as not consumed (stub doesn't track)
        assert!(!client.check_consumed(&nullifier).unwrap());
    }

    #[test]
    fn test_in_memory_onp_basic() {
        let client = InMemoryOnpClient::new();
        let nullifier = [0x42u8; 32];

        // Initially not consumed
        assert!(!client.check_consumed(&nullifier).unwrap());
        assert_eq!(client.consumed_count(), 0);

        // Mark as consumed
        client.mark_consumed(&nullifier).unwrap();

        // Now shows as consumed
        assert!(client.check_consumed(&nullifier).unwrap());
        assert_eq!(client.consumed_count(), 1);
    }

    #[test]
    fn test_in_memory_onp_multiple_nullifiers() {
        let client = InMemoryOnpClient::new();

        let null1 = [0x11u8; 32];
        let null2 = [0x22u8; 32];
        let null3 = [0x33u8; 32];

        // Mark some as consumed
        client.mark_consumed(&null1).unwrap();
        client.mark_consumed(&null2).unwrap();

        assert!(client.check_consumed(&null1).unwrap());
        assert!(client.check_consumed(&null2).unwrap());
        assert!(!client.check_consumed(&null3).unwrap());
        assert_eq!(client.consumed_count(), 2);
    }

    #[test]
    fn test_in_memory_onp_idempotent() {
        let client = InMemoryOnpClient::new();
        let nullifier = [0x42u8; 32];

        // Mark multiple times
        client.mark_consumed(&nullifier).unwrap();
        client.mark_consumed(&nullifier).unwrap();
        client.mark_consumed(&nullifier).unwrap();

        // Count is still 1 (HashSet dedupes)
        assert_eq!(client.consumed_count(), 1);
        assert!(client.check_consumed(&nullifier).unwrap());
    }

    #[test]
    fn test_in_memory_onp_clear() {
        let client = InMemoryOnpClient::new();

        client.mark_consumed(&[1u8; 32]).unwrap();
        client.mark_consumed(&[2u8; 32]).unwrap();
        assert_eq!(client.consumed_count(), 2);

        client.clear();

        assert_eq!(client.consumed_count(), 0);
        assert!(!client.check_consumed(&[1u8; 32]).unwrap());
        assert!(!client.check_consumed(&[2u8; 32]).unwrap());
    }

    #[test]
    fn test_in_memory_onp_contains() {
        let client = InMemoryOnpClient::new();
        let nullifier = [0xABu8; 32];

        assert!(!client.contains(&nullifier));

        client.mark_consumed(&nullifier).unwrap();

        assert!(client.contains(&nullifier));
    }

    #[test]
    fn test_in_memory_onp_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let client = Arc::new(InMemoryOnpClient::new());
        let mut handles = vec![];

        // Spawn threads that mark different nullifiers
        for i in 0..10 {
            let client = Arc::clone(&client);
            handles.push(thread::spawn(move || {
                let mut nullifier = [0u8; 32];
                nullifier[0] = i;
                client.mark_consumed(&nullifier).unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(client.consumed_count(), 10);
    }

    #[test]
    fn test_stub_onp_default() {
        let client = StubOnpClient::default();
        assert!(!client.check_consumed(&[0u8; 32]).unwrap());
    }
}
