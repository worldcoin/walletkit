//! Plain-Rust trait surface for consumer-supplied platform integrations.
//!
//! Consumers that need FFI define their own annotated traits and adapt to
//! these via newtype wrappers.

use crate::error::StoreResult;

/// Device keystore for sealing and opening secrets under a device-bound key.
///
/// Implementations must integrity-protect `associated_data` as part of the
/// seal: any mismatch when opening must fail.
pub trait Keystore: Send + Sync {
    /// Seals plaintext under the device-bound key, authenticating
    /// `associated_data`.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore refuses the operation or the seal
    /// fails.
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>>;

    /// Opens ciphertext under the device-bound key, verifying
    /// `associated_data`. The same associated data used during sealing must
    /// be supplied or the open operation must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the keystore cannot open.
    fn open_sealed(
        &self,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> StoreResult<Vec<u8>>;
}

/// Atomic blob store for small binary files (e.g. sealed key envelopes).
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: &str) -> StoreResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, path: &str, bytes: &[u8]) -> StoreResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    fn delete(&self, path: &str) -> StoreResult<()>;
}
