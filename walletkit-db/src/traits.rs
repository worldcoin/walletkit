//! Plain-Rust trait surface for consumer-supplied platform integrations.
//!
//! Argument shapes mirror `WalletKit`'s existing uniffi-annotated traits
//! (`Vec<u8>` for byte buffers, owned `String` for paths) so downstream
//! consumers can blanket-impl these for their own annotated traits without
//! adapter newtypes.

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
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StoreResult<Vec<u8>>;

    /// Opens ciphertext under the device-bound key, verifying
    /// `associated_data`. The same associated data used during sealing must
    /// be supplied or the open operation must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the keystore cannot open.
    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StoreResult<Vec<u8>>;
}

/// Atomic blob store for small binary files (e.g. sealed key envelopes).
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    fn delete(&self, path: String) -> StoreResult<()>;
}
