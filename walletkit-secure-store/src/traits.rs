//! Internal platform interfaces consumed by the primitives in this crate.
//!
//! These traits are deliberately plain Rust (no `uniffi` annotations).
//! Consumers that need to expose them across an FFI boundary define their
//! own annotated traits and provide thin adapters to these.

use crate::error::StoreResult;

/// Device-bound keystore that seals and opens small key material.
///
/// Implementations are typically backed by the platform secure enclave
/// (iOS Keychain / Android Keystore) and ensure the wrapped material can
/// only be decrypted on the same device.
///
/// `associated_data` is integrity-protected but not encrypted — callers must
/// supply identical bytes when sealing and opening.
pub trait Keystore: Send + Sync {
    /// Seals `plaintext` under the device-bound key, authenticating
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

    /// Opens `ciphertext` under the device-bound key, verifying
    /// `associated_data`.
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

/// Atomic key-value blob store for small files (e.g. envelope payloads).
///
/// Writes must be atomic (write-then-rename or equivalent) so a crash never
/// leaves a half-written blob on disk.
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, returning `None` if absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>>;

    /// Writes `bytes` atomically to `path`.
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
