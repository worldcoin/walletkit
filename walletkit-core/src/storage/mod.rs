//! # Credential Store
//!
//! On-device consisted encrypted storage for World ID credentials.
//!
//! The storage layer handles structured storage of all credentials and their
//! associated data (only storage, the semantics of the associated data is the
//! Issuer's responsibility). In addition the storage layer handles encryption
//! and clean up after expiration.
//!
//! # Components
//!
//! [`crate::storage::CredentialStore`] is the facade exposed to hosts (via `UniFFI`). It owns the
//! account key envelope and two `SQLCipher` databases opened with the resulting key.
//! The lower-level primitives (key-envelope sealing, `SQLCipher` setup,
//! content-addressed blobs, cross-process locking, and the threat model) live in the
//! `walletkit-db` crate — see its README for the key hierarchy and on-disk format.
//!
//! 1. **Device keystore root (`K_device`)** — device-bound, preferably non-exportable
//!    key backed by Secure Enclave / Android Keystore / `WebCrypto` where available.
//!    Used only to unwrap `K_intermediate` at init; never used directly for database
//!    encryption. Provided by the host via [`crate::storage::DeviceKeystore`].
//! 2. **Account key envelope (`account_keys.bin`)** — `K_intermediate` sealed under
//!    `K_device`. Opened once per storage init and kept in memory for the lifetime of
//!    the handle. Device-local; not synced across devices.
//! 3. **Vault database (`account.vault.sqlite`)** — authoritative storage for
//!    credentials, associated blobs, issuer subject blinding factors, and the account
//!    leaf index. Encrypted via sqlite3mc (`ChaCha20-Poly1305` by default) and
//!    integrity-protected. Corruption is a hard failure. See [`crate::storage::CredentialVault`].
//! 4. **Cache database (`account.cache.sqlite`)** — non-authoritative, regenerable
//!    entries: Merkle inclusion proof cache, per-account session seed, and nullifier
//!    replay guards. Subject to TTL pruning and can be rebuilt at any time without
//!    correctness loss. See [`crate::storage::CacheDb`].
//!
//! # Cryptographic keys
//!
//! - `K_device` — device-bound root key from the platform keystore; MUST be
//!   non-exportable when supported.
//! - `K_intermediate` — 32-byte per-account key, generated randomly on first use,
//!   stored sealed under `K_device` in `account_keys.bin`, loaded once at init and
//!   retained in memory. Used as the sqlite3mc key for both databases.
//! - Session seed — a `session_id_r_seed` derived for session proof flows and cached
//!   in the cache DB keyed by the OPRF seed (see `cache/session.rs`). Because it is
//!   derived from device-local material, caching it is an optimization: a missing
//!   entry is re-derived.
//!
//! ## Key hierarchy
//!
//! ```text
//! Level 0 — Device Keystore Root
//!   K_device: device-bound root key
//!   (Secure Enclave / Android Keystore / WebCrypto; non-exportable when supported)
//!        │ seal / open (AD = "worldid:account-key-envelope")
//!        ▼
//! Level 1 — Account Key Envelope (account_keys.bin)
//!   Stores seal(AD, K_intermediate) under K_device
//!   In-memory after init: K_intermediate (32 bytes)
//!        │ sqlite3mc key                    │ sqlite3mc key
//!        ▼                                  ▼
//!   Vault DB (.vault.sqlite)           Cache DB (.cache.sqlite)
//!   leaf_index, credentials, blobs     merkle cache, session seed, replay guards
//! ```
//!
//! # On-disk layout
//!
//! Storage root: `<root>/worldid/` — see [`crate::storage::StoragePaths`].
//!
//! ```text
//! account_keys.bin            # DeviceKeystore-sealed K_intermediate envelope
//! account.cache.sqlite        # sqlite3mc-encrypted cache DB (keyed by K_intermediate)
//! account.vault.sqlite        # sqlite3mc-encrypted vault DB (keyed by K_intermediate)
//! lock                        # account-scoped lock
//! ```
//!
//! # Locking and concurrency
//!
//! Operations that modify a persistent layer (envelope writes, vault writes, cache
//! writes) run under an account-wide lock (`walletkit-db`'s cross-process `flock`).
//!
//! # Security and privacy properties
//!
//! - No filesystem paths encode `leaf_index`, RP identifiers, issuer names, or action
//!   names — see [`crate::storage::StoragePaths`].
//! - Vault contents are encrypted via sqlite3mc (keyed by `K_intermediate`,
//!   `ChaCha20-Poly1305` by default); untrusted storage cannot read credentials. No
//!   `OpenSSL` dependency is required.
//! - `K_intermediate` is sealed under `K_device`; without the device keystore, neither
//!   the envelope nor the encrypted databases can be opened.
//! - The vault (authoritative) holds the `leaf_index`, credentials, and blobs. The
//!   cache DB holds only regenerable, TTL-bounded entries.
//! - Nullifier replay guards are intentionally short-lived to avoid creating a
//!   long-lived "interaction history" on device.
//!
//! # Operational flow: unique action proof
//!
//! ```text
//! RP ─► Authenticator: signed proof request (rp_id, action, nonce, signal)
//!
//! ── Account initialized/unlocked once per session ──
//! Authenticator ─► Storage: init(leaf_index, now)
//!   Storage: unwrap K_intermediate via device keystore,
//!            open sqlite3mc vault + cache DBs keyed by K_intermediate
//!
//! ── Merkle inclusion proof lookup ──
//! Authenticator ─► Storage: merkle_cache_get(valid_until)
//!   if cache hit (not expired): return proof_bytes
//!   else: fetch inclusion proof from Indexer, then
//!         Storage: merkle_cache_put(proof_bytes, now, ttl_seconds)
//!
//! ── OPRF query phase (blinded leaf index + query proof) ──
//! Authenticator ─► OPRF Nodes: query proof + blinded request context
//! OPRF Nodes ─► Authenticator: blinded responses (threshold)
//! Authenticator: construct proof + nullifier
//!
//! ── Replay-safety / single-use enforcement ──
//! Authenticator ─► Storage: is_nullifier_replay(nullifier, now)
//!   if true (seen before, past the grace period):
//!     MUST NOT disclose a new proof for that nullifier
//!   else:
//!     Storage: replay_guard_set(nullifier, now); disclose proof to RP
//! ```

pub mod cache;
pub mod credential_storage;
pub mod credential_vault;
pub mod error;
#[cfg(all(not(target_arch = "wasm32"), feature = "embed-zkeys"))]
pub mod groth16_cache;
pub mod keys;
pub mod paths;
pub mod traits;
pub mod types;

pub use cache::CacheDb;
pub use credential_storage::CredentialStore;
pub use credential_vault::CredentialVault;
pub use error::{StorageError, StorageResult};
#[cfg(all(not(target_arch = "wasm32"), feature = "embed-zkeys"))]
pub use groth16_cache::cache_embedded_groth16_material;
pub use keys::StorageKeys;
pub use paths::StoragePaths;
pub use traits::{
    AtomicBlobStore, DeviceKeystore, StorageProvider, VaultChangedListener,
};
pub use types::{
    BlobKind, ContentId, CredentialRecord, Nullifier, ReplayGuardKind,
    ReplayGuardResult, RequestId,
};
pub use walletkit_db::{Lock as StorageLock, LockGuard as StorageLockGuard};

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

#[cfg(test)]
pub(crate) mod tests_utils;
