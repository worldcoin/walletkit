//! Credential storage: consistent, versioned, encrypted persistence for World ID credentials.
//!
//! # Goal
//!
//! Have a consistent method to store credentials.
//!
//! - Consistent API for different credentials
//! - Store different versions of the same credential
//! - Eventually:
//!   - Awareness of a credential on multiple devices (sync, originating authenticator)
//!   - Pruning/compaction
//!   - Purging
//!
//! # Components
//!
//! The storage system consists of the following components:
//!
//! 1. **Device keystore root (`K_device`)**
//!    - A device-bound, preferably non-exportable key.
//!    - Backed by Secure Enclave / Android Keystore / WebCrypto where available.
//!    - Used only to unwrap a per-account intermediate key during initialization.
//!    - Never used directly for database encryption.
//!
//! 2. **Account Key Envelope (`account_keys.bin`)**
//!    - `K_intermediate` sealed under `K_device`.
//!    - Opened once per storage initialization and kept in memory for the lifetime
//!      of the storage handle.
//!    - Device-local and not intended to be synced across devices.
//!
//! 3. **Encrypted Vault Database (`account.vault.sqlite`)**
//!    - Encrypted via sqlite3mc (SQLite3 Multiple Ciphers, ChaCha20-Poly1305 default)
//!      and integrity-protected.
//!    - Opened using `K_intermediate`.
//!    - Authoritative storage for:
//!      - Credentials and associated blobs
//!      - Issuer subject blinding factors
//!      - Core account state (leaf index, per-device state)
//!    - This implementation is device-local; future cross-device sync would require an
//!      explicit key export/import mechanism or an external key provider.
//!    - On native targets, sqlite3mc is compiled from the vendored amalgamation via `cc`.
//!      On WASM targets, `sqlite-wasm-rs` provides sqlite3mc compiled to WebAssembly.
//!
//! 4. **Encrypted Cache Database (`account.cache.sqlite`)**
//!    - Encrypted via sqlite3mc and integrity-protected.
//!    - Opened using `K_intermediate`.
//!    - Stores non-authoritative, regenerable cache entries (key/value/ttl):
//!      - Per-RP session key material (derived from `K_intermediate`) for session proof flows
//!      - Replay-safety entries (nullifier mappings)
//!      - Merkle inclusion proof cache
//!    - May grow large and is subject to aggressive TTL-based pruning.
//!    - Can be deleted and rebuilt at any time without correctness loss.
//!
//! # Cryptographic Keys
//!
//! ## Root and intermediate keys
//!
//! - `K_device`
//!   - Device-bound root key provided by the platform keystore.
//!   - MUST be non-exportable when supported.
//! - `K_intermediate`
//!   - 32-byte per-account intermediate key.
//!   - Generated randomly on first use.
//!   - Stored sealed under `K_device` in `account_keys.bin`.
//!   - Loaded once during initialization and retained in memory for the lifetime
//!     of the storage session.
//!
//! ## Derived keys (device-local)
//!
//! Derived session keys (**NOTE: This is temporary (~2 months)**)
//!
//! - `K_session = HKDF(IKM = K_intermediate, salt = <explicit salt>, info = "worldid:session-key" || rpId)`
//! - `r = HKDF(IKM = K_session, salt = <explicit salt>, info = "worldid:session-r" || actionId)`
//!
//! Session keys are derived from `K_intermediate` and therefore are device-local.
//! Persisting them in cache is an optimization and does not change correctness.
//!
//! ## sqlite3mc database keying
//!
//! Both databases (`account.vault.sqlite` and `account.cache.sqlite`) are encrypted
//! using sqlite3mc (SQLite3 Multiple Ciphers) with `K_intermediate` as the key material.
//! The default cipher is ChaCha20-Poly1305 (no OpenSSL dependency). The same encryption
//! library and PRAGMA dialect is used on all platforms (native and WASM).
//!
//! ## Key hierarchy
//!
//! ```text
//! Level 0 — Device Keystore Root
//! ┌──────────────────────────────────────────────────────────┐
//! │  K_device                                                │
//! │  Device-bound root key                                   │
//! │  Secure Enclave / Android Keystore / WebCrypto           │
//! │  Non-exportable when supported                           │
//! └──────────────┬───────────────────────────────────────────┘
//!                │ seal / open (AD = "worldid:account-key-envelope")
//!                ▼
//! Level 1 — Account Key Envelope
//! ┌──────────────────────────────────────────────────────────┐
//! │  account_keys.bin                                        │
//! │  Stores: seal(AD_i, K_intermediate) under K_device       │
//! │                                                          │
//! │  In-memory after init:                                   │
//! │    K_intermediate (32 bytes)                              │
//! │    Per-install intermediate key, unsealed via K_device    │
//! └──────┬───────────────┬───────────────┬───────────────────┘
//!        │               │               │
//!        │ sqlite3mc key │ sqlite3mc key │ HKDF (rpId)
//!        ▼               ▼               ▼
//! ┌────────────┐  ┌────────────┐  Level 2 — Derived Keys
//! │ Vault DB   │  │ Cache DB   │  ┌──────────────────────────┐
//! │ .vault.    │  │ .cache.    │  │ K_session (32B)          │
//! │ sqlite     │  │ sqlite     │  │ HKDF: IKM=K_intermediate │
//! │            │  │            │  │ info=session-key || rpId  │
//! │ Stores:    │  │ Stores:    │  ├──────────────────────────┤
//! │ -leaf_index│  │ -nullifiers│  │         │ HKDF (actionId)│
//! │ -creds +   │  │ -merkle    │  │         ▼                │
//! │  blobs     │  │  cache     │  │ r (32B)                  │
//! │            │  │ -per-RP    │  │ HKDF: IKM=K_session      │
//! │            │  │  sessions  │  │ info=session-r || actionId│
//! └────────────┘  └────────────┘  ├──────────────────────────┤
//!                                 │         │ hash           │
//!                                 │         ▼                │
//!                                 │ sessionId                │
//!                                 │ H(DS_C || leafIndex || r)│
//!                                 └──────────────────────────┘
//! ```
//!
//! # On-disk layout
//!
//! Storage root: `<root>/worldid/`
//!
//! ```text
//! account_keys.bin            # DeviceKeystore-sealed K_intermediate envelope
//! account.cache.sqlite        # sqlite3mc-encrypted SQLite cache DB (keyed by K_intermediate)
//! account.vault.sqlite        # sqlite3mc-encrypted SQLite vault DB (keyed by K_intermediate)
//! lock                        # account-scoped lock
//! ```
//!
//! # Locking and concurrency
//!
//! All operations that modify any persistent layer execute under an account-wide lock, including:
//!
//! - Writes to `account_keys.bin`
//! - Vault DB writes
//! - Cache DB writes
//!
//! Nullifier replay guard operations are transactional to prevent race conditions
//! between concurrent proof flows.
//!
//! # Security and Privacy Properties
//!
//! - No filesystem paths contain `leaf_index`, RP identifiers, issuer names, or action names.
//! - `AccountId` is not a hash of `leaf_index`; it is derived from `K_intermediate` and
//!   network context, preventing brute-force recovery of `leaf_index`.
//! - Vault contents are end-to-end encrypted via sqlite3mc (keyed by `K_intermediate`,
//!   ChaCha20-Poly1305 by default); untrusted storage cannot read credentials.
//!   No OpenSSL dependency is required.
//! - Account state is device-protected under `K_device`; it contains:
//!   - `leaf_index_cache` (sensitive)
//!   - `K_session_root` (sensitive)
//!   - `used_nullifier_cache` (sensitive; bounded TTL)
//!   - Merkle proof cache (sensitive; bounded TTL)
//! - Cache DB entries are sensitive and bounded by TTL:
//!   - Replay guard entries
//!   - Merkle proof cache
//!   - Per-RP session keys
//! - Replay guard entries are intentionally short-lived to avoid creating long-lived
//!   "interaction history" on device.
//! - Granular security on each credential stored in the vault: each credential blob
//!   is encrypted with a separate key which should be hardware backed (or wrapped)
//!   when available. Each key should have access control proportional to the sensitivity
//!   of that specific credential.
//!
//! # Operational flow: Unique action proof
//!
//! ```text
//! User ─► RP: (initiates proof request)
//! RP ─► Authenticator: signed proof request (rp_id, action, nonce, signal)
//!
//! ── Account must be initialized/unlocked once per session ──
//! Authenticator ─► Storage: init(leafIndex)
//!   Storage: unwrap K_intermediate via device keystore,
//!            open sqlite3mc vault + cache DBs keyed by K_intermediate
//!
//! ── Merkle inclusion proof lookup ──
//! Authenticator ─► Storage: merkle_cache_get(registry_kind, root, now)
//!   if cache hit (not expired):
//!     Storage ─► Authenticator: proof_bytes
//!   else (cache miss / expired):
//!     Authenticator ─► Indexer: fetch inclusion proof for (registry_kind, root, leafIndex)
//!     Indexer ─► Authenticator: proof_bytes
//!     Authenticator ─► Storage: merkle_cache_put(registry_kind, root, proof_bytes, now, ttl)
//!
//! ── OPRF query phase (blinded leafIndex + query proof) ──
//! Authenticator ─► OPRF Nodes: query proof + blinded request context
//! OPRF Nodes ─► Authenticator: blinded responses (threshold)
//!
//! Authenticator: construct proof_package + nullifier
//!
//! ── Replay-safety / single-use disclosure enforcement (transactional) ──
//! Authenticator ─► Storage: begin_proof_disclosure(request_id, nullifier, proof_package, now, ttl)
//!   if replay (same request_id):
//!     Storage ─► Authenticator: same proof_package bytes
//!   if fresh:
//!     Storage ─► Authenticator: proof_package bytes
//!   if conflict (same nullifier, different request_id):
//!     Storage ─► Authenticator: error (NullifierAlreadyDisclosed)
//!     Authenticator: MUST NOT disclose a new proof_package for that nullifier
//!
//! Authenticator ─► RP: proof_package
//! RP ─► Authenticator: success/failure
//! ```

pub mod cache;
pub mod credential_storage;
pub mod envelope;
pub mod error;
pub mod groth16_cache;
pub mod keys;
pub mod lock;
pub mod paths;
pub mod traits;
pub mod types;
pub mod vault;

pub use cache::CacheDb;
pub use credential_storage::CredentialStore;
pub use error::{StorageError, StorageResult};
pub use groth16_cache::cache_embedded_groth16_material;
pub use keys::StorageKeys;
pub use lock::{StorageLock, StorageLockGuard};
pub use paths::StoragePaths;
pub use traits::{
    AtomicBlobStore, DeviceKeystore, StorageProvider, VaultChangedListener,
};
pub use types::{
    BlobKind, ContentId, CredentialRecord, Nullifier, ReplayGuardKind,
    ReplayGuardResult, RequestId,
};
pub use vault::VaultDb;

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

#[cfg(test)]
pub(crate) mod tests_utils;
