# walletkit-db

Encrypted on-device storage primitives for WalletKit. SQLCipher (`sqlite3mc`) wrapper, vault opener, content-addressed blobs, sealed key envelope, cross-process lock. Plain Rust, no `uniffi`.

Consumed by `walletkit-core::storage` (credential vault) and by sibling SDKs in the WalletKit workspace that need an encrypted on-device store.

## Concepts

Five physical pieces. Knowing what each one is and isn't makes everything else straightforward.

- **Vault** — the encrypted SQLite file on disk (e.g. `account.vault.sqlite`). Opened by `Vault::open`; accessed via `Vault::connection() -> &Connection`. SQLite's WAL-mode file locks serialize cross-process writers; walletkit-db doesn't layer another lock on top.
- **Envelope** — a small CBOR file (e.g. `account_keys.bin`) holding the sealed 32-byte `K_intermediate`. The seal is done by the host's hardware keystore. Managed by `init_or_open_envelope_key` + `KeyEnvelope`.
- **Lock** — a separate empty file used as a cross-process mutex via `flock` / `LockFileEx`. Acquired internally by `init_or_open_envelope_key` (envelope-init bootstrap race) and by consumers around operations that mix SQL with filesystem state (e.g. plaintext export/import).
- **`blob_objects` table** — one shared table inside the vault for content-addressed bytes, keyed by SHA-256. Consumer-specific tables reference rows here by `content_id`. Managed by `blobs::*`.
- **`Keystore` + `AtomicBlobStore`** — two traits the host implements. `Keystore` seals/unseals bytes under `K_device`; `AtomicBlobStore` reads/writes the envelope file. walletkit-db never touches the OS keystore or the filesystem directly.

## Architecture

```mermaid
flowchart TB
    subgraph Host["Host platform (Kotlin / Swift)"]
        KS["DeviceKeystore (uniffi)"]
        BS["AtomicBlobStore (uniffi)"]
    end
    subgraph WKDB["walletkit-db (this crate)"]
        OV["Vault::open / connection"]
        Blobs["blobs::{ensure_schema, put, get, delete}"]
        Env["init_or_open_envelope_key"]
        Lock["Lock / LockGuard"]
        Cipher["sqlite3mc"]
        OV --> Cipher
        Blobs --> Cipher
    end
    subgraph Consumer["Consumer (e.g. walletkit-core)"]
        Wrapper["Domain wrapper<br/>(e.g. CredentialVault)"]
        Tables["domain tables<br/>+ blob_objects (shared)"]
        Wrapper --> Tables
    end
    KS -.bridged via newtype.-> Env
    BS -.bridged via newtype.-> Env
    Wrapper --> WKDB
    style WKDB fill:#e8f4f8
```

Dependency direction is one-way: walletkit-db doesn't know about its consumers, uniffi, or any specific schema. Each consumer brings its own filename, AD namespace, lock file, vault file, and SQL schema.

## Key hierarchy

- **`K_device`** — root sealing key, provided by the host via the `Keystore` trait. In production deployments this MUST be backed by a non-extractable hardware key (iOS Secure Enclave / Android Keystore) so that even a disk-copy attacker can't recover it. walletkit-db doesn't enforce this; the threat-model rows below assume it.
- **`K_intermediate`** — 32-byte random key per consumer-vault. Generated once via `getrandom`, sealed under `K_device`, persisted as a CBOR `KeyEnvelope`. Used as the SQLite page-encryption key by sqlite3mc.
- **AD** — non-secret label bound into the AEAD seal (e.g. `worldid:account-key-envelope`). Per-consumer so envelopes can't be swapped between vaults.

## Startup

**Cold start:** open `Lock` → `init_or_open_envelope_key` generates fresh `K_intermediate`, seals it via `Keystore`, writes the envelope via `AtomicBlobStore`. `Vault::open` opens the SQLite file via `sqlite3mc`, runs the consumer's schema callback, runs `PRAGMA integrity_check`.

**Warm start:** same flow, but the envelope already exists. `init_or_open_envelope_key` reads and unseals it to recover the bit-for-bit original `K_intermediate`. Schema callback is idempotent (`CREATE TABLE IF NOT EXISTS`).

**Device wipe / app uninstall:** `K_device` is destroyed. The envelope on disk becomes permanently unsealable. Recovery requires a separate backup path that re-wraps the data under a non-device-bound key.

## Encryption

`K_intermediate` is hex-encoded and passed to sqlite3mc as a raw key via `PRAGMA key = "x'<hex>'"` (bypasses any passphrase KDF). sqlite3mc then encrypts each page with ChaCha20-Poly1305 AEAD and tamper-checks via the Poly1305 MAC. Wrong key → `SQLITE_NOTADB` on first page read. Bit-flip on disk → `SQLITE_CORRUPT`. WAL mode for concurrent readers.

## Threat model

All rows assume the host's `Keystore` is backed by a non-extractable hardware key. A `Keystore` implementation that keeps `K_device` in RAM, on disk, or anywhere the disk-copy attacker can reach voids the "Safe" rows below.

| Tier | Status | What protects you |
|---|---|---|
| Disk copy / lost device / backup extraction | **Safe** | Vault + envelope are encrypted under a key sealed by the hardware-backed `Keystore`; attacker can't unseal without `K_device`. |
| Code running inside the app session | **Exposed** | Attacker calls the legitimate keystore as the app and unseals envelopes. Defense lives at the keystore-entry access policy layer. |
| File corruption / envelope swap | **Safe** | Per-page MAC fails; AD binding fails AEAD auth on swapped envelopes. |
| Hardware keystore compromise | Out of scope | — |

**Defense-in-depth lever:** host policy on the keystore entry (iOS `kSecAccessControlBiometryCurrentSet`, Android `setUserAuthenticationRequired(true)`). walletkit-db is neutral; the policy lives in the Kotlin/Swift code that creates `K_device`.

## Per-consumer isolation

If multiple consumers share the device (today the credential vault; later an OrbKit PCP store, etc.), the host has to give each one its own secrets and its own files:

1. A separate hardware keystore entry (Secure Enclave key / Android Keystore alias).
2. A separate AD label passed to `init_or_open_envelope_key`.
3. A separate envelope filename, vault file, and lock file.

walletkit-db cryptographically binds operations to AD: an envelope sealed under one AD won't open under another. Everything else is host wiring. Sharing a keystore entry across consumers breaks the isolation.

## Usage

A consumer wires up storage in four steps:

```rust
use walletkit_db::{blobs, init_or_open_envelope_key, Lock, Vault};

// 1. Cross-process lock. One file per consumer.
let lock = Lock::open(&paths.lock_path())?;

// 2. Unseal or generate the consumer's intermediate key.
//    Filename + AD are per-consumer so different vaults never share keys.
let k_intermediate = init_or_open_envelope_key(
    &my_keystore_adapter,
    &my_blob_store_adapter,
    &lock,
    "my_consumer_keys.bin",
    b"my-consumer:key-envelope",
    now,
)?;

// 3. Open the encrypted SQLite database with the consumer's own schema.
let vault = Vault::open(&paths.db_path(), &k_intermediate, |conn| {
    blobs::ensure_schema(conn)?;
    my_schema::ensure_schema(conn)
})?;

// 4. Store / read / delete.
let conn = vault.connection();
let cid = blobs::put(conn, MY_KIND_TAG, &payload_bytes, now)?;
let bytes = blobs::get(conn, &cid)?.expect("present");
blobs::delete(conn, &cid)?;
```

The consumer brings a `Keystore` impl, an `AtomicBlobStore` impl, a `kind: u8` tag space, and its own SQL schema. The crate handles cipher setup, schema dispatch, integrity check, content hashing (`SHA-256("worldid:blob" || [kind] || plaintext)`), CBOR envelope persistence, and the lock.

## Public surface

- `Vault::open(path, key, ensure_schema) -> StoreResult<Vault>`, `Vault::connection(&self) -> &Connection`.
- `blobs::{ensure_schema, put, get, delete, compute_content_id}` plus `pub type ContentId = [u8; 32]`.
- `init_or_open_envelope_key(...) -> StoreResult<SecretBox<[u8; 32]>>`.
- `Lock` / `LockGuard` — native `flock` / `LockFileEx`, no-op on WASM.
- `Keystore` / `AtomicBlobStore` traits — plain Rust.
- `Connection`, `Transaction`, `Statement`, `Row`, `StepResult`, `Value`, `cipher::*`, `DbError`, `DbResult`, `StoreError`, `StoreResult`.

## On-disk format

Schemas, CBOR envelope layout, content_id derivation, and the `account_keys.bin` / `worldid:account-key-envelope` filename + AD tags are byte-stable. Existing user databases keep working without migration. Frozen-byte tests live next to the code they cover (`blobs.rs`, `envelope.rs`).

## Platforms

Native (macOS, Linux, Windows): static `sqlite3mc` from the build script. `wasm32-unknown-unknown`: `sqlite-wasm-rs` with the `sqlite3mc` feature; `Lock` collapses to a no-op.
