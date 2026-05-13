# walletkit-db

Encrypted on-device storage primitives for WalletKit. SQLCipher (`sqlite3mc`)
wrapper, vault opener, content-addressed blobs, sealed key envelope,
cross-process lock.

Consumed by `walletkit-core::storage` (credential vault) and by sibling
SDKs in the WalletKit workspace that need an encrypted on-device store.
Plain Rust, no `uniffi`.

## Intended usage

A new consumer wires up storage in four steps. Each consumer picks its own
paths, envelope filename, associated-data namespace, and SQL schema:

```rust
use walletkit_db::{blobs, init_or_open_envelope_key, open_vault, Lock};

// 1. Cross-process lock. One file per consumer.
let lock = Lock::open(&paths.lock_path())?;
let guard = lock.lock()?;

// 2. Unseal or generate the consumer's intermediate key.
//    Filename + AD are per-consumer so different vaults never share keys.
let k_intermediate = init_or_open_envelope_key(
    &my_keystore_adapter,
    &my_blob_store_adapter,
    &guard,
    "my_consumer_keys.bin",
    b"my-consumer:key-envelope",
    now,
)?;

// 3. Open the encrypted SQLite database with the consumer's own schema.
let conn = open_vault(&paths.db_path(), &k_intermediate, &guard, |conn| {
    blobs::ensure_schema(conn)?;      // shared blob_objects table
    my_schema::ensure_schema(conn)    // consumer's own tables
})?;

// 4. Store and fetch blobs by content id; insert consumer-specific rows
//    referencing those ids.
let cid = blobs::put(&conn, MY_KIND_TAG, &payload_bytes, now)?;
let bytes = blobs::get(&conn, &cid)?.expect("present");
blobs::delete(&conn, &cid)?;          // GC orphaned bytes on status change
```

The consumer brings:

- A type implementing `Keystore` (seal/open under a device-bound key)
- A type implementing `AtomicBlobStore` (small-blob persistence — e.g. the
  sealed envelope file)
- A `kind: u8` tag space for blob payloads
- Its own SQL schema and queries

The crate handles cipher setup, schema dispatch, integrity check, content
hashing (`SHA-256(b"worldid:blob" || [kind] || plaintext)`), CBOR-encoded
envelope persistence, and the lock.

## Public surface

- `open_vault(...) -> StoreResult<Connection>` — open + key + schema +
  integrity check. Returns the bare `Connection`; consumers compose on top.
- `blobs::{ensure_schema, put, get, delete, compute_content_id}` plus
  `pub type ContentId = [u8; 32]`.
- `init_or_open_envelope_key(...) -> StoreResult<SecretBox<[u8; 32]>>`.
- `Lock` / `LockGuard` — native `flock` / `LockFileEx`, no-op on WASM.
- `Keystore` / `AtomicBlobStore` traits — plain Rust. Consumers that expose
  FFI define their own annotated traits and bridge with a small newtype.
- `Connection`, `Transaction`, `Statement`, `Row`, `StepResult`, `Value`,
  `cipher::*`, `DbError`, `DbResult`, `StoreError`, `StoreResult` — the
  underlying SQLite wrapper and error types.

## On-disk format

Schemas, CBOR envelope layout, content_id derivation, and the
`account_keys.bin` / `worldid:account-key-envelope` filename + AD tags are
byte-stable. Existing user databases keep working without migration.
Frozen-byte tests in `src/tests.rs` guard the format.

## Platforms

- Native (macOS, Linux, Windows): static `sqlite3mc` from the build script.
- `wasm32-unknown-unknown`: `sqlite-wasm-rs` with the `sqlite3mc` feature;
  `Lock` collapses to a no-op (single-threaded Web Worker runtime).
