# SQLite at-rest encryption for browser WASM

## Recommendation

Use the existing `sqlite3mc` build in `sqlite-wasm-rs` above the SAH-pool OPFS
VFS. Keep the 32-byte `K_intermediate` in Rust/WASM memory while the store is
unlocked, pass it to sqlite3mc as a raw key, and keep the current encrypted key
envelope as the persistence boundary. Do not build a custom encrypted VFS for
the first version.

The required stack is:

```text
WalletKit SQL API
  -> sqlite3mc VFS shim (`multipleciphers-opfs-sahpool`)
    -> sqlite-wasm-vfs SAH pool (`opfs-sahpool`)
      -> OPFS FileSystemSyncAccessHandle
```

This protects copied OPFS/profile data while locked. It does not protect an
unlocked database from same-origin malicious JavaScript, XSS, browser
compromise, or a debugger: the page key and plaintext necessarily exist in the
WASM process.

## Exact dependency and build composition

The current lockfile resolves `sqlite-wasm-rs` to **0.5.5**. Its `sqlite3mc`
feature compiles the bundled `sqlite3mc_amalgamation.c`; that bundle is SQLite
**3.53.0** plus SQLite3 Multiple Ciphers **2.3.3**. The WASM build uses
`SQLITE_THREADSAFE=0`, `SQLITE_TEMP_STORE=2`, and an 8192-byte default page
size. See the [0.5.5 manifest], [0.5.5 build script], and [bundled sqlite3mc
header].

SAH-pool is not another feature on `sqlite-wasm-rs`. It is the separate
`sqlite-wasm-vfs` crate. Upstream documents this pairing:

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
sqlite-wasm-rs = { version = "=0.5.5", features = ["sqlite3mc"] }
sqlite-wasm-vfs = "=0.2.0"
```

`sqlite-wasm-vfs` 0.2 requires `sqlite-wasm-rs` 0.5.2 or newer. Both packages
use the same `rsqlite-vfs` 0.1 line, so 0.5.5/0.2.0 is the currently compatible
published pair. The VFS crate calls itself experimental, so pin both exact
versions and treat an upgrade as an on-disk compatibility change requiring the
browser persistence suite below. See the [sqlite-wasm-rs VFS matrix] and
[`sqlite-wasm-vfs` manifest].

There is already a small cross-platform skew to make explicit in tests:
WalletKit native builds sqlite3mc **2.3.2** with SQLite **3.51.3** and the normal
SQLite default page size, while WASM 0.5.5 bundles sqlite3mc 2.3.3/SQLite 3.53.0
and defaults to 8192-byte pages ([WalletKit build script]). Both currently use
the non-legacy `chacha20` format, but compatibility should be demonstrated by a
frozen fixture instead of inferred from nearby version numbers.

### Does `rusqlite` support sqlite3mc?

There is no `sqlite3mc` Cargo feature in current `rusqlite` or
`libsqlite3-sys`. Their similarly named `sqlcipher`, `bundled-sqlcipher`, and
`bundled-sqlcipher-vendored-openssl` features select Zetetic SQLCipher or its
link conventions; they do not build SQLite3 Multiple Ciphers. Nevertheless,
the `rusqlite` query layer can run over sqlite3mc because sqlite3mc is designed
as a drop-in SQLite replacement exporting the standard `sqlite3_*` API. It
must be the **only** SQLite implementation in the process ([rusqlite features],
[sqlite3mc drop-in installation], [sqlite3mc single-implementation warning]).

On native targets this is possible but not plug-and-play with WalletKit's
current archive. In external-link mode `libsqlite3-sys` accepts
`SQLITE3_LIB_DIR`, `SQLITE3_INCLUDE_DIR`, and `SQLITE3_STATIC` (or the
`SQLCIPHER_*` equivalents), but its build script fixes the requested library
basename to `sqlite3`, or to `sqlcipher` when the `sqlcipher` feature is on.
WalletKit currently compiles `libsqlite3mc`, so adopting `rusqlite` would
require deliberately emitting/aliasing that sole archive as `libsqlite3` (or
`libsqlcipher`) and matching its standard SQLite header/bindings. The standard
bindings are sufficient for rusqlite and SQL PRAGMAs; they do not include
sqlite3mc's extra declarations from `sqlite3mc.h`, so those need a tiny custom
`extern` wrapper. `libsqlite3-sys`'s `buildtime_bindgen` reads `sqlite3.h` and
does not solve that extra-header gap automatically ([libsqlite3-sys linking
logic], [libsqlite3-sys binding generation], [sqlite3mc C declarations]).

`rusqlite` does already expose
`Connection::open_with_flags_and_vfs`, so it can explicitly open
`multipleciphers-opfs-sahpool` after the asynchronous SAH-pool installation.
It does not provide a high-level sqlite3mc key API. `PRAGMA cipher`/`PRAGMA
key` work through ordinary SQL, while sqlite3mc also exposes
`sqlite3_key[_v2]` and its own configuration C API. Reaching those APIs through
`Connection::handle()` is unsafe, and ordinary `rusqlite::execute_batch` does
not promise to zeroize its internal SQL `CString`. WalletKit would therefore
still need a narrow audited FFI/key adapter (and should retain its current
zeroizing raw-key buffers) rather than interpolating `K_intermediate` through
generic rusqlite helpers ([rusqlite VFS and raw-handle API], [sqlite3mc C API]).

For `wasm32-unknown-unknown`, current `rusqlite` defaults to re-exporting
`sqlite-wasm-rs` as its FFI backend instead of using `libsqlite3-sys`.
`rusqlite`'s `sqlcipher` feature does not enable `sqlite-wasm-rs/sqlite3mc`;
WalletKit would still enable that feature on its direct, version-compatible
`sqlite-wasm-rs` dependency so Cargo unifies it into rusqlite's backend. This
does not replace the separate `sqlite-wasm-vfs` dependency, async SAH-pool
bootstrap, explicit prefixed VFS selection, or pool administration. Thus
rusqlite is a viable alternative query wrapper, not an encryption/VFS solution
and not a reason to change the recommended WASM stack ([rusqlite WASM backend]).

## VFS bootstrap and browser constraints

SAH-pool installation is asynchronous. It must finish before any WalletKit
connection opens:

```rust
let cfg = OpfsSAHPoolCfgBuilder::new()
    .vfs_name("opfs-sahpool")
    .directory(".walletkit-opfs-sahpool")
    .clear_on_init(false)
    .initial_capacity(6)
    .build();

install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, false).await?;
```

The important argument is `false`: do not make raw `opfs-sahpool` the default.
SQLite3MC wraps the default VFS during SQLite initialization. SAH-pool's
installer itself queries SQLite's VFS registry, which can initialize SQLite
before SAH-pool is registered. Making SAH-pool default afterwards can therefore
leave the unencrypted VFS as the default. Open each database explicitly with
`zVfs = "multipleciphers-opfs-sahpool"`; SQLite3MC dynamically constructs that
wrapper for a registered non-default VFS when the `multipleciphers-` prefix is
requested. Never fall back to a null VFS or raw `opfs-sahpool` when persistence
was requested. See [SQLite3MC's VFS FAQ], the SAH-pool [`install()` source], and
SQLite's [`sqlite3_vfs_find()` initialization rule].

The browser requirements and limits are:

- Run SQLite and SAH-pool in a **dedicated worker** and a **secure context**.
  `FileSystemSyncAccessHandle` is exposed only there. Its synchronous I/O is
  specifically intended to avoid asynchronous overhead for WASM ([File System
  Standard]).
- SAH-pool itself does **not** require COOP/COEP or `SharedArrayBuffer`.
  WalletKit's wider WASM runtime may independently add such a requirement.
- A sync access handle exclusively locks its OPFS file. SAH-pool does not offer
  transparent same-database/multi-tab concurrency, and a second context using
  the same pool directory may fail to initialize. Two WalletKit connections to
  two different files (vault and cache) are supported if the pool has enough
  slots; the default capacity of six accounts for database/journal files.
  Multi-tab use needs an app-level elected dedicated-worker owner/RPC scheme or
  explicit leader/pause coordination ([SQLite SAH-pool documentation]).
- OPFS is origin-scoped and quota-managed. Request/check persistent storage for
  an authoritative credential vault, surface quota errors, and still retain a
  recovery/backup story; user-cleared site data remains deletion
  ([Storage Standard]).

## Cipher and connection sequence

SQLite3MC's recommended/default scheme is sqleet-compatible ChaCha20 with a
Poly1305 tag. It uses a 16-byte nonce and 16-byte authentication tag per page,
therefore reserving 32 bytes per page ([cipher documentation]). Select it
explicitly so a future compile-time default change cannot reinterpret a file.

For each connection:

1. Open with `multipleciphers-opfs-sahpool`.
2. Execute `PRAGMA cipher = 'chacha20';`.
3. Execute `PRAGMA key = "x'<64 hex characters>'";` using the zeroizing path.
   This is a raw 256-bit key and bypasses the passphrase KDF.
4. Read `sqlite_master` immediately. `PRAGMA key` succeeds even for a wrong
   key; the first page read is the actual check.
5. Configure foreign keys, `synchronous=FULL`, `secure_delete=ON`, and
   `temp_store=MEMORY`.

Cipher selection/configuration must precede the key, and the key must precede
ordinary SQL. The current [`cipher.rs`] already gets the raw-key form,
zeroization, and verification right; it should add the explicit cipher and
target-specific journal policy. See [SQLite3MC key PRAGMAs].

### Journal, temp, and rekey caveats

For the initial WASM implementation use a rollback journal (`journal_mode =
DELETE`) and assert the returned mode. SAH-pool's Rust VFS exposes version-1 I/O
methods, not the shared-memory methods normally required by WAL. SQLite can use
WAL without those methods only if `locking_mode=EXCLUSIVE` is set before the
first WAL access; WAL then provides no concurrency benefit in this environment.
It may benchmark faster for SAH-pool, so it is a later measured optimization,
not a parity default. If enabled, the sequence must be key ->
`locking_mode=EXCLUSIVE` -> first page read -> `journal_mode=WAL`, and the
returned journal mode must equal `wal`. See [SQLite WAL without shared memory],
the SAH-pool [version-1 I/O implementation], and the official [OPFS WAL notes].

SQLite3MC encrypts database page contents and page contents in rollback/WAL
journals, but journal housekeeping structures remain visible. Temporary DBs and
subjournals are not encrypted, which is why `temp_store=MEMORY` is mandatory.
The bundled WASM build already defaults temp storage to memory, but the runtime
PRAGMA makes the invariant local and testable ([SQLite3MC VFS architecture]).

The bundled sqlite3mc versions are at or below 2.3.6, where rekey is not
supported in WAL mode. Before rotating `K_intermediate`, checkpoint/close all
connections, switch to a rollback journal, rekey and verify, then restore the
chosen mode. Prefer changing or adding a passkey by rewrapping the same random
`K_intermediate`; that avoids rewriting the database entirely. See the
[SQLite3MC rekey restriction].

## WalletKit implementation seams

1. Add and pin `sqlite-wasm-vfs` under the WASM target. Keep both sqlite crates
   in `walletkit-sqlite`; SAH-pool is a storage primitive, not credential logic.
2. Add an explicit async WASM bootstrap which installs one configured pool and
   returns/retains its `OpfsSAHPoolUtil`. Invoke it from the web worker before
   synchronous `CredentialStore::init`; do not hide an async install inside
   `Connection::open`.
3. Extend the private connection/raw-DB open path to accept an internal VFS
   choice. Native keeps its current default; WASM persistent opens use only the
   prefixed sqlite3mc VFS. Keep VFS names/constants beside this wiring.
4. Split key application from verification enough to make journal ordering
   explicit. Use rollback journal for WASM initially; query and assert all
   security-sensitive PRAGMA results instead of discarding result rows.
5. Route WASM file administration through `OpfsSAHPoolUtil`. Current cache
   rebuild uses `std::fs::remove_file`, and `destroy_storage` deliberately skips
   database deletion on WASM. Both must delete closed virtual files through the
   pool; otherwise cache recovery fails and destroying/reinitializing storage
   leaves an old vault which rejects the new key.
6. Treat `StoragePaths` as logical VFS filenames on WASM. Choose the pool
   directory as host/per-consumer wiring so unrelated WalletKit consumers do
   not share SAH handles or deletion scope.

## Key handling scope

Keeping `K_intermediate` in a Rust `SecretBox` for the unlocked lifetime is
compatible with sqlite3mc and matches the native design. Persistence still
requires the existing wrapped `account_keys.bin` envelope (or an equivalent):
a purely ephemeral random key would make the OPFS database unreadable after a
reload.

WebCrypto integration and a custom encryption VFS are out of scope. The browser
bootstrap supplies the unlocked `K_intermediate` bytes to WalletKit, after which
Rust owns and zeroizes the in-memory key material. SQLite3MC performs page
encryption synchronously inside WASM.

## Validation gates

- WASM unit/integration tests run in a dedicated worker and fail closed if the
  prefixed VFS is unavailable.
- Create both databases, commit representative data, drop connections,
  reinstall with `clear_on_init=false`, and reopen with the same key.
- Repeat across an actual worker termination/page reload, not only a close/open
  in one module instance.
- Wrong key fails on the immediate `sqlite_master` read. Raw `opfs-sahpool` and
  null-VFS opens are absent from the production path.
- Export raw virtual files through `OpfsSAHPoolUtil` after close; assert no
  SQLite header or seeded plaintext appears, and exercise ciphertext corruption.
- Assert `temp_store=memory`, the selected journal mode, cipher name, integrity
  check, deletion, cache rebuild, and destroy/reinitialize behavior.
- Terminate a worker immediately after a reported commit and verify recovery on
  the next worker. Add quota and second-tab/pool-contention tests.
- Freeze an encrypted fixture and verify native/WASM read compatibility before
  changing sqlite3mc, SQLite, page-size defaults, cipher parameters, or either
  sqlite WASM crate.

[0.5.5 manifest]: https://github.com/Spxg/sqlite-wasm-rs/blob/f2bb5109c07bf3d7ab800704c0f2373e6c7aa3b4/Cargo.toml
[0.5.5 build script]: https://github.com/Spxg/sqlite-wasm-rs/blob/f2bb5109c07bf3d7ab800704c0f2373e6c7aa3b4/build.rs
[bundled sqlite3mc header]: https://github.com/Spxg/sqlite-wasm-rs/blob/f2bb5109c07bf3d7ab800704c0f2373e6c7aa3b4/sqlite3mc/sqlite3mc_amalgamation.h
[sqlite-wasm-rs VFS matrix]: https://github.com/Spxg/sqlite-wasm-rs/tree/f2bb5109c07bf3d7ab800704c0f2373e6c7aa3b4#about-vfs
[`sqlite-wasm-vfs` manifest]: https://github.com/Spxg/sqlite-wasm-rs/blob/f2bb5109c07bf3d7ab800704c0f2373e6c7aa3b4/crates/sqlite-wasm-vfs/Cargo.toml
[WalletKit build script]: ../../crates/walletkit-sqlite/build.rs
[rusqlite features]: https://docs.rs/crate/rusqlite/0.40.2/features
[sqlite3mc drop-in installation]: https://utelle.github.io/SQLite3MultipleCiphers/docs/installation/install_overview/#drop-in-replacement-for-sqlite
[sqlite3mc single-implementation warning]: https://utelle.github.io/SQLite3MultipleCiphers/docs/features/feat_dispatch/#introduction
[libsqlite3-sys linking logic]: https://github.com/rusqlite/rusqlite/blob/master/libsqlite3-sys/build.rs#L370-L513
[libsqlite3-sys binding generation]: https://github.com/rusqlite/rusqlite/blob/master/libsqlite3-sys/build.rs#L378-L410
[sqlite3mc C declarations]: https://github.com/utelle/SQLite3MultipleCiphers/blob/main/src/sqlite3mc.h#L69-L90
[rusqlite VFS and raw-handle API]: https://docs.rs/rusqlite/0.40.2/rusqlite/struct.Connection.html#method.open_with_flags_and_vfs
[sqlite3mc C API]: https://utelle.github.io/SQLite3MultipleCiphers/docs/configuration/config_capi/
[rusqlite WASM backend]: https://github.com/rusqlite/rusqlite/blob/master/src/lib.rs#L104-L116
[SQLite3MC's VFS FAQ]: https://utelle.github.io/SQLite3MultipleCiphers/docs/faq/faq_overview/#how-can-i-use-a-non-default-vfs
[`install()` source]: https://github.com/Spxg/sqlite-wasm-rs/blob/f2bb5109c07bf3d7ab800704c0f2373e6c7aa3b4/crates/sqlite-wasm-vfs/src/sahpool.rs#L881-L905
[`sqlite3_vfs_find()` initialization rule]: https://www.sqlite.org/c3ref/vfs_find.html
[File System Standard]: https://fs.spec.whatwg.org/#api-filesystemfilehandle-createSyncAccessHandle
[SQLite SAH-pool documentation]: https://sqlite.org/wasm/doc/trunk/persistence.md#vfs-opfs-sahpool
[Storage Standard]: https://storage.spec.whatwg.org/#dom-storagemanager-persist
[cipher documentation]: https://utelle.github.io/SQLite3MultipleCiphers/docs/ciphers/cipher_chacha20/
[`cipher.rs`]: ../../crates/walletkit-sqlite/src/cipher.rs
[SQLite3MC key PRAGMAs]: https://utelle.github.io/SQLite3MultipleCiphers/docs/configuration/config_sql_pragmas/#key-handling
[SQLite WAL without shared memory]: https://www.sqlite.org/wal.html#noshm
[version-1 I/O implementation]: https://github.com/Spxg/sqlite-wasm-rs/blob/f2bb5109c07bf3d7ab800704c0f2373e6c7aa3b4/crates/sqlite-wasm-vfs/src/sahpool.rs#L590-L626
[OPFS WAL notes]: https://sqlite.org/wasm/doc/trunk/persistence.md#wal-mode-with-opfs
[SQLite3MC VFS architecture]: https://utelle.github.io/SQLite3MultipleCiphers/docs/architecture/arch_vfs/
[SQLite3MC rekey restriction]: https://utelle.github.io/SQLite3MultipleCiphers/docs/configuration/config_sql_pragmas/#pragma-rekey--hexrekey
