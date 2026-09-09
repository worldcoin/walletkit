# `walletkit-web`

WalletKit's browser client. The package always runs Rust/WASM, cryptography,
proof generation and SQLite in a dedicated Web Worker. Importing the package
is safe during SSR; call `initializeWalletKit` in a browser.

```ts
import { initializeWalletKit } from "walletkit-web";

const wallet = await initializeWalletKit({
  databaseKey, // Uint8Array containing the resolved 32-byte K_intermediate
  storageId: "my-account", // stable namespace for this consumer/account
  environment: "staging", // defaults to production
  region: "eu",
});
const recovery = await wallet.recoveryDataFromSeed(seed);
// For an already registered account:
await wallet.initializeAuthenticator(seed);
const proofJson = await wallet.generateProof(requestJson);
await wallet.close();
```

The host supplies the resolved `databaseKey`, for example after obtaining passkey
PRF output and deriving the database key. PRF acquisition/derivation happens before
initialization; WalletKit does not call WebAuthn or wrap this key in an envelope.
The worker constructs `StorageKeys.fromBytes(databaseKey)` and passes those keys to
`CredentialStore`. Both vault and cache use that key directly through sqlite3mc.

Supply the same key and storage ID when reopening. The authenticator seed and
database key are separate inputs. The package does not persist the database key;
initialization copies it and the caller owns clearing its own copy. Rust keeps the
resolved key in zeroizing memory until its last owner releases it.

Mobile hosts can instead resolve `StorageKeys.fromEnvelope(paths, keystore,
blobStore, now)` before constructing the same `CredentialStore(paths, keys)`.
The store retains no keystore or blob-store references. It releases its key
reference on destruction and requires a new instance to reopen. The host separately
calls `deleteStorageKeyEnvelope(paths, blobStore)` if it owns an envelope that should
be deleted. Existing envelope-backed databases still use their resolved intermediate
key; the old wrapping secret is not a replacement for that database key.

## Browser API

All calls into the worker return Promises. The public client exposes
`recoveryDataFromSeed`, `register`, `pollRegistration`, `initializeAuthenticator`,
`prepareCredential`, `storeCredential`, and `generateProof`. Registration polling
returns plain status records, including failure details. `prepareCredential`
returns the subject and serialized blinding factor for an issuer flow;
`storeCredential` accepts credential bytes and that factor. Issuer HTTP calls and
relying-party request construction remain application code.

This replaces the prototype API that returned the generated UniFFI namespace.
Generated Rust objects are internal and never cross the worker boundary. Existing
consumers must migrate their calls to the browser client; it is not a transparent
proxy for every generated binding. See the Next.js demo for a complete registration,
issuance and proof flow.

Operations run in order, including asynchronous work. `close()` drains queued
operations, destroys owned Rust objects and terminates the worker. `terminate()`
interrupts immediately and rejects pending requests. Worker failures also reject
pending requests. An optional `signal` cancels initialization only; after it
resolves, use `close()` or `terminate()`.

## Assets and deployment

Default URLs are resolved by the application's bundler. Both worker JavaScript
and the roughly 40 MB WASM asset ship in `dist`. The worker is self-contained,
including the generated glue and its runtime dependencies.

Hosts with custom asset layouts can provide explicit URLs:

```ts
const wallet = await initializeWalletKit({
  databaseKey,
  workerUrl: "/assets/walletkit.worker.js",
  wasmUrl: "/assets/walletkit.wasm",
});
```

Relative overrides resolve against the page URL. These options change asset
locations; they do not enable main-thread execution. Serve the worker from a
permitted same-origin location and the WASM file as `application/wasm`.

## Persistent storage

Initialization acquires the OPFS sync-access-handle pool asynchronously. SQLite
operations are synchronous afterward. The browser's direct-key path needs no envelope database. The encrypted credential
vault/cache retain their existing format and use rollback journals on WASM.
The optional `SqliteBlobStore` primitive still opens/closes a connection per
operation for hosts that need to persist sealed blobs.

Closing a SQLite connection does not release the pool's OPFS handles: the pool
remains alive until worker termination. Currently one worker owns the WalletKit
pool per origin. A second tab/client receives an initialization error, even with
a different storage ID. After shutdown, browser handle release may be asynchronous;
a subsequent initializer may need to retry. There is no silent memory fallback.
Pool capacity is reserved at startup rather than expanded during synchronous SQL.

Browser storage requires a supported secure context (localhost is suitable for
development). The SAH pool does not require cross-origin-isolation headers.
Browser quota and eviction policy still apply.

## Build and verify

```sh
nix develop .#wasm --command bun install --cwd web/walletkit --frozen-lockfile
nix develop .#wasm --command bun run --cwd web/walletkit build
nix develop .#wasm --command bun run --cwd web/walletkit test:browser
```

Browser tests use installed Google Chrome and a production Vite fixture. They
cover worker startup and lifecycle, URL overrides, exclusive pool ownership,
Rust blob persistence, wrong-key rejection, and reopening both direct-key and envelope-backed storage.
`bun run bundle` reuses generated bindings for TypeScript-only development.

The example uses a new namespace and memory-only database keys on each load. Its encrypted
files persist, but it intentionally cannot unlock them after reload; a production
host must implement key recovery/unlock and stable account namespace selection.
