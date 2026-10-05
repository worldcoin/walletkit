# `@worldcoin/walletkit-web`

WalletKit's browser client. The package always runs Rust/WASM, cryptography,
proof generation and SQLite in a dedicated Web Worker. Importing the package
is safe during SSR; call `initializeWalletKit` in a browser.

```ts
import { initializeWalletKit } from "@worldcoin/walletkit-web";

const walletkit = await initializeWalletKit();

// Open the account's encrypted storage, as the Swift and Kotlin bindings do.
const keys = await walletkit.StorageKeys.fromBytes(databaseKey); // resolved 32-byte key
const paths = await walletkit.StoragePaths.fromRoot("/walletkit/my-account");
const store = await walletkit.CredentialStore.new(paths, keys);
const artifacts = await walletkit.EmbeddedZkArtifacts.new();

// Register a new account...
const registration = await walletkit.InitializingAuthenticator.registerWithDefaults(
  seed, undefined, "staging", "eu", undefined,
);
const status = await registration.pollStatus(); // { state: "queued" | ... }

// ...or open a registered one and prove.
const authenticator = await walletkit.Authenticator.initWithDefaults(
  seed, undefined, "staging", "eu", artifacts, store,
);
await authenticator.initStorage(BigInt(Math.floor(Date.now() / 1000)));
const request = await walletkit.ProofRequest.fromJson(requestJson);
const response = await authenticator.generateProof(request);
const proofJson = await response.toJson();

await walletkit.close();
```

The host supplies the resolved `databaseKey`, for example after obtaining passkey
PRF output and deriving the database key. PRF acquisition/derivation happens before
initialization; WalletKit does not call WebAuthn or wrap this key in an envelope.
Both vault and cache use that key directly through sqlite3mc. Supply the same key
and root path when reopening.

The authenticator seed and database key are separate inputs. The package does not
persist the database key; the worker clears its copy of every byte array it receives,
and the caller owns clearing its own. Rust keeps the resolved key in zeroizing memory
until its last owner releases it.

`StorageKeys.fromBytes` and `CredentialStore.new(paths, keys)` are browser-only:
the browser has no device keystore, so the host supplies the key and no key
envelope is written. Mobile hosts keep opening the store from their keystore and
blob store. `destroyStorage()` deletes the databases; discarding a supplied key is
up to the host.

## Browser API

The classes, methods and arguments mirror the `walletkit-core` UniFFI objects that
the Swift and Kotlin bindings expose, in `camelCase`: `Authenticator`,
`InitializingAuthenticator`, `CredentialStore`, `StorageKeys`, `StoragePaths`,
`EmbeddedZkArtifacts`, `FieldElement`, `Credential`, `ProofRequest` and
`ProofResponse`, plus `recoveryDataFromSeed`, `validateAuthenticatorPubkey`,
`checkCredentialsAgainstProofRequest`, `pohRecoveryAgentAddress` and
`worldIdVerifierAddress`. Constructors and static functions live on the object
returned by `initializeWalletKit()` (`walletkit.FieldElement.fromU64(1n)`,
`walletkit.CredentialStore.new(paths, keys)`); instance methods are on the objects
they return. Conventions that differ from native:

- Every call returns a Promise, because it crosses to the worker.
- `u64` is `bigint`, byte arrays are `Uint8Array`, `Environment` is
  `"production" | "staging"` and `Region` is `"eu" | "us" | "ap"`.
- `now` (unix seconds) is passed explicitly, as on native. Only `generateProof`
  defaults it, to the browser clock, because core cannot read a clock on wasm.
- 256-bit values, such as `packedAccountData()`, are 0x-prefixed hex strings.
- Records (`RegistrationStatus`, `CredentialRecord`, `ActivityEntry`, …) are plain
  objects. Their enum fields are lowercase strings, as in core's serialization.
- Rust objects live in the worker until you call `free()` (they are also released
  when garbage collected). Using a freed object rejects.

Not available in the browser: `Logger`, `DeviceKeystore`, `AtomicBlobStore`,
`StorageProvider` and the change listeners (foreign traits), vault backup and
`proveCredentialSub` (native-only in core), `UserAgent`, `sanitizeHexSecrets`, and the
issuer and Flamingo modules. Core's warnings and errors, for example a vault that
could not be deleted, are written to the worker console with hex secrets redacted.

Rust errors reject with their source as `name` (`WalletKitError`, `StorageError`,
`CredentialConstraintsCheckError`), the variant name as `code` (for example
`NullifierReplay`) and the variant details appended to `message`, with hex secrets
redacted. Invalid arguments reject with a `TypeError`. A Rust panic traps the module:
the failing call rejects (or the worker error stops the client) and every later call
fails, so reinitialize.
Issuer HTTP calls and relying-party request construction remain application code.

The worker runs the `walletkit-web` crate, a `wasm-bindgen` facade over
`walletkit-core` with one wrapper class per UniFFI object. The page-side API is
derived from the generated declarations by a generic proxy (`src/remote.ts`), so
adding a core export to the browser only means adding its wrapper in the crate. The
worker calls nothing but the functions and methods the module exports.

Operations run in order, including asynchronous work, and have no deadline of their
own: a network call that never settles blocks the calls queued behind it. `close()`
drains queued operations, frees every Rust object and terminates the worker; if the
worker does not answer within 5 seconds it is terminated and `close()` rejects.
`terminate()` interrupts immediately and rejects pending requests. Worker failures also reject
pending requests. An optional `signal` cancels initialization only; after it
resolves, use `close()` or `terminate()`.

## Assets and deployment

Default URLs are resolved by the application's bundler. Both worker JavaScript
and the roughly 40 MB WASM asset ship in `dist`. The worker is self-contained,
including the generated glue and its runtime dependencies.

Hosts with custom asset layouts can provide explicit URLs:

```ts
const walletkit = await initializeWalletKit({
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

Closing a SQLite connection does not release the pool's OPFS handles: the pool
remains alive until worker termination. Currently one worker owns the WalletKit
pool per origin. A second tab/client receives an initialization error, even with
a different root path. After shutdown, browser handle release may be asynchronous;
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
wrong-key rejection, reopening storage with directly supplied keys, error
mapping, and using Rust objects through handles. `bun run bundle` reuses the built
module for TypeScript-only development. The build checks that the `wasm-bindgen` CLI
matches the version in `Cargo.lock`.

The example persists its storage ID and database key in `localStorage` so it can
reopen its encrypted files after a reload; a production host must implement key
recovery/unlock and stable account namespace selection.

## Releasing

[`web.yml`](../../.github/workflows/web.yml) builds, tests and publishes the package.
Pull requests and pushes to `main` build it with the pinned `nix develop .#wasm`
toolchain, run `format:check` and the browser tests, and verify the tarball contents.
Nothing is published from them.

Publishing happens when release-plz publishes a GitHub release (tag `vX.Y.Z`): the
same job stamps `X.Y.Z` into `package.json`, packs the tarball, and a second job in
the `production` environment publishes that exact tarball with provenance. A
pre-release version (`X.Y.Z-rc.1`) is published under the `next` dist-tag instead of
`latest`, and re-running a release skips a version that is already on npm.

Publishing uses npm [trusted publishing](https://docs.npmjs.com/trusted-publishers),
so the repository holds no npm token. One-time setup on npmjs.com, under the
`@worldcoin/walletkit-web` package settings: add a trusted publisher for GitHub
repository `worldcoin/walletkit`, workflow `web.yml`, environment `production`. The
scoped package does not exist yet, so its first version may have to be published by
hand (or with a short-lived token) before a trusted publisher can be attached. After
the first scoped release, point users of the old unscoped package at it with
`npm deprecate walletkit-web "Moved to @worldcoin/walletkit-web"`.

To roll back a bad release, `npm deprecate @worldcoin/walletkit-web@X.Y.Z "<reason>"`
and publish a fixed version; do not rely on `npm unpublish`.
