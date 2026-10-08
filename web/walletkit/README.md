# `@worldcoin/walletkit-web`

`@worldcoin/walletkit-web` brings WalletKit to web apps: a browser app can register
a World ID account, keep credentials in encrypted browser storage, and generate
World ID proofs. Each call to `initializeWalletKit` starts a dedicated Web Worker
that runs WalletKit's Rust code, compiled to WebAssembly (WASM), off the main
thread, and returns one WalletKit _instance_ that talks to it.

## Requirements

To run WalletKit, your app needs the following:

- A secure context: HTTPS, or `localhost` during development
- A browser with module workers and the Origin Private File System (OPFS),
  including `FileSystemSyncAccessHandle`
- A bundler that emits assets referenced with `new URL(…, import.meta.url)`, such
  as Vite or the Next.js bundler, or
  [custom asset URLs](#serve-the-assets-from-custom-urls)

Cross-origin isolation headers aren't required.

## Get started

1. Install the package:

   ```sh
   npm install @worldcoin/walletkit-web
   ```

1. In browser code, initialize WalletKit and open the account's encrypted
   storage:

   ```ts
   import { initializeWalletKit } from "@worldcoin/walletkit-web";

   declare const seed: Uint8Array; // The account's authenticator seed.
   declare const databaseKey: Uint8Array; // See "Protect the database key".

   const walletkit = await initializeWalletKit();
   const keys = await walletkit.StorageKeys.fromBytes(databaseKey);
   const paths = await walletkit.StoragePaths.fromRoot("/walletkit/my-account");
   const store = await walletkit.CredentialStore.new(paths, keys);
   ```

1. If the account isn't registered, register it:

   ```ts
   const registration =
     await walletkit.InitializingAuthenticator.registerWithDefaults(
       seed,
       undefined, // rpcUrl: use the default.
       "staging",
       "eu",
       undefined, // recoveryAddress: none.
     );
   const status = await registration.pollStatus(); // For example, { state: "queued" }.
   ```

1. To answer a relying party's proof request, open the registered account and
   generate a proof:

   ```ts
   declare const requestJson: string; // The relying party's proof request.

   const authenticator = await walletkit.Authenticator.initWithDefaults(
     seed,
     undefined, // rpcUrl: use the default.
     "staging",
     "eu",
     await walletkit.EmbeddedZkArtifacts.new(),
     store,
   );
   await authenticator.initStorage(BigInt(Math.floor(Date.now() / 1000)));
   const request = await walletkit.ProofRequest.fromJson(requestJson);
   const proofJson = await (
     await authenticator.generateProof(request)
   ).toJson();
   ```

1. When your app no longer needs WalletKit, close the instance:

   ```ts
   await walletkit.close();
   ```

Importing the package is safe during server-side rendering; call
`initializeWalletKit` only in the browser. For a complete registration, issuance,
and proof flow, see the
[Next.js example](https://github.com/worldcoin/walletkit/tree/main/examples/web).

## Protect the database key

In the browser, your app supplies the 32-byte key that encrypts the credential
store. On iOS and Android, WalletKit creates this key and seals it with the device
keystore; browsers have none, so your app derives the key, for example from a
passkey's PRF output, and passes it to `StorageKeys.fromBytes`.

- **Never store the key in `localStorage`** or anywhere else that scripts can read.
  The key is the stored credentials' only protection.
- **Derive the key the same way every time, and keep a stable root path per
  account.** Reopening a store needs both.
- **Clear your own copies.** WalletKit clears the copy that it receives and never
  persists the key, but it doesn't modify your array.

## Store credentials

WalletKit keeps its encrypted SQLite databases in OPFS, subject to the browser's
storage quota and eviction policy. It never falls back to in-memory storage.

Only one instance per origin can own the storage. If another tab or instance owns
it, `initializeWalletKit` rejects, even for a different root path. Because a
closed instance can hold the storage briefly, initialization retries for up to
about three seconds first.

To add credentials from an authenticated vault backup, call
`store.mergeVaultFromBackup(backupBytes)`.

## Use the API

The classes, methods, and arguments mirror the Swift and Kotlin bindings, in
`camelCase`. The TypeScript declarations in `dist/index.d.ts` are the complete API
reference. Constructors and static functions are properties of the instance, for
example `walletkit.FieldElement.fromU64(1n)`.

The browser API differs from the Swift and Kotlin bindings in these ways:

- Every WalletKit function and method returns a `Promise`.
- A `u64` is a `bigint`, a byte array is a `Uint8Array`, and a 256-bit value is a
  0x-prefixed hex string.
- `Environment`, `Region`, and other enums are lowercase strings, such as
  `"staging"` and `"eu"`. Records are plain objects.
- Only `generateProof` defaults its `now` argument, to the browser clock. Pass
  Unix seconds everywhere else.
- Objects stay in the worker until you call `free()` or they are garbage
  collected.

## Handle errors

WalletKit reports failures in these ways:

- A WalletKit error rejects with an `Error` whose `name` is the error type, such as
  `StorageError`, and whose `code` is the variant, such as `NullifierReplay`. Hex
  secrets in the `message` are redacted.
- An invalid argument rejects with a `TypeError`.
- If storage setup fails, `initializeWalletKit` rejects with a `StorageError`
  whose `code` is `PersistentStorage`.
- A crash in WalletKit's Rust code stops the instance, and every later call
  rejects. To recover, initialize a new instance.

WalletKit logs its own warnings and errors to the worker's console.

## Manage the instance

The worker runs one call at a time, in order, and calls have no timeout. A network
request that never settles blocks the calls queued after it.

- `close()` waits for queued calls, frees every object, and stops the worker. After
  five seconds without a response, it stops the worker anyway and rejects.
- `terminate()` stops the worker immediately and rejects pending calls.
- `isStopped()` returns `true` once the instance can no longer serve calls.

## Serve the assets from custom URLs

The package ships a worker script and a WASM module of about 40 MB. If your app
serves them itself, pass their URLs:

```ts
const walletkit = await initializeWalletKit({
  workerUrl: "/assets/walletkit.worker.js",
  wasmUrl: "/assets/walletkit.wasm",
});
```

Relative URLs resolve against the page URL. Serve the worker from your page's
origin, and serve the WASM module as `application/wasm`.

## Browser limitations

These parts of the Swift and Kotlin bindings aren't available in the browser:

| API                                                        | Reason                                                                                           |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `Logger` and the log level                                 | Not implemented for the browser.                                                                 |
| Vault and activity change listeners                        | Not implemented for the browser.                                                                 |
| Vault backup export and replacement import                 | Supported only on iOS and Android. Use `mergeVaultFromBackup` to import.                         |
| `proveCredentialSub`                                       | Credential ownership proofs aren't supported on WASM.                                            |
| Flamingo                                                   | Browser WebSockets can't send its signed handshake headers, and it relies on device attestation. |
| `DeviceKeystore`, `AtomicBlobStore`, and `StorageProvider` | They need synchronous host callbacks. Use `StorageKeys.fromBytes`.                               |
| `CachingZkArtifacts`                                       | The WASM module embeds the proving keys. Use `EmbeddedZkArtifacts`.                              |
| `UserAgent` and `UserAgentBuilder`                         | The browser controls the `User-Agent` header.                                                    |
| Issuer clients (`TfhNfcIssuer`, `RecoveryBindingManager`)  | Not included.                                                                                    |
| World ID v3 (`walletkit_core::v3`)                         | Not included.                                                                                    |

## Get help

To report a bug or ask a question, open an
[issue](https://github.com/worldcoin/walletkit/issues). To contribute, see the
[browser package docs](https://github.com/worldcoin/walletkit/blob/main/docs/web/README.md).
