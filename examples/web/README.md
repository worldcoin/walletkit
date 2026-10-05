# WalletKit web package Next.js example

> PROTOTYPE: integration probe for the `@worldcoin/walletkit-web` package.

This example verifies that a Next.js App Router application can consume
WalletKit as an ordinary package without owning its Rust wrapper, WASM
optimization, or asset staging.

The example consumes `@worldcoin/walletkit-web` from this checkout (a `link:`
dependency), so it always runs the package's current Swift/Kotlin-style object API
(`Authenticator`, `CredentialStore`, …). `walletkit:local` builds the package, links
it and installs; run it inside the WASM Nix shell, then start the app:

```sh
nix develop .#wasm --command bash -c \
  'cd examples/web && bun run walletkit:local && bun run dev'
```

Use `bun run build` to prove the production bundle as well. To exercise a published
build instead, replace the `link:` dependency with a registry version once one exists.

## What the POC proves

- `@worldcoin/walletkit-web` hides generation and WASM loading behind
  `initializeWalletKit()`.
- The package exposes an async facade that mirrors the Swift and Kotlin objects
  and owns the worker running WalletKit.
- The generated WASM loads in a browser and calls WalletKit synchronously to
  derive authenticator recovery material from secure browser randomness.
- Next.js can bundle the package's generated JavaScript glue and emit its WASM
  asset from a Client Component.
- The UI drives a real opt-in staging flow: account registration, persistent
  credential-store initialization, faux credential issuance, and uniqueness
  proof generation.
- A staging RP proof request is signed in the browser with the intentionally
  public test key used by `walletkit-testkit`.
- A same-origin Next.js route forwards the issuance request because the hosted
  staging faux issuer does not allow browser CORS preflights.

## Browser build

The package is built from the `walletkit-web` crate, a small `wasm-bindgen`
facade over `walletkit-core`, rather than from generated UniFFI bindings. The
facade keeps WalletKit's Rust objects inside the worker, hands the page handles to
them, and returns records as plain data.

The package is imported dynamically from a Client Component. This keeps the
WASM module and browser-only APIs out of Next.js server rendering.

The package's WASM is optimized with Binaryen's `wasm-opt -Oz --converge` and
resolved from the package with `new URL(..., import.meta.url)`. Proof generation
currently embeds the proving artifacts, making the optimized WASM roughly 40 MB.
The example reuses a saved storage ID and database key to reopen its encrypted
OPFS SQLite databases. Its seed and registration/issuance progress are also saved,
so after reload you can initialize the existing authenticator and use its stored
credentials without registering again. Initialization remains an explicit action
because it contacts staging services.

The versioned demo profile is stored in localStorage, including the seed and raw
database key. This is staging-only key retention, not passkey protection: scripts
on the origin can read both keys. Production hosts should supply a protected key
source, such as passkey PRF. Corrupt profiles fail rather than silently replacing
keys. Use one tab per origin; clearing site data removes both the profile and OPFS
databases. A browser can also evict site data, so this is not a backup.

Use the local package workflow above for this unreleased worker API.
