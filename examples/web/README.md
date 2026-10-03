# WalletKit web package Next.js example

> PROTOTYPE: integration probe for the published `walletkit-web` package.

This example verifies that a Next.js App Router application can consume
WalletKit as an ordinary package without owning its Rust wrapper, WASM
optimization, or asset staging.

Run it from the repository root:

```sh
bun install --cwd examples/web --frozen-lockfile
bun run --cwd examples/web dev
```

The example installs `walletkit-web` from the npm registry and does not build the
package's Rust, wasm-bindgen glue, or WASM locally. Use `bun run build` to prove the
production bundle as well.

To test the package from this checkout instead, run `bun run walletkit:local`
from the example directory inside the WASM Nix shell. This builds and links the
local package. Run `bun run walletkit:published` to restore the registry package.

## What the POC proves

- `walletkit-web` hides generation and WASM loading behind
  `initializeWalletKit()`.
- The package exposes an async facade and owns the worker running WalletKit.
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
facade owns WalletKit's Rust objects inside the worker and returns plain data.
It enables `walletkit-core/uniffi-wasm`, which exports futures without UniFFI's
Tokio adapter; that adapter needs a fallback thread browser WASM cannot create.

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
