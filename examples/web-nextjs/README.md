# WalletKit web Next.js example

This example verifies that a Next.js App Router application can consume
WalletKit as an ordinary package without owning its Rust wrapper, UniFFI
generation, WASM optimization, or asset staging.

Run it from the repository root:

```sh
bun install --cwd examples/web-nextjs --frozen-lockfile
bun run --cwd examples/web-nextjs dev
```

The example installs `walletkit-web` from the npm registry and does not build the
package's Rust, generated bindings, or WASM locally. Use `bun run build` to prove the
production bundle as well.

To test the package from this checkout instead, run `bun run walletkit:local`
from the example directory inside the WASM Nix shell. This builds and links the
local package. Run `bun run walletkit:published` to restore the registry package.

## What the example proves

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

## Experimental compatibility pins

The published `walletkit-web` 0.21.3 package was generated with UniFFI 0.31.2
because the released generator (`0.31.0-5`) cannot parse UniFFI 0.32 metadata.
Its internal wasm-bindgen processor is pinned to 0.2.100, while
`sqlite-wasm-rs` requires a newer schema; the package build aligns the
generator to WalletKit's 0.2.126 schema.

WalletKit's native bindings ask UniFFI to adapt exported futures to Tokio. That
adapter creates a fallback thread when it is polled without a Tokio runtime,
which browser WASM cannot do. The `walletkit` crate enables
`walletkit-core/uniffi-wasm` only for `wasm32-unknown-unknown`, so the
authenticator exports are polled directly by the generator's WASM player while
native builds keep their existing Tokio behavior.

The package is imported dynamically from a Client Component. This keeps the
WASM player and browser-only APIs out of Next.js server rendering.

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
