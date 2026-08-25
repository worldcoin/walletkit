# WalletKit UniFFI browser authenticator POC

> PROTOTYPE: throwaway feasibility probe, not production packaging.

This example asks one question: can WalletKit's existing UniFFI authenticator
surface be generated, loaded, and called from a Next.js App Router application
through `uniffi-bindgen-react-native`'s WASM player?

Run it from the repository root with the pinned WASM toolchain:

```sh
nix develop .#wasm --command npm --prefix examples/uniffi-web-authenticator-poc install
nix develop .#wasm --command npm --prefix examples/uniffi-web-authenticator-poc run dev
```

`npm run dev` regenerates the bindings before starting Next.js. Use
`npm run build` to prove the production bundle as well. These scripts expect to
run inside `nix develop .#wasm`, which supplies Node, Binaryen, and the
WASM-targeted Clang and LLVM tools.

The Rust wrapper is deliberately local to this example so the WASM player's
runtime dependency does not leak into WalletKit's production crate graph.

## What the POC proves

- The generator can produce TypeScript for WalletKit records, errors, objects,
  callbacks, and async authenticator methods.
- The generated WASM loads in a browser and calls WalletKit synchronously to
  derive authenticator recovery material from secure browser randomness.
- Next.js can bundle the generated JavaScript glue in a Client Component while
  serving the generated WASM as a static asset from `public/wasm`.
- An async authenticator constructor crosses the generated future/error bridge;
  the smoke call uses invalid configuration and stops before any network request.
- The UI wires the generated async `InitializingAuthenticator` registration and
  polling methods. Registration is an explicit, opt-in staging mutation.

## Experimental compatibility pins

The released generator (`0.31.0-5`) cannot parse UniFFI 0.32 metadata, so this
POC pins the worktree to UniFFI 0.31.2. Its internal wasm-bindgen processor is
also pinned to 0.2.100, while `sqlite-wasm-rs` requires a newer schema; the
postinstall script aligns the generator to WalletKit's 0.2.126 schema.

WalletKit's native bindings ask UniFFI to adapt exported futures to Tokio. That
adapter creates a fallback thread when it is polled without a Tokio runtime,
which browser WASM cannot do. The POC enables `walletkit-core/uniffi-wasm` so
only the authenticator exports skip that adapter and are polled directly by the
generator's WASM player; native builds keep their existing Tokio behavior.

The generated bindings are imported dynamically from a Client Component. This
keeps the WASM player and browser-only APIs out of Next.js server rendering.

The generated WASM is optimized with Binaryen's `wasm-opt -Oz --converge`
before it is copied into the Next.js public assets. No attempt has been made to
productionize storage, artifact loading, worker placement, bundle splitting,
or key persistence.
