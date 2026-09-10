# `walletkit-web`

Browser WebAssembly bindings for WalletKit.

> PROTOTYPE: the package is published while its generation and release workflow
> is being validated.

The package owns the compiled WalletKit module, generated TypeScript bindings,
UniFFI player setup, and WASM asset resolution. Browser applications initialize
it through one interface:

```ts
const { initializeWalletKit } = await import("walletkit-web");
const walletKit = await initializeWalletKit();
```

Build it from the repository root with the pinned toolchain:

```sh
nix develop .#wasm --command bun install --cwd web/walletkit --frozen-lockfile
nix develop .#wasm --command bun run --cwd web/walletkit build
```

The release build uses `crates/walletkit` directly, disables its default
features except for `embed-zkeys`, and optimizes the generated module with
`wasm-opt -Oz --converge`. Embedding the proving artifacts currently makes the
optimized WASM roughly 40 MB; lazy artifact delivery and worker placement are
still future production work.
