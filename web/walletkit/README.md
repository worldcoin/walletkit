# `@worldcoin/walletkit-web`

Browser WebAssembly bindings for WalletKit.

> PROTOTYPE: this package is private while its generation and publication
> workflow is being validated.

The package owns the compiled WalletKit module, generated TypeScript bindings,
UniFFI player setup, and WASM asset resolution. Browser applications initialize
it through one interface:

```ts
const { initializeWalletKit } = await import("@worldcoin/walletkit-web");
const walletKit = await initializeWalletKit();
```

Build it from the repository root with the pinned toolchain:

```sh
nix develop .#wasm --command npm --prefix web/walletkit install
nix develop .#wasm --command npm --prefix web/walletkit run build
```

The release build uses `crates/walletkit` directly, disables its default
features, and optimizes the generated module with
`wasm-opt -Oz --converge`.
