# Develop WalletKit

This page describes how to set up a development environment and run the checks
that CI runs. For platform bindings, see [iOS and Swift](ios.md),
[Android and Kotlin](android.md), and the [browser package](../web/).

## Before you begin

- Install [Nix](https://nixos.org/download/). The repository's flake provides
  development shells with pinned toolchains: `default` for host development,
  `android` for Android, `wasm` for WebAssembly, and `docs` for this book. Without
  Nix, you can run the same shells in Docker; see
  [Nix development environments](https://github.com/worldcoin/walletkit/blob/main/nix/README.md).
- To run the integration tests, install [Foundry](https://getfoundry.sh/). The
  tests use Anvil to fork World Chain from the RPC endpoint in
  `WORLDCHAIN_RPC_URL`, which defaults to the public World Chain RPC. You can set
  it in a `.env` file.

Run every command on this page from the repository root.

## Lint and format

WalletKit gates code paths behind Cargo features, so a warning can appear in only
one feature combination. To lint every combination, as CI does, run the following
commands:

```sh
nix develop --command cargo clippy --workspace --all-targets --all-features -- -D warnings
nix develop --command cargo clippy --workspace --all-targets -- -D warnings
nix develop --command cargo clippy --workspace --all-targets --no-default-features -- -D warnings
```

To check formatting, run the following command:

```sh
nix develop --command cargo fmt -- --check
```

## Test

To run the workspace tests, run the following command:

```sh
nix develop --command cargo test --workspace
```

CI runs the tests with all features enabled, using `cargo nextest`, on several
Rust toolchains.

## Write documentation

The sources of this book are in `docs/`, and `docs/SUMMARY.md` defines its table
of contents. To preview the book while you edit it, run the following command and
open the URL that it prints:

```sh
nix develop .#docs --command mdbook serve
```

Link to other pages of the book with relative paths. Link to files outside `docs/`
with absolute GitHub URLs, because the book is served without the rest of the
repository.

The [`docs.yml`](https://github.com/worldcoin/walletkit/blob/main/.github/workflows/docs.yml)
workflow builds the book for every pull request that changes it, and publishes it
to GitHub Pages from `main`.
