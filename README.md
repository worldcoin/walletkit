# WalletKit

[![Documentation](https://github.com/worldcoin/walletkit/actions/workflows/docs.yml/badge.svg)][book]

WalletKit lets apps hold World ID credentials and prove things about their holder
with [World ID](https://world.org/world-id). It is the reference implementation
for World ID clients and part of the [World ID SDK](https://docs.world.org/world-id).

WalletKit is written in Rust and ships as a Rust crate, Swift and Kotlin bindings
generated with [UniFFI](https://github.com/mozilla/uniffi-rs), and a browser
package that runs it as WebAssembly.

## Documentation

- **Integrate World ID:** start with the
  [World ID developer docs](https://docs.world.org/world-id).
- **Use WalletKit:** the [WalletKit book][book] covers installation, accounts and
  credentials, proofs, logging, and the browser package.
- **API reference:** see [`walletkit`](https://docs.rs/walletkit) and
  [`walletkit-core`](https://docs.rs/walletkit-core) on docs.rs.
- **Contribute:** see the [contributing guide](https://github.com/worldcoin/walletkit/blob/main/CONTRIBUTING.md) and the
  [development docs](https://github.com/worldcoin/walletkit/blob/main/docs/development/README.md).

## Packages

| Platform | Package                                                                                             |
| -------- | --------------------------------------------------------------------------------------------------- |
| Rust     | [`walletkit`](https://crates.io/crates/walletkit)                                                   |
| iOS      | [`worldcoin/walletkit-swift`](https://github.com/worldcoin/walletkit-swift) (Swift Package Manager) |
| Android  | `org.world:walletkit` ([GitHub Packages](https://github.com/worldcoin/walletkit/packages))          |
| Browser  | [`@worldcoin/walletkit-web`](https://www.npmjs.com/package/@worldcoin/walletkit-web)                |

## Crates

| Crate                                                                                            | Description                                                                                        |
| ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| [`walletkit`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit)                 | The published entry point, re-exporting `walletkit-core`.                                          |
| [`walletkit-core`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-core)       | Accounts, credential storage, and World ID proofs; the UniFFI surface for Swift and Kotlin.        |
| [`walletkit-db`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-db)           | Encrypted on-device storage: vault, content-addressed blobs, key envelope, and cross-process lock. |
| [`walletkit-sqlite`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-sqlite)   | Safe Rust wrapper around encrypted SQLite (`sqlite3mc`).                                           |
| [`walletkit-web`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-web)         | `wasm-bindgen` facade over `walletkit-core` for the browser package.                               |
| [`walletkit-cli`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-cli)         | Developer CLI for accounts, credentials, and proofs.                                               |
| [`walletkit-testkit`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-testkit) | End-to-end test helpers.                                                                           |
| [`uniffi-bindgen`](https://github.com/worldcoin/walletkit/tree/main/crates/uniffi-bindgen)       | Generates the Swift and Kotlin bindings.                                                           |

## Project structure

- **`crates/`**: Rust crates
- **`swift/`** and **`kotlin/`**: Swift package and Android library configuration,
  with their binding tests
- **`web/walletkit/`**: the browser package
- **`examples/`**: example apps, including a Next.js app that registers an
  account, issues a credential, and generates a proof with the browser package
- **`docs/`**: sources of the [WalletKit book][book]
- **`xtask/`**: build automation for the Swift and Kotlin packages
  (`cargo xtask`)
- **`nix/`**: development shells for Android, WebAssembly, and host builds
- **`audits/`**: security audit reports

## Security

Report security issues privately to
[security@toolsforhumanity.com](mailto:security@toolsforhumanity.com), not in
public issues. For details, see [`SECURITY.md`](https://github.com/worldcoin/walletkit/blob/main/SECURITY.md).

[book]: https://worldcoin.github.io/walletkit/
