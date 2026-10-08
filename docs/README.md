# WalletKit

WalletKit lets apps hold World ID credentials and prove things about their holder
with [World ID](https://world.org/world-id). It is part of the
[World ID SDK](https://docs.world.org/world-id).

WalletKit is written in Rust. Apps use it in one of these forms:

- **Rust**: the [`walletkit`](https://crates.io/crates/walletkit) crate.
- **iOS**: Swift bindings, generated with
  [UniFFI](https://github.com/mozilla/uniffi-rs).
- **Android**: Kotlin bindings, generated with UniFFI.
- **Browser**: the [`@worldcoin/walletkit-web`](web/package.md) npm package, which
  runs WalletKit as WebAssembly in a Web Worker.

All forms share the same core, `walletkit-core`, and expose the same objects, such
as `Authenticator` and `CredentialStore`. The browser package omits a few of them;
see [Browser limitations](web/package.md#browser-limitations).

## Find what you need

- To add WalletKit to an app, see [Install WalletKit](installation.md).
- To learn how an account is registered and how credentials are stored, see
  [Accounts and credentials](accounts.md).
- To answer a relying party's proof request, see [Generate a proof](proofs.md).
- To change WalletKit, see [Develop WalletKit](development/).
- For the API reference of the Rust crates, see
  [`walletkit` on docs.rs](https://docs.rs/walletkit).

To preview this book locally, run the following command from the repository root
and open the URL that it prints:

```sh
nix develop .#docs --command mdbook serve
```
