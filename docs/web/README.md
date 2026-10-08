# Browser package

`@worldcoin/walletkit-web` runs WalletKit in the browser. Its source is in
`web/walletkit` (TypeScript) and `crates/walletkit-web` (Rust). To use the package,
see [Use WalletKit in the browser](package.md).

The following pages are for contributors to the package:

- [How the browser package works](architecture.md): the worker, the page proxy,
  object handles, error handling, and storage.
- [Develop the browser package](development.md): build and test the package, and
  expose a `walletkit-core` API to the browser.
- [Release the browser package](releasing.md): publish to npm, configure trusted
  publishing, and roll back a release.
