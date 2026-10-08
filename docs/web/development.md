# Develop the browser package

This page describes how to build and test `@worldcoin/walletkit-web` and how to
expose a `walletkit-core` API to the browser. For the design behind these steps,
see [How the browser package works](architecture.md).

## Before you begin

- Install Nix. The `wasm` devshell pins the Rust toolchain, the `wasm-bindgen`
  CLI, Binaryen, and Bun. Without Nix, you can run the devshell in Docker with
  `nix/docker.sh`; for details, see [Nix development environments](https://github.com/worldcoin/walletkit/blob/main/nix/README.md).
- To run the browser tests, install Google Chrome on the machine that runs them.
  Playwright drives the installed Chrome (the `chrome` channel), not its bundled
  Chromium, and neither the devshell nor the Docker wrapper provides Chrome.

Run every command on this page from the repository root.

## Build the package

1. Install the JavaScript dependencies:

   ```sh
   nix develop .#wasm --command bun install --cwd web/walletkit --frozen-lockfile
   ```

1. Build the WASM module and the TypeScript bundle into `web/walletkit/dist`:

   ```sh
   nix develop .#wasm --command bun run --cwd web/walletkit build
   ```

To rebuild after a TypeScript-only change, run the following command. It reuses
the WASM module from the last full build:

```sh
nix develop .#wasm --command bun run --cwd web/walletkit bundle
```

## Test the package

To run the browser tests, run the following command. It type-checks the tests and
the fixture app, builds the fixture with Vite, and runs the Playwright tests in
Chrome:

```sh
nix develop .#wasm --command bun run --cwd web/walletkit test:browser
```

The tests are in [`web/walletkit/tests`](https://github.com/worldcoin/walletkit/tree/main/web/walletkit/tests):

- `browser.spec.ts` drives the built package in a page.
- `types/consumer.ts` checks the public TypeScript API at compile time. To check
  that an invalid call doesn't compile, mark it with `// @ts-expect-error`.

CI also lints the crate and checks the TypeScript formatting. To run the same
checks, run these commands:

```sh
nix develop .#wasm --command cargo clippy -p walletkit-web --no-deps \
  --target wasm32-unknown-unknown --locked -- -D warnings
nix develop .#wasm --command bun run --cwd web/walletkit format:check
```

The [Next.js example](https://github.com/worldcoin/walletkit/tree/main/examples/web) is the package's integration consumer.
CI type-checks, tests, and builds it against the package from the same checkout.

## Expose a core API to the browser

The worker and the page proxy dispatch new exports without changes, but the
public type names are listed by hand. To expose a `walletkit-core` class or
function, do the following:

1. In [`crates/walletkit-web/src`](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-web/src), add a wrapper
   with `#[wasm_bindgen]`. Follow the conventions of the wrappers there:
   - Keep the UniFFI name and arguments, with `js_name` in `camelCase`.
   - Hold the core object in an `Arc`, so that asynchronous methods can return a
     `'static` future.
   - Take a `u64` as a `BigInt` and validate it with `js::u64_arg`.
   - Return records as plain objects built with `js::object`.
   - Return a `Promise` from asynchronous methods with `js::promise`.
   - Convert errors with `error::to_js`, and reject invalid arguments with
     `error::invalid_argument`, which throws a `TypeError`.
1. For a class, add a `RemoteObject` type alias in
   [`remote.ts`](https://github.com/worldcoin/walletkit/blob/main/web/walletkit/src/remote.ts) and export it from
   [`index.ts`](https://github.com/worldcoin/walletkit/blob/main/web/walletkit/src/index.ts). For a record or an enum, export
   its generated type from `index.ts`.
1. Add compile-time checks to `tests/types/consumer.ts` and a browser test to
   `tests/browser.spec.ts`.
1. If the API appears in
   [Browser limitations](package.md#browser-limitations), remove it from that
   table in `web/walletkit/README.md`.
