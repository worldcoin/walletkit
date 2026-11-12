# WalletKit Agent Guidelines

## You are the owner of this codebase

You are the owner and long-term maintainer of this codebase, and its design is up to you.

- Optimize for the next reader over quick local patches.
- Read and understand the surrounding code before changing it.
- Fix root causes instead of papering over symptoms.
- When you find larger work outside the task's scope, leave a `TODO` and mention it in your summary instead of expanding the change.
- Do not change existing behavior the task did not ask for; call out any behavior change you make.
- List every change in your summary, including small ones.
- Push back when a request is wrong or a better approach exists.

## Build environment

Dependency and build setup can be complex, especially for cross-compilation. Use the devshells provided by `flake.nix`: `default` for host development, `android` for Android, `wasm` for WebAssembly, and `docs` for the mdBook in `docs/`. From the repository root:

```bash
nix develop .#wasm
nix develop .#android --command cargo xtask kotlin build
```

If Nix is not installed locally, use `nix/docker.sh` with the same arguments (requires Docker, plus host Git for worktrees):

```bash
nix/docker.sh develop .#wasm
```

The Docker wrapper runs Linux/amd64, using emulation on ARM hosts.

Swift/iOS builds require macOS and Xcode; use `cargo xtask swift` on the host. See [nix/README.md](nix/README.md) for platform support and build commands.

Human-facing guides live in the mdBook under `docs/` (see `docs/SUMMARY.md`); update the page that owns a fact instead of repeating it elsewhere.

For changes to the browser package (`crates/walletkit-web` or `web/walletkit`), follow [docs/web/development.md](docs/web/development.md). New functions need no TypeScript changes; a new class also needs a `RemoteObject` alias in `remote.ts` and an export from `index.ts`, and a new record or enum needs an export from `index.ts`. Add type tests for every new export.

## Compatibility pitfalls

- Preserve the on-disk format: schemas, CBOR layouts, and `compute_content_id` derivations must remain compatible with existing databases. Guard format-sensitive changes with frozen-byte tests next to the code.
- Never name a UniFFI-exported method `to_string`: its Kotlin binding conflicts with `Any.toString()`. Use a descriptive name such as `to_hex_string`, `to_decimal_string`, or `to_json`.

## Logging & Error handling

Take care when designing log statements & error types to avoid leaking sensitive user information. Anything crossing the FFI boundary should be carefully inspected for potential leakage of sensitive info.

## Code style

Write readable, self-explanatory code.

### Comments

Keep non-doc comments to a minimum. Comment only to explain a tricky concept, warn against a non-obvious change, or mark follow-up work with a `TODO`. Link the issue or PR when one exists:

```rust
// TODO: Temporary workaround, remove once https://github.com/org/repo/pull/123 is merged
```

Describe only the current state of the code. Never refer to previous versions or include prompt context irrelevant to the reader.

### The Boy Scout rule

Leave touched code better than you found it, within the scope of the task. Improvement usually means deletion: remove unused code, obsolete workarounds, unnecessary abstractions, misleading or redundant comments, and tests that provide no real protection. Bad code does not deserve to survive just because it exists. Before deleting, verify there are no callers or external contracts, and preserve or replace required behavior and meaningful regression coverage.

### Stepdown rule

Order definitions so files read top to bottom, with callers before callees:

```rust
// BAD
fn bar() {}
fn foo() { bar(); }

// GOOD
fn foo() { bar(); }
fn bar() {}
```

### Commits

Commits should follow the Conventional Commits specification. Group changes in meaningful small commits.

## AI Disclosure

When creating a pull request, disclose the AI model used and provide a sanitized summary of the prompt that excludes sensitive, confidential, and personal information.
