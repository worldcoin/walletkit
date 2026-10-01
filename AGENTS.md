# WalletKit Agent Guidelines

## Build environment

Dependency and build setup can be complex, especially for cross-compilation. Use the devshells provided by `flake.nix`: `default` for host development, `android` for Android, and `wasm` for WebAssembly. From the repository root:

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

## Compatibility pitfalls

- Preserve the on-disk format: schemas, CBOR layouts, and `compute_content_id` derivations must remain compatible with existing databases. Guard format-sensitive changes with frozen-byte tests next to the code.
- Never name a UniFFI-exported method `to_string`: its Kotlin binding conflicts with `Any.toString()`. Use a descriptive name such as `to_hex_string`, `to_decimal_string`, or `to_json`.

## Logging & Error handling

Take care when designing log statements & error types to avoid leaking sensitive user information. Anything crossing the FFI boundary should be carefully inspected for potential leakage of sensitive info.

## Code Style

Take care to ensure the code you submit is readable.

### Comments

Comments in code—with the exception of doc comments—should be kept to an **absolute minimum**. Comments in code are justified if they explain a tricky concept or warn against making changes to the code in question.

If present - comments in code should only describe the current state of the code. They should never refer to any previous version of the code. And they should never include information provided in the prompt that is not relevant to the reader.

Code comments linking to GitHub issues or documenting workarounds are acceptable, e.g.

```rust
// TODO: A temporary workaround - remove once https://github.com/org/repo/pull/123 is merged
```

### The Boy Scout Rule

Leave the code better than you found it, within the scope of the task.

Improvement often means deletion, not addition. Remove unused code, obsolete workarounds, unnecessary abstractions, misleading or redundant comments, and tests that provide no meaningful protection. Bad code does not need to be preserved merely because it already exists. Verify that apparently unused code has no relevant callers or external contract; when removing a poor implementation, preserve or replace any behavior that is still required. Apply the same judgment to tests: remove noise, not meaningful regression coverage.

### Stepdown rule

Code should read top to bottom, for example:

```rust
// BAD
fn bar() {
  // ...
}

fn foo() {
  bar()
}

// GOOD
fn foo() {
  bar()
}

fn bar() {
  // ...
}
```

### Commits

Commits should follow the Conventional Commits specification. Group changes in meaningful small commits.

## AI Disclosure

When creating a pull request - make sure to disclose the AI model & the prompt used.
