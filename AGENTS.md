# WalletKit Agent Guidelines

## Build environment

Dependency and build setup can be complex, especially for cross-compilation.
Use the devshells provided by `flake.nix`: `default` for host development,
`android` for Android, and `wasm` for WebAssembly. From the repository root:

```bash
nix develop .#wasm
nix develop .#android --command cargo xtask kotlin build
```

If Nix is not installed locally, use `nix/docker.sh` with the same arguments
(requires Docker, plus host Git for worktrees):

```bash
nix/docker.sh develop .#wasm
```

The Docker wrapper runs Linux/amd64, using emulation on ARM hosts. Swift/iOS
builds require macOS and Xcode; use `cargo xtask swift` on the host.
See [nix/README.md](nix/README.md) for platform support and build commands.

## Compatibility pitfalls

- Preserve the on-disk format: schemas, CBOR layouts, and `compute_content_id` derivations must remain compatible with existing databases. Guard format-sensitive changes with frozen-byte tests next to the code.
- Never name a UniFFI-exported method `to_string`: its Kotlin binding conflicts with `Any.toString()`. Use a descriptive name such as `to_hex_string`, `to_decimal_string`, or `to_json`.
