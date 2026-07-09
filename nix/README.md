# Nix development environments

This directory contains the Nix devshells and helper scripts used to
cross-compile WalletKit for Android, iOS and wasm, both locally and in CI.

The flake provides **devshells, not packages**: the shells pin the Rust
toolchain (from `rust-toolchain.toml`), the Android NDK, nargo and every
env var cargo needs for cross-compilation — the builds themselves are
ordinary `cargo build` invocations run inside a shell.

## Shells

| Shell | Purpose | Systems |
|---|---|---|
| `default` | Host builds, uniffi-bindgen, nargo | all |
| `android` | Cross-compile the 4 Android targets (NDK, linkers, API 23) | linux/darwin x86_64, darwin aarch64 |
| `swift` | iOS targets via the **host** Xcode | macOS only |
| `wasm` | `wasm32-unknown-unknown` with a wasm-safe clang | all |

```bash
nix develop .#android   # enter a shell
nix develop .#android --command cargo build ...   # or run one command
```

Convenience wrappers (they enter the right shell for you):

```bash
nix/build-android.sh --target aarch64-linux-android
nix/build-wasm.sh
nix/build-swift.sh                                   # macOS + Xcode required
nix develop .#android --command ./kotlin/build_kotlin.sh   # full Android jniLibs + bindings
```

## iOS is only partially hermetic

Apple's iOS SDKs cannot be redistributed through nixpkgs, so the `swift`
shell deliberately escapes to the host Xcode (`/usr/bin/xcrun` etc.).
Nix pins everything else; the Xcode version comes from the machine.
CI pins it via `WALLETKIT_DEVELOPER_DIR` — the shell fails loudly if that
path lacks the iOS SDKs. You can use the same variable locally to select
a specific Xcode install.

## No Nix installed? Use Docker

`nix/docker.sh` runs any Linux-compatible shell (`default`, `android`,
`wasm`) inside a `nixos/nix` container — the only host dependency is Docker:

```bash
nix/docker.sh android ./kotlin/build_kotlin.sh   # Android libs + Kotlin bindings
nix/docker.sh wasm cargo build -p walletkit --release --locked --target wasm32-unknown-unknown
nix/docker.sh default                            # interactive shell
```

Notes:

- The Nix store is kept in the `walletkit-nix-store` Docker volume, so
  toolchains download only on the first run (`docker volume rm
  walletkit-nix-store` to reclaim the space).
- The Android NDK only ships an x86_64 Linux toolchain, so on Apple
  Silicon the `android` shell runs the container as `linux/amd64` —
  enable Rosetta emulation in Docker Desktop settings (on by default in
  recent versions). Expect it to be slower than native.
- The `swift` shell cannot run in Docker (needs macOS + Xcode).
- On Linux hosts, files created by the container (e.g. `target/`) are
  root-owned.

## Building without Nix at all

Possible, if you bring the dependencies yourself:

- **Host / wasm / iOS**: `rustup` picks the toolchain and targets up from
  `rust-toolchain.toml`, and `.cargo/config.toml` carries the target
  rustflags. wasm needs clang ≥ 18 exported as `CC_wasm32_unknown_unknown`
  (see `nix/wasm.nix`). iOS additionally needs:
  - full Xcode with the iOS SDKs — if `xcode-select -p` points at
    CommandLineTools, builds fail with `SDK "iphoneos" cannot be located`;
    fix with `sudo xcode-select -s /Applications/Xcode.app` or
    `export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`
    (the Nix shell does this fallback for you)
  - `cmake` (`brew install cmake`) — aws-lc-sys builds its C code with it
  - `swiftlint`, but only for `archive_swift.sh` (release packaging)
- **Android**: you need NDK r27 and the `CC_*`/`AR_*`/
  `CARGO_TARGET_*_LINKER` env vars pointing into it — exactly what
  `nix/android.nix` sets. There is no script for the manual setup; the
  Nix shell (or its Docker wrapper) is the supported path.
- **nargo**: install the version matching the `provekit_*` crates in
  `Cargo.lock` (see `nix/nargo.nix`).
