#!/usr/bin/env bash
set -euo pipefail

# Run Nix commands in a Linux/amd64 Docker container for hosts without Nix.
# This mirrors the Nix CLI; only the container boundary is added.
#
# Usage:
#   nix/docker.sh develop .#android
#   nix/docker.sh develop .#android --command ./kotlin/build_kotlin.sh
#   nix/docker.sh develop .#wasm --command cargo build --release --target wasm32-unknown-unknown
#   nix/docker.sh flake show
#
# The Swift shell cannot work in this Linux container because it needs macOS
# and Xcode. Use native Nix for `nix develop .#swift`.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TTY_FLAGS=(-i)
if [[ -t 0 && -t 1 ]]; then
  TTY_FLAGS=(-it)
fi

# Always use linux/amd64 because the Android NDK has no aarch64-linux host
# toolchain. This is emulated on ARM hosts. Keep the Nix store and Cargo home
# architecture-specific so they cannot be contaminated by native ARM binaries.
# Nix's syscall filter cannot be installed under Rosetta emulation; Docker still
# provides the outer container sandbox.
#
# Note: the container runs as root, so on Linux hosts files created in target/
# will be root-owned.
exec docker run --rm "${TTY_FLAGS[@]}" --platform linux/amd64 \
  --volume "$PWD:/src" \
  --volume walletkit-nix-store-amd64:/nix \
  --volume walletkit-cargo-home-amd64:/root/.cargo \
  --workdir /src \
  nixos/nix:2.34.8 \
  nix --extra-experimental-features 'nix-command flakes' \
  --option filter-syscalls false \
  "$@"
