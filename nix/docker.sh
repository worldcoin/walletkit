#!/usr/bin/env bash
set -euo pipefail

# Run a command in one of the Nix devshells inside Docker, for hosts
# without Nix installed. Only Linux-compatible shells work here
# (default, android, wasm) — the swift shell requires macOS with Xcode.
#
# Usage: nix/docker.sh <shell> [command...]
#   nix/docker.sh android cargo build -p walletkit --release --target aarch64-linux-android --features compress-zkeys,embed-zkeys,v3
#   nix/docker.sh wasm cargo build -p walletkit --release --target wasm32-unknown-unknown
#   nix/docker.sh android            # interactive shell
#
# The Nix store lives in the `walletkit-nix-store` Docker volume so the
# toolchain is only downloaded on the first run.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SHELL_NAME="${1:-default}"
if [[ $# -gt 0 ]]; then shift; fi
if [[ $# -eq 0 ]]; then set -- bash; fi

case "${SHELL_NAME}" in
default | android | wasm) ;;
swift)
  echo "error: the swift shell needs macOS with Xcode and cannot run in Docker" >&2
  exit 1
  ;;
*)
  echo "error: unknown shell: ${SHELL_NAME} (expected: default, android, wasm)" >&2
  exit 1
  ;;
esac

TTY_FLAGS="-i"
if [[ -t 0 && -t 1 ]]; then
  TTY_FLAGS="-it"
fi

# The Android NDK only ships an x86_64 Linux toolchain, so on ARM hosts
# (e.g. Apple Silicon) the android shell must run under emulation — needs
# Rosetta enabled in Docker Desktop settings.
PLATFORM_FLAGS=""
if [[ "${SHELL_NAME}" == "android" ]]; then
  PLATFORM_FLAGS="--platform linux/amd64"
fi

# Note: the container runs as root, so on Linux hosts files created in
# target/ will be root-owned.
# shellcheck disable=SC2086 # TTY_FLAGS/PLATFORM_FLAGS are intentionally word-split
exec docker run --rm ${TTY_FLAGS} ${PLATFORM_FLAGS} \
  --volume "$PWD:/src" \
  --volume walletkit-nix-store:/nix \
  --volume walletkit-cargo-home:/root/.cargo \
  --workdir /src \
  nixos/nix:2.34.8 \
  nix --extra-experimental-features 'nix-command flakes' \
  develop ".#${SHELL_NAME}" --command "$@"
