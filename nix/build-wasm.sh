#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec nix develop .#wasm --command cargo build \
  -p walletkit \
  --release \
  --locked \
  --target wasm32-unknown-unknown \
  "$@"
