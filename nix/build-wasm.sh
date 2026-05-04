#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec nix develop .#wasm --command cargo build \
  -p walletkit \
  --release \
  --target wasm32-unknown-unknown \
  "$@"
