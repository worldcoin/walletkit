#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec nix develop .#wasm --command bash -c '
  cd wasm
  exec cargo run \
    --manifest-path ../Cargo.toml \
    -p uniffi-bindgen \
    --bin uniffi-bindgen-react-native \
    -- build web \
    --config ubrn.config.yaml \
    --release \
    "$@"
' bash "$@"
