#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec nix develop .#wasm --command bash -c '
  set -euo pipefail

  cd wasm

  build_wasm() {
    local config="$1"
    shift

    cargo run \
      --manifest-path ../Cargo.toml \
      -p uniffi-bindgen \
      --bin uniffi-bindgen-react-native \
      -- build web \
      --config "$config" \
      --release \
      "$@"
  }

  build_wasm ubrn.config.yaml "$@"
  build_wasm ubrn.node.config.yaml "$@"
' bash "$@"
