#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$PWD"
flamingo_dir="${FLAMINGO_DIR:-$root/target/web-deps/flamingo}"
pontifex_dir="${PONTIFEX_DIR:-$root/target/web-deps/pontifex}"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
if [[ "$CARGO_TARGET_DIR" != /* ]]; then
  export CARGO_TARGET_DIR="$root/$CARGO_TARGET_DIR"
fi
(
  cd "$pontifex_dir"
  cargo +1.98.1 test --no-default-features --features channel,attestation \
    --target wasm32-unknown-unknown --lib
)
(
  cd "$flamingo_dir"
  cargo test -p flamingo-verifier-client --target wasm32-unknown-unknown --lib \
    --config "patch.crates-io.pontifex.path=\"$pontifex_dir\""
)
