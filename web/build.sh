#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
bash web/cargo.sh build -p walletkit-web --release --target wasm32-unknown-unknown
wasm-bindgen "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/walletkit_web.wasm" \
  --target web --out-dir web/pkg --out-name walletkit_web
