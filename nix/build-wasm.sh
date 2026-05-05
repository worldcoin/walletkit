#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec nix develop .#wasm --command bash -c " \
  cd wasm && \
  npm run build:wasm:web && \
  npm run build:wasm:node && \
  npm run build:js && \
  npm run build:js:web && \
  npm run build:js:node \
"
