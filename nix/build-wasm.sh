#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec nix develop .#wasm --command bash -c " \
  cd wasm && \
  npx ubrn build web --config ubrn.config.yaml --release $@ && \
  npx ubrn build web --config ubrn.node.config.yaml --release $@ \
"
