#!/usr/bin/env bash
# Develop the coordinated WalletKit / Flamingo / Pontifex changes before their releases.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
flamingo_dir="${FLAMINGO_DIR:-$PWD/target/web-deps/flamingo}"
pontifex_dir="${PONTIFEX_DIR:-$PWD/target/web-deps/pontifex}"
for dep_dir in "$flamingo_dir" "$pontifex_dir"; do
  if [[ ! -f "$dep_dir/Cargo.toml" ]]; then
    echo "Missing dependency checkout: $dep_dir. Run bash web/bootstrap-deps.sh first." >&2
    exit 1
  fi
done
command="$1"
shift
exec cargo "$command" \
  --config "patch.crates-io.pontifex.path=\"$pontifex_dir\"" \
  --config "patch.crates-io.flamingo-verifier-client.path=\"$flamingo_dir/verifier/client\"" \
  --config "patch.crates-io.flamingo-verifier-api-types.path=\"$flamingo_dir/verifier/api-types\"" \
  --config "patch.crates-io.flamingo-verifier-protocol.path=\"$flamingo_dir/verifier/protocol\"" \
  --config "patch.crates-io.flamingo-verifier-sealed-types.path=\"$flamingo_dir/verifier/sealed-types\"" \
  "$@"
