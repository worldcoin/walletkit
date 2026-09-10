#!/usr/bin/env bash
# Run on macOS: exercise the same static-library/system-SQLite collision as iOS.
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "This regression test requires the Apple linker and system SQLite." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"
profile="${1:-dev}"
case "$profile" in
  dev) profile_dir=debug ;;
  release) profile_dir=release ;;
  *) echo "Usage: bash $0 [dev|release]" >&2; exit 1 ;;
esac
cargo build --locked -p walletkit-sqlite --example native_link_probe --features native-link-probe --profile "$profile"

target_dir="${CARGO_TARGET_DIR:-target}"
output_dir="$target_dir/native-link-probe/$profile_dir"
archive="$target_dir/$profile_dir/examples/libnative_link_probe.a"
host_source="crates/walletkit-sqlite/examples/native_link_host.c"
mkdir -p "$output_dir"

# Static archive visibility matters: a hidden global symbol can still collide
# during the final app link. The standard SQLite API must have local linkage.
nm -g "$archive" > "$output_dir/symbols.txt" 2> "$output_dir/nm.log"
if grep -E ' [A-Za-z] _sqlite3_' "$output_dir/symbols.txt"; then
  echo "WalletKit still exposes or references unprefixed SQLite API symbols." >&2
  exit 1
fi

clang "$host_source" -Wl,-dead_strip -lsqlite3 "$archive" \
  -framework Security -framework CoreFoundation -o "$output_dir/system-first"
"$output_dir/system-first"

clang "$host_source" -Wl,-dead_strip "$archive" -lsqlite3 \
  -framework Security -framework CoreFoundation -o "$output_dir/walletkit-first"
"$output_dir/walletkit-first"

echo "PASS: both link orders preserve separate host and WalletKit SQLite engines"
