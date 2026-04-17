#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE_DIR="$SCRIPT_DIR"
TARGET_DIR="$WORKSPACE_DIR/target/release"
GENERATED_DIR="$WORKSPACE_DIR/host-python/generated"

case "$(uname -s)" in
  Linux*)
    lib_file() { printf 'lib%s.so' "$1"; }
    ;;
  Darwin*)
    lib_file() { printf 'lib%s.dylib' "$1"; }
    ;;
  MINGW*|MSYS*|CYGWIN*)
    lib_file() { printf '%s.dll' "$1"; }
    ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

cargo build --manifest-path "$WORKSPACE_DIR/Cargo.toml" --release

for component in switchboard shouty mirror; do
  out_dir="$GENERATED_DIR/$component"
  library_path="$TARGET_DIR/$(lib_file "$component")"

  mkdir -p "$out_dir"
  find "$out_dir" -maxdepth 1 -type f \( -name '*.py' -o -name '*.so' -o -name '*.dylib' -o -name '*.dll' -o -name '*.pyd' \) -delete

  cargo run \
    --manifest-path "$WORKSPACE_DIR/Cargo.toml" \
    -p uniffi-bindgen \
    -- generate \
    --library "$library_path" \
    --language python \
    --out-dir "$out_dir"

  cp "$library_path" "$out_dir/"
done
