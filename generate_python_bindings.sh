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

# Map: crate package name → native lib stem (snake_case).
#
# issuer-sdk is now a cdylib that owns IssuerDriver as a proper UniFFI export.
# issuer-host re-exports those symbols via uniffi_reexport_scaffolding!(), but
# Python adapters subclass IssuerDriver from the issuer_sdk module directly.
declare -A COMPONENTS=(
  ["issuer-sdk"]="issuer_sdk"
  ["issuer-host"]="issuer_host"
  ["orb-kit"]="orb_kit"
  ["nfc-kit"]="nfc_kit"
)

for component in "${!COMPONENTS[@]}"; do
  lib_stem="${COMPONENTS[$component]}"
  out_dir="$GENERATED_DIR/$lib_stem"
  library_path="$TARGET_DIR/$(lib_file "$lib_stem")"

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
