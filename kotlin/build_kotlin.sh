#!/usr/bin/env bash
set -euo pipefail

## Builds the Android native libraries and assembles the Kotlin bindings
## (jniLibs layout + UniFFI-generated sources). Used both locally and by CI,
## which builds the native libraries in a parallel matrix and passes them in
## via --artifacts-dir.
##
## Building requires the Android cross-compilation environment (NDK linkers
## etc.). The easiest way to get it is the Nix devshell:
##   nix develop .#android --command ./kotlin/build_kotlin.sh
## or, without Nix installed, via Docker:
##   nix/docker.sh develop .#android --command ./kotlin/build_kotlin.sh

cd "$(dirname "${BASH_SOURCE[0]}")/.."

readonly TARGETS=(
  "aarch64-linux-android"
  "armv7-linux-androideabi"
  "x86_64-linux-android"
  "i686-linux-android"
)

abi_for_target() {
  case "$1" in
  aarch64-linux-android) echo "arm64-v8a" ;;
  armv7-linux-androideabi) echo "armeabi-v7a" ;;
  x86_64-linux-android) echo "x86_64" ;;
  i686-linux-android) echo "x86" ;;
  esac
}

usage() {
  cat <<EOF
Usage: $0 [--artifacts-dir <dir>]

Options:
  --artifacts-dir <dir>  Skip the cargo builds and take prebuilt libraries
                         from <dir>/android-<target>/libwalletkit.so
                         (the layout produced by the CI build matrix).

EOF
}

ARTIFACTS_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
  --artifacts-dir)
    if [[ $# -lt 2 ]]; then
      echo "error: --artifacts-dir requires a value" >&2
      usage >&2
      exit 1
    fi
    ARTIFACTS_DIR="$2"
    shift 2
    ;;
  --help | -h)
    usage
    exit 0
    ;;
  *)
    echo "error: unknown argument: $1" >&2
    usage >&2
    exit 1
    ;;
  esac
done

if [[ -z "${ARTIFACTS_DIR}" ]]; then
  if [[ -z "${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER:-}" ]]; then
    echo "error: Android cross-compilation environment not configured." >&2
    echo "Run inside the Nix devshell:  nix develop .#android --command $0" >&2
    echo "or via Docker without Nix:    nix/docker.sh develop .#android --command $0" >&2
    exit 1
  fi

  # Defaults to the release feature set; CI overrides via WALLETKIT_CARGO_FEATURES.
  CARGO_FEATURES="${WALLETKIT_CARGO_FEATURES:-compress-zkeys,embed-zkeys,v3}"

  echo "Building WalletKit Android SDK..."
  for target in "${TARGETS[@]}"; do
    echo "Building for ${target}..."
    cargo build -p walletkit --release --locked --target "${target}" --features "$CARGO_FEATURES"
  done
fi

# Copy .so files into the jniLibs layout
echo "Copying native libraries..."
for target in "${TARGETS[@]}"; do
  abi="$(abi_for_target "${target}")"
  if [[ -n "${ARTIFACTS_DIR}" ]]; then
    src="${ARTIFACTS_DIR}/android-${target}/libwalletkit.so"
  else
    src="target/${target}/release/libwalletkit.so"
  fi
  mkdir -p "kotlin/walletkit/src/main/jniLibs/${abi}"
  cp "${src}" "kotlin/walletkit/src/main/jniLibs/${abi}/libwalletkit.so"
done

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
cargo run -p uniffi-bindgen --locked -- generate \
  kotlin/walletkit/src/main/jniLibs/arm64-v8a/libwalletkit.so \
  --library \
  --language kotlin \
  --no-format \
  --out-dir kotlin/walletkit/src/main/java

echo "✅ Build complete!"
