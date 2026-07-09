#!/bin/bash
set -e

## This script is only used for local builds. For production releases, the code is in the CI workflow.
##
## Requires the Android cross-compilation environment (NDK linkers etc.).
## The easiest way to get it is the Nix devshell:
##   nix develop .#android --command ./kotlin/build_kotlin.sh
## or, without Nix installed, via Docker:
##   nix/docker.sh android ./kotlin/build_kotlin.sh

if [ -z "${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER:-}" ]; then
  echo "error: Android cross-compilation environment not configured." >&2
  echo "Run inside the Nix devshell:  nix develop .#android --command $0" >&2
  echo "or via Docker without Nix:    nix/docker.sh android $0" >&2
  exit 1
fi

echo "Building WalletKit Android SDK..."

CARGO_FEATURES="compress-zkeys,embed-zkeys,v3"

# Create jniLibs directories
mkdir -p ./walletkit/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

# Build for all Android architectures
echo "Building for aarch64-linux-android..."
cargo build -p walletkit --release --locked --target=aarch64-linux-android --features "$CARGO_FEATURES"

echo "Building for armv7-linux-androideabi..."
cargo build -p walletkit --release --locked --target=armv7-linux-androideabi --features "$CARGO_FEATURES"

echo "Building for x86_64-linux-android..."
cargo build -p walletkit --release --locked --target=x86_64-linux-android --features "$CARGO_FEATURES"

echo "Building for i686-linux-android..."
cargo build -p walletkit --release --locked --target=i686-linux-android --features "$CARGO_FEATURES"

# Move .so files to jniLibs
echo "Moving native libraries..."
mv ../target/aarch64-linux-android/release/libwalletkit.so ./walletkit/src/main/jniLibs/arm64-v8a/libwalletkit.so
mv ../target/armv7-linux-androideabi/release/libwalletkit.so ./walletkit/src/main/jniLibs/armeabi-v7a/libwalletkit.so
mv ../target/x86_64-linux-android/release/libwalletkit.so ./walletkit/src/main/jniLibs/x86_64/libwalletkit.so
mv ../target/i686-linux-android/release/libwalletkit.so ./walletkit/src/main/jniLibs/x86/libwalletkit.so

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
cargo run -p uniffi-bindgen generate \
  ./walletkit/src/main/jniLibs/arm64-v8a/libwalletkit.so \
  --library \
  --language kotlin \
  --no-format \
  --out-dir walletkit/src/main/java

echo "✅ Build complete!"
