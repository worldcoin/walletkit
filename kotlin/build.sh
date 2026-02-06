#!/bin/bash
set -e

echo "Building WalletKit Android SDK..."

# Create jniLibs directories
mkdir -p ./walletkit/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

# NOTE: cross mounts the repo at /project inside the container
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BASE="/project/third-party-libs/openssl-android"
export PKG_CONFIG_ALLOW_CROSS=1

# Preflight checks (fail fast)
if [ ! -f "$REPO_ROOT/circom/OPRFQuery.arks.zkey" ]; then
  echo "Missing circom artifacts. Expected at $REPO_ROOT/circom/OPRFQuery.arks.zkey"
  exit 1
fi

if [ ! -f "$REPO_ROOT/third-party-libs/openssl-android/arm64-v8a/include/openssl/crypto.h" ]; then
  echo "Missing OpenSSL headers. Expected at $REPO_ROOT/third-party-libs/openssl-android/arm64-v8a/include/openssl/crypto.h"
  exit 1
fi

# Build for all Android architectures
echo "Building for aarch64-linux-android..."
export OPENSSL_DIR="$OPENSSL_BASE/arm64-v8a"
export OPENSSL_INCLUDE_DIR="$OPENSSL_BASE/arm64-v8a/include"
export OPENSSL_LIB_DIR="$OPENSSL_BASE/arm64-v8a/lib"
export C_INCLUDE_PATH="$OPENSSL_BASE/arm64-v8a/include"
export CPATH="$OPENSSL_BASE/arm64-v8a/include"
export CFLAGS_aarch64_linux_android="-I$OPENSSL_BASE/arm64-v8a/include"
export CC_aarch64_linux_android="aarch64-linux-android21-clang"
export CROSS_CONTAINER_OPTS="-v $REPO_ROOT/third-party-libs:/project/third-party-libs:ro -v $REPO_ROOT/circom:/project/circom:ro"
cross build -p walletkit --release --target=aarch64-linux-android --no-default-features --features v4

echo "Building for armv7-linux-androideabi..."
export OPENSSL_DIR="$OPENSSL_BASE/armeabi-v7a"
export OPENSSL_INCLUDE_DIR="$OPENSSL_BASE/armeabi-v7a/include"
export OPENSSL_LIB_DIR="$OPENSSL_BASE/armeabi-v7a/lib"
export C_INCLUDE_PATH="$OPENSSL_BASE/armeabi-v7a/include"
export CPATH="$OPENSSL_BASE/armeabi-v7a/include"
export CFLAGS_armv7_linux_androideabi="-I$OPENSSL_BASE/armeabi-v7a/include"
export CC_armv7_linux_androideabi="armv7a-linux-androideabi21-clang"
export CROSS_CONTAINER_OPTS="-v $REPO_ROOT/third-party-libs:/project/third-party-libs:ro -v $REPO_ROOT/circom:/project/circom:ro"
cross build -p walletkit --release --target=armv7-linux-androideabi --no-default-features --features v4

echo "Building for x86_64-linux-android..."
export OPENSSL_DIR="$OPENSSL_BASE/x86_64"
export OPENSSL_INCLUDE_DIR="$OPENSSL_BASE/x86_64/include"
export OPENSSL_LIB_DIR="$OPENSSL_BASE/x86_64/lib"
export C_INCLUDE_PATH="$OPENSSL_BASE/x86_64/include"
export CPATH="$OPENSSL_BASE/x86_64/include"
export CFLAGS_x86_64_linux_android="-I$OPENSSL_BASE/x86_64/include"
export CC_x86_64_linux_android="x86_64-linux-android21-clang"
export CROSS_CONTAINER_OPTS="-v $REPO_ROOT/third-party-libs:/project/third-party-libs:ro -v $REPO_ROOT/circom:/project/circom:ro"
cross build -p walletkit --release --target=x86_64-linux-android --no-default-features --features v4

echo "Building for i686-linux-android..."
export OPENSSL_DIR="$OPENSSL_BASE/x86"
export OPENSSL_INCLUDE_DIR="$OPENSSL_BASE/x86/include"
export OPENSSL_LIB_DIR="$OPENSSL_BASE/x86/lib"
export C_INCLUDE_PATH="$OPENSSL_BASE/x86/include"
export CPATH="$OPENSSL_BASE/x86/include"
export CFLAGS_i686_linux_android="-I$OPENSSL_BASE/x86/include"
export CC_i686_linux_android="i686-linux-android21-clang"
export CROSS_CONTAINER_OPTS="-v $REPO_ROOT/third-party-libs:/project/third-party-libs:ro -v $REPO_ROOT/circom:/project/circom:ro"
cross build -p walletkit --release --target=i686-linux-android --no-default-features --features v4

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
