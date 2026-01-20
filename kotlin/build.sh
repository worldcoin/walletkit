#!/bin/bash
set -e

echo "Building WalletKit Android SDK..."

# Create jniLibs directories
mkdir -p ./lib/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

# Build for all Android architectures
echo "Building for aarch64-linux-android..."
cross build -p walletkit --release --target=aarch64-linux-android --features v4

echo "Building for armv7-linux-androideabi..."
cross build -p walletkit --release --target=armv7-linux-androideabi --features v4

echo "Building for x86_64-linux-android..."
cross build -p walletkit --release --target=x86_64-linux-android --features v4

echo "Building for i686-linux-android..."
cross build -p walletkit --release --target=i686-linux-android --features v4

# Move .so files to jniLibs
echo "Moving native libraries..."
mv ../target/aarch64-linux-android/release/libwalletkit.so ./lib/src/main/jniLibs/arm64-v8a/libwalletkit.so
mv ../target/armv7-linux-androideabi/release/libwalletkit.so ./lib/src/main/jniLibs/armeabi-v7a/libwalletkit.so
mv ../target/x86_64-linux-android/release/libwalletkit.so ./lib/src/main/jniLibs/x86_64/libwalletkit.so
mv ../target/i686-linux-android/release/libwalletkit.so ./lib/src/main/jniLibs/x86/libwalletkit.so

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
cargo run -p uniffi-bindgen generate \
  ./lib/src/main/jniLibs/arm64-v8a/libwalletkit.so \
  --library \
  --language kotlin \
  --no-format \
  --out-dir lib/src/main/java

echo "✅ Build complete!"
