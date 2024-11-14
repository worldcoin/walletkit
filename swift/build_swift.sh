#!/bin/bash
set -e

echo "Building WalletKitCore.xcframework"

BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -rf $BASE_PATH/ios_build
rm -rf $BASE_PATH/WalletKitCore.xcframework
mkdir -p $BASE_PATH/ios_build/bindings
mkdir -p $BASE_PATH/ios_build/target/universal-ios-sim/release
mkdir -p $BASE_PATH/Sources/WalletKitCore


export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"
cargo build --package walletkit-core --target aarch64-apple-ios-sim --release
cargo build --package walletkit-core --target aarch64-apple-ios --release
cargo build --package walletkit-core --target x86_64-apple-ios --release

echo "Rust packages built. Combining into a single binary."

lipo -create target/aarch64-apple-ios-sim/release/libwalletkit_core.a \
  target/x86_64-apple-ios/release/libwalletkit_core.a \
  -output $BASE_PATH/ios_build/target/universal-ios-sim/release/libwalletkit_core.a

lipo -info $BASE_PATH/ios_build/target/universal-ios-sim/release/libwalletkit_core.a

echo "Generating Swift bindings."

cargo run -p uniffi-bindgen generate \
  target/aarch64-apple-ios-sim/release/libwalletkit_core.dylib \
  --library \
  --language swift \
  --no-format \
  --out-dir $BASE_PATH/ios_build/bindings

mv $BASE_PATH/ios_build/bindings/walletkit_core.swift $BASE_PATH/Sources/WalletKitCore/

mkdir $BASE_PATH/ios_build/Headers
mv $BASE_PATH/ios_build/bindings/walletkit_coreFFI.h $BASE_PATH/ios_build/Headers/

# Create a subfolder for the modulemap
mkdir -p $BASE_PATH/ios_build/Headers/WalletKitCore
mv $BASE_PATH/ios_build/Headers/module.modulemap $BASE_PATH/ios_build/Headers/WalletKitCore/module.modulemap

echo "Creating xcframework."

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libwalletkit_core.a -headers $BASE_PATH/ios_build/Headers \
  -library $BASE_PATH/ios_build/target/universal-ios-sim/release/libwalletkit_core.a -headers $BASE_PATH/ios_build/Headers \
  -output $BASE_PATH/WalletKitCore.xcframework

rm -rf $BASE_PATH/ios_build
