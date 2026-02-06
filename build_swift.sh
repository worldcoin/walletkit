#!/bin/bash
set -e

# Creates a Swift build of the `WalletKit` library.
# This script is intended to be run in a GitHub Actions workflow.
# When a release is created, the output is committed to the github.com/worldcoin/walletkit-swift repo.

echo "Building WalletKit.xcframework"

BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -rf $BASE_PATH/ios_build
rm -rf $BASE_PATH/WalletKit.xcframework
mkdir -p $BASE_PATH/ios_build/bindings
mkdir -p $BASE_PATH/ios_build/target/universal-ios-sim/release
mkdir -p $BASE_PATH/Sources/WalletKit


export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"
cargo build --package walletkit --target aarch64-apple-ios-sim --release --no-default-features --features v4
cargo build --package walletkit --target aarch64-apple-ios --release --no-default-features --features v4
cargo build --package walletkit --target x86_64-apple-ios --release --no-default-features --features v4

echo "Rust packages built. Combining into a single binary."

lipo -create target/aarch64-apple-ios-sim/release/libwalletkit.a \
  target/x86_64-apple-ios/release/libwalletkit.a \
  -output $BASE_PATH/ios_build/target/universal-ios-sim/release/libwalletkit.a

lipo -info $BASE_PATH/ios_build/target/universal-ios-sim/release/libwalletkit.a

echo "Generating Swift bindings."

cargo run -p uniffi-bindgen generate \
  target/aarch64-apple-ios-sim/release/libwalletkit.dylib \
  --library \
  --language swift \
  --no-format \
  --out-dir $BASE_PATH/ios_build/bindings

mv $BASE_PATH/ios_build/bindings/walletkit.swift $BASE_PATH/Sources/WalletKit/
mv $BASE_PATH/ios_build/bindings/walletkit_core.swift $BASE_PATH/Sources/WalletKit/

mkdir $BASE_PATH/ios_build/Headers
mkdir -p $BASE_PATH/ios_build/Headers/WalletKit

mv $BASE_PATH/ios_build/bindings/walletkitFFI.h $BASE_PATH/ios_build/Headers/WalletKit
mv $BASE_PATH/ios_build/bindings/walletkit_coreFFI.h $BASE_PATH/ios_build/Headers/WalletKit

# Combine both modulemaps into one
cat $BASE_PATH/ios_build/bindings/walletkitFFI.modulemap > $BASE_PATH/ios_build/Headers/WalletKit/module.modulemap
echo "" >> $BASE_PATH/ios_build/Headers/WalletKit/module.modulemap
cat $BASE_PATH/ios_build/bindings/walletkit_coreFFI.modulemap >> $BASE_PATH/ios_build/Headers/WalletKit/module.modulemap

echo "Creating xcframework."

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libwalletkit.a -headers $BASE_PATH/ios_build/Headers \
  -library $BASE_PATH/ios_build/target/universal-ios-sim/release/libwalletkit.a -headers $BASE_PATH/ios_build/Headers \
  -output $BASE_PATH/WalletKit.xcframework

rm -rf $BASE_PATH/ios_build
