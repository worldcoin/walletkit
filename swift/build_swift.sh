#!/bin/bash
set -e

echo "Building WalletKitCore.xcframework"

rm -rf ios_build
rm -rf WalletKitCore.xcframework
mkdir ios_build
mkdir ios_build/bindings
mkdir -p ios_build/target/universal-ios-sim/release
mkdir -p ./Sources/WalletKitCore


export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"
cargo build --package walletkit-core --target aarch64-apple-ios-sim --release
cargo build --package walletkit-core --target aarch64-apple-ios --release
cargo build --package walletkit-core --target x86_64-apple-ios --release

echo "Rust packages built. Combining into a single binary."

lipo -create target/aarch64-apple-ios-sim/release/libwalletkit_core.a \
  target/x86_64-apple-ios/release/libwalletkit_core.a \
  -output ./ios_build/target/universal-ios-sim/release/libwalletkit_core.a

echo "Generating Swift bindings."

cargo run -p uniffi-bindgen generate \
  target/aarch64-apple-ios-sim/release/libwalletkit_core.dylib \
  --library \
  --language swift \
  --no-format \
  --out-dir ios_build/bindings

mv ./ios_build/bindings/walletkit_core.swift ./Sources/WalletKitCore/

mkdir ios_build/Headers
mv ./ios_build/bindings/walletkit_coreFFI.h ./ios_build/Headers/

cat ./ios_build/bindings/walletkit_coreFFI.modulemap > ./ios_build/Headers/module.modulemap

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libwalletkit_core.a \
  -headers ./ios_build/Headers \
  -library ./ios_build/target/universal-ios-sim/release/libwalletkit_core.a \
  -headers ./ios_build/Headers \
  -output ./WalletKitCore.xcframework

rm -rf ios_build
