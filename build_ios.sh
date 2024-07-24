#!/bin/bash
rm -rf ios_build
rm -rf WalletKit.xcframework
mkdir ios_build
mkdir ios_build/bindings
mkdir -p ios_build/target/universal-ios-sim/release
mkdir -p ./Sources/Oxide


export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"
cargo build --package walletkit --target aarch64-apple-ios-sim --release
cargo build --package walletkit --target aarch64-apple-ios --release
cargo build --package walletkit --target x86_64-apple-ios --release


lipo -create target/aarch64-apple-ios-sim/release/libwalletkit.a \
  target/x86_64-apple-ios/release/libwalletkit.a \
  -output ./ios_build/target/universal-ios-sim/release/libwalletkit.a

cargo run -p uniffi-bindgen generate \
  target/aarch64-apple-ios-sim/release/libwalletkit.dylib \
  --library \
  --language swift \
  --no-format \
  --out-dir ios_build/bindings

mv ./ios_build/bindings/walletkit.swift ./Sources/Oxide/

mkdir ios_build/Headers
mv ./ios_build/bindings/walletkitFFI.h ./ios_build/Headers/

cat ./ios_build/bindings/walletkitFFI.modulemap > ./ios_build/Headers/module.modulemap

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libwalletkit.a \
  -headers ./ios_build/Headers \
  -library ./ios_build/target/universal-ios-sim/release/libwalletkit.a \
  -headers ./ios_build/Headers \
  -output ./WalletKit.xcframework

rm -rf ios_build