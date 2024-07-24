#!/bin/bash

mkdir -p ./sdk/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

cross build -p walletkit --release --target=aarch64-linux-android

mv ../target/aarch64-linux-android/release/libwalletkit.so ./sdk/src/main/jniLibs/arm64-v8a/libwalletkit.so

cross build -p walletkit --release --target=armv7-linux-androideabi

mv ../target/armv7-linux-androideabi/release/libwalletkit.so ./sdk/src/main/jniLibs/armeabi-v7a/libwalletkit.so

cross build -p walletkit --release --target=x86_64-linux-android

mv ../target/x86_64-linux-android/release/libwalletkit.so ./sdk/src/main/jniLibs/x86_64/libwalletkit.so

cross build -p walletkit --release --target=i686-linux-android

mv ../target/i686-linux-android/release/libwalletkit.so ./sdk/src/main/jniLibs/x86/libwalletkit.so

cargo run -p uniffi-bindgen generate \
  ./sdk/src/main/jniLibs/arm64-v8a/libwalletkit.so \
  --library \
  --language kotlin \
  --no-format \
  --out-dir sdk/src/main/java