#!/usr/bin/env bash
set -euo pipefail

# Creates Kotlin/JNA bindings for the `walletkit` library.
# This mirrors the Bedrock Kotlin build flow.

PROJECT_ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KOTLIN_DIR="$PROJECT_ROOT_PATH/kotlin"
JAVA_SRC_DIR="$KOTLIN_DIR/walletkit/src/main/java"
LIBS_DIR="$KOTLIN_DIR/libs"

# Clean previous artifacts
rm -rf "$JAVA_SRC_DIR" "$LIBS_DIR"
mkdir -p "$JAVA_SRC_DIR" "$LIBS_DIR"

echo "🟢 Building Rust cdylib for host platform"
cargo build --package walletkit --release

# Determine the correct library file extension and copy it
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_FILE="$PROJECT_ROOT_PATH/target/release/libwalletkit.dylib"
    cp "$LIB_FILE" "$LIBS_DIR/"
    echo "📦 Copied libwalletkit.dylib for macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_FILE="$PROJECT_ROOT_PATH/target/release/libwalletkit.so"
    cp "$LIB_FILE" "$LIBS_DIR/"
    echo "📦 Copied libwalletkit.so for Linux"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

echo "🟡 Generating Kotlin bindings via uniffi-bindgen"
cargo run -p uniffi-bindgen -- generate \
  "$LIB_FILE" \
  --language kotlin \
  --library \
  --crate walletkit_core \
  --out-dir "$JAVA_SRC_DIR"

echo "✅ Kotlin bindings written to $JAVA_SRC_DIR"
