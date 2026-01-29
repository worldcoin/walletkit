#!/bin/bash
set -e

# Creates a Swift build of the `WalletKit` library.
# This script can be used directly or called by other scripts.
#
# Usage: build_swift.sh [OUTPUT_DIR]
#   OUTPUT_DIR: Directory where the XCFramework should be placed (default: swift/)

PROJECT_ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_PATH="$PROJECT_ROOT_PATH/swift" # The base path for the Swift build
PACKAGE_NAME="walletkit"
TARGET_DIR="$PROJECT_ROOT_PATH/target"
FEATURES="v4"
SUPPORT_SOURCES_DIR="$BASE_PATH/support"

# Default values
OUTPUT_DIR="$BASE_PATH" # Default to BASE_PATH if not provided
FRAMEWORK="WalletKit.xcframework"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Usage: $0 [OUTPUT_DIR]"
            echo ""
            echo "Arguments:"
            echo "  OUTPUT_DIR    Directory where the XCFramework should be placed (default: swift/)"
            echo ""
            exit 0
            ;;
        *)
            # Assume it's the output directory if it doesn't start with --
            if [[ ! "$1" =~ ^-- ]]; then
                OUTPUT_DIR="$1"
            else
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
            fi
            shift
            ;;
    esac
done

# Resolve OUTPUT_DIR to absolute path if it's relative
if [[ "$OUTPUT_DIR" != /* ]]; then
    OUTPUT_DIR="$BASE_PATH/$OUTPUT_DIR"
fi

SWIFT_SOURCES_DIR="$OUTPUT_DIR/Sources/WalletKit"
SWIFT_HEADERS_DIR="$BASE_PATH/ios_build/Headers/WalletKit"
FRAMEWORK_OUTPUT="$OUTPUT_DIR/$FRAMEWORK"

echo "Building $FRAMEWORK to $FRAMEWORK_OUTPUT"

# Clean up previous builds
rm -rf "$BASE_PATH/ios_build"
rm -rf "$FRAMEWORK_OUTPUT"

# Create necessary directories
mkdir -p "$BASE_PATH/ios_build/bindings"
mkdir -p "$BASE_PATH/ios_build/target/universal-ios-sim/release"
mkdir -p "$SWIFT_SOURCES_DIR"
mkdir -p "$SWIFT_HEADERS_DIR"

echo "Building Rust packages for iOS targets..."

export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension \
                  -C link-arg=-Wl,-dead_strip \
                  -C link-arg=-Wl,-dead_strip_dylibs \
                  -C embed-bitcode=no"

# Build for all iOS targets
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios-sim --release \
  --manifest-path "$PROJECT_ROOT_PATH/Cargo.toml" --target-dir "$TARGET_DIR" \
  --features "$FEATURES"
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios --release \
  --manifest-path "$PROJECT_ROOT_PATH/Cargo.toml" --target-dir "$TARGET_DIR" \
  --features "$FEATURES"
cargo build --package $PACKAGE_NAME --target x86_64-apple-ios --release \
  --manifest-path "$PROJECT_ROOT_PATH/Cargo.toml" --target-dir "$TARGET_DIR" \
  --features "$FEATURES"

strip -S -x $TARGET_DIR/aarch64-apple-ios/release/lib$PACKAGE_NAME.a
strip -S -x $TARGET_DIR/x86_64-apple-ios/release/lib$PACKAGE_NAME.a
strip -S -x $TARGET_DIR/aarch64-apple-ios-sim/release/lib$PACKAGE_NAME.dylib

echo "Rust packages built. Combining simulator targets into universal binary..."

# Create universal binary for simulators
lipo -create "$TARGET_DIR/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.a" \
  "$TARGET_DIR/x86_64-apple-ios/release/lib${PACKAGE_NAME}.a" \
  -output $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

lipo -info $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

echo "Generating Swift bindings..."

# Generate Swift bindings using uniffi
cargo run -p uniffi-bindgen --manifest-path "$PROJECT_ROOT_PATH/Cargo.toml" \
  --target-dir "$TARGET_DIR" -- generate \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.dylib" \
  --library \
  --crate walletkit_core \
  --language swift \
  --no-format \
  --out-dir $BASE_PATH/ios_build/bindings

# Move generated Swift file to Sources directory
mv $BASE_PATH/ios_build/bindings/walletkit_core.swift ${SWIFT_SOURCES_DIR}/walletkit.swift

# Copy support Swift sources for the WalletKit module.
if [ -d "$SUPPORT_SOURCES_DIR" ]; then
    rsync -a "$SUPPORT_SOURCES_DIR"/ "$SWIFT_SOURCES_DIR"/
fi

# Move headers
mv $BASE_PATH/ios_build/bindings/walletkit_coreFFI.h $SWIFT_HEADERS_DIR/
cat $BASE_PATH/ios_build/bindings/walletkit_coreFFI.modulemap > $SWIFT_HEADERS_DIR/module.modulemap

echo "Creating XCFramework..."

# Create XCFramework
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/lib${PACKAGE_NAME}.a" -headers $BASE_PATH/ios_build/Headers \
  -library $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a -headers $BASE_PATH/ios_build/Headers \
  -output $FRAMEWORK_OUTPUT

# Clean up intermediate build files
rm -rf $BASE_PATH/ios_build

echo "✅ Swift framework built successfully at: $FRAMEWORK_OUTPUT"
