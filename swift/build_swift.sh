#!/bin/bash
set -e

# Creates a Swift build of the `WalletKit` library.
# This script can be used directly or called by other scripts.
#
# Usage: build_swift.sh [OUTPUT_DIR]
#   OUTPUT_DIR: Directory where the XCFramework should be placed (default: swift/)

PROJECT_ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_PATH="$PROJECT_ROOT_PATH/swift"
PACKAGE_NAME="walletkit"

# Default values
OUTPUT_DIR="$BASE_PATH"
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

cd "$PROJECT_ROOT_PATH"

export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"

# Build for all iOS targets with platform-ios feature enabled
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios-sim --release --features platform-ios
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios --release --features platform-ios
cargo build --package $PACKAGE_NAME --target x86_64-apple-ios --release --features platform-ios

echo "Rust packages built. Combining simulator targets into universal binary..."

# Create universal binary for simulators
lipo -create target/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.a \
  target/x86_64-apple-ios/release/lib${PACKAGE_NAME}.a \
  -output $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

lipo -info $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

echo "Generating Swift bindings..."

# Generate Swift bindings using uniffi
cargo run -p uniffi-bindgen generate \
  target/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.dylib \
  --library \
  --language swift \
  --no-format \
  --out-dir $BASE_PATH/ios_build/bindings

# Move generated Swift file to Sources directory
mv $BASE_PATH/ios_build/bindings/${PACKAGE_NAME}_core.swift ${SWIFT_SOURCES_DIR}/

# Move headers
mv $BASE_PATH/ios_build/bindings/${PACKAGE_NAME}_coreFFI.h $SWIFT_HEADERS_DIR/
cat $BASE_PATH/ios_build/bindings/${PACKAGE_NAME}_coreFFI.modulemap > $SWIFT_HEADERS_DIR/module.modulemap

echo "Creating XCFramework..."

# Create XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/lib${PACKAGE_NAME}.a -headers $BASE_PATH/ios_build/Headers \
  -library $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a -headers $BASE_PATH/ios_build/Headers \
  -output $FRAMEWORK_OUTPUT

# Clean up intermediate build files
rm -rf $BASE_PATH/ios_build

echo "✅ Swift framework built successfully at: $FRAMEWORK_OUTPUT"
