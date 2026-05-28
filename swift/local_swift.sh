#!/bin/bash
set -e

# Creates a Swift package of the `WalletKit` library for local development.
# This script builds the library and sets up the proper structure for importing
# via Swift Package Manager using a local file:// URL.
# All artifacts are placed in swift/local_build to keep the repo clean.

PROJECT_ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_PATH="$PROJECT_ROOT_PATH/swift" # The base path for the Swift build
LOCAL_BUILD_PATH="$BASE_PATH/local_build/walletkit-swift" # Local build artifacts directory
FRAMEWORK="WalletKit.xcframework"

echo "Building $FRAMEWORK for local iOS development"

# Clean up previous builds
rm -rf "$LOCAL_BUILD_PATH"

# Create the local build directory
mkdir -p "$LOCAL_BUILD_PATH"

echo "Running core Swift build..."

# Call the main build script with local build directory
bash "$BASE_PATH/build_swift.sh" "$LOCAL_BUILD_PATH"

echo "Creating Package.swift for local development..."

awk -v path="$FRAMEWORK" '
/<binary_target>/ {
    print "        .binaryTarget("
    print "            name: \"walletkit_coreFFI\","
    print "            path: \"" path "\""
    print "        )"
    next
}
{ print }
' "$BASE_PATH/Package.swift.template" > "$LOCAL_BUILD_PATH/Package.swift"

echo ""
echo "✅ Swift package built successfully!"
echo ""
echo "📦 Package location: $LOCAL_BUILD_PATH"
echo ""
echo "To use this package in your iOS app:"
echo "1. In Xcode, go to File → Add Package Dependencies..."
echo "2. Click 'Add Local...' and select the local_build directory: $LOCAL_BUILD_PATH"
echo "3. Or add it to your Package.swift dependencies:"
echo "   .package(path: \"$LOCAL_BUILD_PATH\")"
echo ""
echo "The package exports the 'WalletKit' library that you can import in your Swift code."
