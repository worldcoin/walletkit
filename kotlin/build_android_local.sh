#!/bin/bash
set -e

echo "Building WalletKit Android SDK for local development..."

# Set rustup and cargo home to /tmp to prevent Docker permission issues
export RUSTUP_HOME="${RUSTUP_HOME:-/tmp/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/tmp/.cargo}"

# Version is required
if [ -z "$1" ]; then
    echo "Error: Version parameter is required"
    echo "Usage: ./build_android_local.sh <version>"
    echo "Example: ./build_android_local.sh 0.2.1-SNAPSHOT"
    exit 1
fi

VERSION="$1"
echo "Using version: $VERSION"

# Build using kotlin/build.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building WalletKit SDK..."
./build.sh

# Publish to Maven Local
echo "Publishing to Maven Local..."
./gradlew :walletkit:publishToMavenLocal -PversionName="$VERSION"

echo ""
echo "✅ Successfully published $VERSION to Maven Local!"
echo "Published to: ~/.m2/repository/org/world/walletkit/$VERSION/"
echo ""
echo "To use in your project:"
echo "  implementation 'org.world:walletkit:$VERSION'"
