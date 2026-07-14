#!/bin/bash
set -e

# Build the Kotlin bindings and publish them to Maven Local.
# Usage: ./kotlin/local_kotlin.sh <version>
# See nix/README.md for build environment setup.

echo "Building WalletKit Android SDK for local development..."

# Version is required
if [ -z "$1" ]; then
    echo "Error: Version parameter is required"
    echo "Usage: ./local_kotlin.sh <version>"
    echo "Example: ./local_kotlin.sh 0.2.1"
    exit 1
fi

VERSION="$1"
echo "Using version: $VERSION"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building WalletKit SDK..."
./build_kotlin.sh

# Publish to Maven Local
echo "Publishing to Maven Local..."
./gradlew :walletkit:publishToMavenLocal -PversionName="$VERSION"

echo ""
echo "✅ Successfully published $VERSION to Maven Local!"
echo "Published to: ~/.m2/repository/org/world/walletkit/$VERSION/"
echo ""
echo "To use in your project:"
echo "  implementation 'org.world:walletkit:$VERSION'"
