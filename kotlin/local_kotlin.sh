#!/bin/bash
set -e

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

# Build using kotlin/build_kotlin.sh inside the Nix android shell
# (via Docker if Nix isn't installed; see nix/README.md).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building WalletKit SDK..."
if command -v nix >/dev/null 2>&1; then
    (cd .. && nix develop .#android --command ./kotlin/build_kotlin.sh)
elif command -v docker >/dev/null 2>&1; then
    ../nix/docker.sh android ./kotlin/build_kotlin.sh
else
    echo "Error: need Nix or Docker to build (see nix/README.md)"
    exit 1
fi

# Publish to Maven Local
echo "Publishing to Maven Local..."
./gradlew :walletkit:publishToMavenLocal -PversionName="$VERSION"

echo ""
echo "✅ Successfully published $VERSION to Maven Local!"
echo "Published to: ~/.m2/repository/org/world/walletkit/$VERSION/"
echo ""
echo "To use in your project:"
echo "  implementation 'org.world:walletkit:$VERSION'"
