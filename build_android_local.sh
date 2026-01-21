#!/usr/bin/env bash
set -euo pipefail

echo "Building WalletKit Android SDK for local development..."

PROJECT_ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTLIN_DIR="$PROJECT_ROOT_PATH/kotlin"

# Set rustup and cargo home to /tmp to prevent Docker permission issues
export RUSTUP_HOME="${RUSTUP_HOME:-/tmp/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/tmp/.cargo}"

# Version is required
if [ $# -lt 1 ]; then
    echo "Error: Version parameter is required"
    echo "Usage: ./build_android_local.sh <version>"
    echo "Example: ./build_android_local.sh 0.2.1-SNAPSHOT"
    exit 1
fi

VERSION="$1"
echo "Using version: $VERSION"

echo "🟢 Building WalletKit Android SDK (cross + UniFFI)..."
(cd "$KOTLIN_DIR" && ./build.sh)

echo "🟡 Publishing to Maven Local..."
(cd "$KOTLIN_DIR" && ./gradlew :lib:publishToMavenLocal -PversionName="$VERSION")

echo ""
echo "✅ Successfully published $VERSION to Maven Local!"
echo "Published to: ~/.m2/repository/org/world/walletkit-android/$VERSION/"
echo ""
echo "To use in your project:"
echo "  implementation 'org.world:walletkit-android:$VERSION'"
