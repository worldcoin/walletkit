#!/bin/bash
set -e

# Creates the dynamic Package.swift file for release.
# Usage: ./archive_swift.sh --asset-url <URL> --checksum <CHECKSUM> --release-version <VERSION>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Initialize variables
ASSET_URL=""
CHECKSUM=""
RELEASE_VERSION=""

# Function to show usage
show_usage() {
    echo "❌ Error: Missing required arguments"
    echo "Usage: $0 --asset-url <URL> --checksum <CHECKSUM> --release-version <VERSION>"
    echo ""
    echo "Example:"
    echo "  $0 --asset-url 'https://github.com/user/repo/releases/download/v1.0.0/WalletKit.xcframework.zip' --checksum 'abc123def456...' --release-version '1.0.0'"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --asset-url)
            ASSET_URL="$2"
            shift 2
            ;;
        --checksum)
            CHECKSUM="$2"
            shift 2
            ;;
        --release-version)
            RELEASE_VERSION="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "❌ Unknown argument: $1"
            show_usage
            ;;
    esac
done

# Check if all required arguments are provided
if [ -z "$ASSET_URL" ] || [ -z "$CHECKSUM" ] || [ -z "$RELEASE_VERSION" ]; then
    echo "❌ Error: All arguments are required"
    show_usage
fi

echo "🔧 Creating Package.swift with:"
echo "   Asset URL: $ASSET_URL"
echo "   Checksum: $CHECKSUM"
echo "   Release Version: $RELEASE_VERSION"
echo ""

awk -v url="$ASSET_URL" -v checksum="$CHECKSUM" '
/<binary_target>/ {
    print "        .binaryTarget("
    print "            name: \"walletkit_coreFFI\","
    print "            url: \"" url "\","
    print "            checksum: \"" checksum "\""
    print "        )"
    next
}
{ print }
' "$SCRIPT_DIR/Package.swift.template" > Package.swift

echo "// Release version: $RELEASE_VERSION" >> Package.swift

swiftlint lint --autocorrect Package.swift

echo ""
echo "✅ Package.swift built successfully for version $RELEASE_VERSION!"
