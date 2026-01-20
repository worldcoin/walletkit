#!/bin/bash
set -e

# Convenience wrapper for the Swift build script in ./swift.

BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$BASE_PATH/swift/build_swift.sh" "$@"
