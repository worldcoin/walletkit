#!/bin/bash
set -e

# Builds the Swift bindings and runs the foreign-binding test suite locally.
# In CI this is split in two (see .github/workflows/ci.yml): build_swift.sh
# runs once, and run_swift_tests.sh re-runs against that same build across
# an Xcode version matrix, so the expensive Rust cross-compilation isn't
# repeated per Xcode version.

BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\033[0;34m🔨 Step 1: Building Swift bindings\033[0m"
# Must cd to the repository root first because build script expects to run from there
cd "$BASE_PATH/.." && bash ./swift/build_swift.sh

bash "$BASE_PATH/run_swift_tests.sh"
