#!/bin/bash
set -e

echo "========================================="
echo "Running Swift Tests"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if iOS Simulator SDK is installed
if ! xcodebuild -showsdks | grep -q 'iphonesimulator'; then
  echo -e "${RED}✗ No iOS Simulator SDK installed${NC}"
  echo "Available SDKs:"
  xcodebuild -showsdks || true
  exit 1
fi

# Base paths
BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_PATH="$BASE_PATH/tests"
SOURCES_PATH_NAME="/Sources/WalletKit/"

echo -e "${BLUE}🔨 Step 1: Building Swift bindings${NC}"
# Run the build_swift.sh script
bash "$BASE_PATH/build_swift.sh"

# Check if the XCFramework was created
if [ ! -d "$BASE_PATH/WalletKit.xcframework" ]; then
    echo -e "${RED}✗ Failed to build XCFramework${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Swift bindings built${NC}"

echo -e "${BLUE}📦 Step 2: Copying generated Swift files to test package${NC}"
# Ensure the destination directory exists
mkdir -p "$TESTS_PATH/$SOURCES_PATH_NAME"

# Copy the generated Swift file to the test package
if [ -f "$BASE_PATH/$SOURCES_PATH_NAME/walletkit_core.swift" ]; then
    cp "$BASE_PATH/$SOURCES_PATH_NAME/walletkit_core.swift" "$TESTS_PATH/$SOURCES_PATH_NAME"
    echo -e "${GREEN}✅ Swift bindings copied to test package${NC}"
else
    echo -e "${RED}✗ Could not find generated Swift bindings at: $BASE_PATH/$SOURCES_PATH_NAME/walletkit_core.swift${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}🧪 Running Swift tests with verbose output...${NC}"
echo ""

# Clean any previous build artifacts
rm -rf .build
rm -rf ~/Library/Developer/Xcode/DerivedData/WalletKitTestPackage-*

# Find an available iPhone simulator
SIMULATOR_ID=$(xcrun simctl list devices available | grep "iPhone 16" | head -1 | grep -o "[0-9A-F\-]*" | tail -1)

if [ -z "$SIMULATOR_ID" ]; then
    # Try any available iPhone
    SIMULATOR_ID=$(xcrun simctl list devices available | grep "iPhone" | head -1 | grep -o "[0-9A-F\-]*" | tail -1)
fi

if [ -z "$SIMULATOR_ID" ]; then
    echo -e "${RED}✗ No iPhone simulator available${NC}"
    exit 1
fi

# Simulator hygiene: clear residual state in CI
if [ "${GITHUB_ACTIONS:-false}" = "true" ] || [ "${CI:-false}" = "true" ]; then
    echo "🧹 Running simulator hygiene (CI environment detected)..."
    xcrun simctl shutdown "$SIMULATOR_ID" >/dev/null 2>&1 || true
    xcrun simctl erase    "$SIMULATOR_ID"
    xcrun simctl boot     "$SIMULATOR_ID"
    xcrun simctl bootstatus "$SIMULATOR_ID" -b
else
    echo "💻 Local environment detected - skipping simulator hygiene"
fi

echo "📱 Using simulator ID: $SIMULATOR_ID"

cd "$TESTS_PATH"

# Run tests using xcodebuild for iOS simulator
echo "🚀 Running tests on iOS Simulator..."
xcodebuild test \
  -scheme WalletKitTestPackage \
  -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
  -sdk iphonesimulator \
  CODE_SIGNING_ALLOWED=NO \
  2>&1 | tee test_output.log

echo ""
echo "📊 Test Results Summary:"
echo "========================"

# Parse test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

if [ -f test_output.log ]; then
    echo "✅ Test results found in: test_output.log"
    
    TOTAL_TESTS=$(grep -c "Test Case.*started" test_output.log 2>/dev/null || echo "0")
    TOTAL_TESTS=${TOTAL_TESTS%%[^0-9]*}
    TOTAL_TESTS=${TOTAL_TESTS:-0}
    
    PASSED_TESTS=$(grep -c "Test Case.*passed" test_output.log 2>/dev/null || echo "0")
    PASSED_TESTS=${PASSED_TESTS%%[^0-9]*}
    PASSED_TESTS=${PASSED_TESTS:-0}
    
    FAILED_TESTS=$(grep -c "Test Case.*failed" test_output.log 2>/dev/null || echo "0")
    FAILED_TESTS=${FAILED_TESTS%%[^0-9]*}
    FAILED_TESTS=${FAILED_TESTS:-0}
    
    echo "📋 Total test cases: $TOTAL_TESTS"
    echo "✅ Tests passed: $PASSED_TESTS"
    echo "❌ Tests failed: $FAILED_TESTS"
else
    echo "⚠️  No test results found"
fi

# Check if tests passed
if grep -q "failed" test_output.log; then
    echo ""
    echo -e "${YELLOW}⚠️ Some tests failed${NC}"
    echo "Failed test details:"
    grep -E "(failed|error:)" test_output.log || true
    rm -f test_output.log
    exit 1
elif grep -q "Test Suite.*passed" test_output.log; then
    echo ""
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    rm -f test_output.log
    exit 0
else
    echo ""
    echo -e "${RED}✗ Could not determine test results${NC}"
    echo "Full output:"
    cat test_output.log
    rm -f test_output.log
    exit 1
fi
