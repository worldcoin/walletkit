#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo "Running Kotlin/JVM Tests"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TEST_RESULTS_DIR="$ROOT_DIR/kotlin/walletkit-tests/build/test-results/test"
rm -rf "$TEST_RESULTS_DIR"

cd "$ROOT_DIR"

# Set JAVA_HOME if not already set (for CI environments)
if [ -z "${JAVA_HOME:-}" ]; then
  if [ -d "/opt/homebrew/Cellar/openjdk@17" ]; then
    # macOS with Homebrew - find latest 17.x version
    LATEST_JDK=$(ls -v /opt/homebrew/Cellar/openjdk@17 | grep "^17\." | tail -n 1)
    if [ -n "$LATEST_JDK" ]; then
      export JAVA_HOME="/opt/homebrew/Cellar/openjdk@17/$LATEST_JDK/libexec/openjdk.jdk/Contents/Home"
      echo -e "${BLUE}🔧 Set JAVA_HOME to: $JAVA_HOME${NC}"
    else
      echo -e "${YELLOW}⚠️  No OpenJDK 17.x found in Homebrew${NC}"
    fi
  elif command -v java >/dev/null 2>&1; then
    JAVA_PATH=$(which java)
    export JAVA_HOME=$(dirname $(dirname $(readlink -f $JAVA_PATH)))
    echo -e "${BLUE}🔧 Detected JAVA_HOME: $JAVA_HOME${NC}"
  else
    echo -e "${YELLOW}⚠️  JAVA_HOME not set and Java not found in PATH${NC}"
  fi
fi

echo -e "${BLUE}🔨 Step 1: Building Kotlin bindings with build_kotlin.sh${NC}"
"$ROOT_DIR/kotlin/build_kotlin.sh"

echo -e "${GREEN}✅ Kotlin bindings built${NC}"

echo -e "${BLUE}📦 Step 2: Setting up Gradle test environment${NC}"
cd "$ROOT_DIR/kotlin"

# Generate Gradle wrapper if missing
if [ ! -f "gradlew" ]; then
  echo "Gradle wrapper missing, generating..."
  GRADLE_VERSION="${GRADLE_VERSION:-8.14.3}"
  DIST_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
  TMP_DIR="$(mktemp -d)"
  ZIP_PATH="$TMP_DIR/gradle-${GRADLE_VERSION}.zip"
  UNZIP_DIR="$TMP_DIR/unzip"

  echo "Downloading Gradle ${GRADLE_VERSION}..."
  curl -sSL "$DIST_URL" -o "$ZIP_PATH"
  mkdir -p "$UNZIP_DIR"
  if command -v unzip >/dev/null 2>&1; then
    unzip -q "$ZIP_PATH" -d "$UNZIP_DIR"
  else
    (cd "$UNZIP_DIR" && jar xvf "$ZIP_PATH" >/dev/null)
  fi

  echo "Bootstrapping wrapper with Gradle ${GRADLE_VERSION}..."
  "$UNZIP_DIR/gradle-${GRADLE_VERSION}/bin/gradle" wrapper --gradle-version "$GRADLE_VERSION"

  rm -rf "$TMP_DIR"
fi
echo -e "${GREEN}✅ Gradle test environment ready${NC}"

echo ""
echo -e "${BLUE}🧪 Step 3: Running Kotlin tests with verbose output...${NC}"
echo ""

./gradlew --no-daemon walletkit-tests:test --info --continue

echo ""
echo "📊 Test Results Summary:"
echo "========================"

if [ -d "$TEST_RESULTS_DIR" ]; then
  echo "✅ Test results found in: $TEST_RESULTS_DIR"
  TOTAL_TESTS=$(find "$TEST_RESULTS_DIR" -name "*.xml" -exec grep -l "testcase" {} \; | wc -l | tr -d ' ')
  if [ "$TOTAL_TESTS" -gt 0 ]; then
    echo "📋 Total test files: $TOTAL_TESTS"
    PASSED=$(find "$TEST_RESULTS_DIR" -name "*.xml" -exec grep -o "tests=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    FAILURES=$(find "$TEST_RESULTS_DIR" -name "*.xml" -exec grep -o "failures=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    ERRORS=$(find "$TEST_RESULTS_DIR" -name "*.xml" -exec grep -o "errors=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')

    echo "✅ Tests passed: $PASSED"
    echo "❌ Tests failed: $FAILURES"
    echo "⚠️  Test errors: $ERRORS"

    if [ "$FAILURES" -gt 0 ] || [ "$ERRORS" -gt 0 ]; then
      echo ""
      echo -e "${YELLOW}⚠️ Some tests failed${NC}"
      exit 1
    else
      echo ""
      echo -e "${GREEN}🎉 All tests passed!${NC}"
      exit 0
    fi
  fi
else
  echo "⚠️  No test results found"
  echo ""
  echo -e "${RED}✗ Could not determine test results${NC}"
  exit 1
fi
