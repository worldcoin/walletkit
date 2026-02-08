#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Setting up Android build deps (circom + OpenSSL)"
echo

echo "Expected paths:"
echo "  - $REPO_ROOT/circom"
echo "  - $REPO_ROOT/third-party-libs/openssl-android"
echo

CIRCOM_DIR="$REPO_ROOT/circom"
OPENSSL_DIR="$REPO_ROOT/third-party-libs/openssl-android"

# Circom artifacts (download if missing)
if [ ! -f "$CIRCOM_DIR/OPRFQuery.arks.zkey" ]; then
  echo "Circom artifacts missing; downloading from world-id-protocol..."
  mkdir -p "$CIRCOM_DIR"
  BASE_URL="https://raw.githubusercontent.com/worldcoin/world-id-protocol/cebbe92ba48fac9dd5f60c3f9272a2b82f075ecc/circom"
  curl -fsSL "$BASE_URL/OPRFQuery.arks.zkey" -o "$CIRCOM_DIR/OPRFQuery.arks.zkey"
  curl -fsSL "$BASE_URL/OPRFNullifier.arks.zkey" -o "$CIRCOM_DIR/OPRFNullifier.arks.zkey"
  curl -fsSL "$BASE_URL/OPRFQueryGraph.bin" -o "$CIRCOM_DIR/OPRFQueryGraph.bin"
  curl -fsSL "$BASE_URL/OPRFNullifierGraph.bin" -o "$CIRCOM_DIR/OPRFNullifierGraph.bin"
fi

# OpenSSL Android bundle (download if missing)
if [ ! -f "$OPENSSL_DIR/arm64-v8a/include/openssl/crypto.h" ]; then
  if [ -z "${OPENSSL_ANDROID_TARBALL_URL:-}" ]; then
    echo "Missing OpenSSL headers in $OPENSSL_DIR"
    echo "Set OPENSSL_ANDROID_TARBALL_URL to a tarball containing openssl-android/" 
    exit 1
  fi
  echo "OpenSSL bundle missing; downloading from $OPENSSL_ANDROID_TARBALL_URL"
  mkdir -p "$OPENSSL_DIR"
  curl -fsSL "$OPENSSL_ANDROID_TARBALL_URL" | tar -xz -C "$REPO_ROOT/third-party-libs"
fi

test -f "$CIRCOM_DIR/OPRFQuery.arks.zkey" || { echo "Missing circom artifacts in $CIRCOM_DIR"; exit 1; }

test -f "$OPENSSL_DIR/arm64-v8a/include/openssl/crypto.h" || {
  echo "Missing OpenSSL headers in $OPENSSL_DIR"; exit 1; }

echo "✅ Android deps present"
