#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec nix develop .#swift --command ./swift/build_swift.sh "$@"
