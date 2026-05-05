#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

readonly TARGETS=(
  "aarch64-linux-android"
  "armv7-linux-androideabi"
  "x86_64-linux-android"
  "i686-linux-android"
)

usage() {
  cat <<EOF
Usage: $0 --target <target>

Targets:
$(printf '  %s\n' "${TARGETS[@]}")

EOF
}

TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
  --target | -t)
    if [[ $# -lt 2 ]]; then
      echo "error: --target requires a value" >&2
      usage >&2
      exit 1
    fi
    TARGET="$2"
    shift 2
    ;;
  --help | -h)
    usage
    exit 0
    ;;
  *)
    echo "error: unknown argument: $1" >&2
    usage >&2
    exit 1
    ;;
  esac
done

if [[ -z "${TARGET}" ]]; then
  echo "error: --target is required" >&2
  usage >&2
  exit 1
fi

valid_target=false
for candidate in "${TARGETS[@]}"; do
  if [[ "${TARGET}" == "${candidate}" ]]; then
    valid_target=true
    break
  fi
done

if [[ "${valid_target}" != true ]]; then
  echo "error: unsupported target: ${TARGET}" >&2
  usage >&2
  exit 1
fi

exec nix develop .#android --command cargo build \
  -p walletkit \
  --release \
  --target "${TARGET}" \
  --features compress-zkeys,v3
