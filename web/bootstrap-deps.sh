#!/usr/bin/env bash
# Reproducible temporary dependency patches, pending upstream releases.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$PWD"

prepare() {
  local name="$1" revision="$2"
  local destination="$root/target/web-deps/$name"
  local patch="$root/web/patches/$name-wasm.patch"
  if [[ ! -d "$destination/.git" ]]; then
    if [[ -e "$destination" ]]; then
      echo "Refusing to overwrite existing directory: $destination" >&2
      exit 1
    fi
    git init -q "$destination"
    git -C "$destination" remote add origin "https://github.com/worldcoin/$name.git"
    git -C "$destination" fetch -q --depth 1 origin "$revision"
    git -C "$destination" switch -q --detach FETCH_HEAD
  fi
  if [[ "$(git -C "$destination" rev-parse HEAD)" != "$revision" ]]; then
    echo "Unexpected revision in $destination; preserving the checkout." >&2
    exit 1
  fi
  if git -C "$destination" apply --reverse --check "$patch" 2>/dev/null; then
    return
  fi
  git -C "$destination" apply --check "$patch"
  git -C "$destination" apply "$patch"
}

prepare pontifex 19fc7eccb8a46babaf688b76fe6a0021d712cbdc
prepare flamingo 3484db339622dd3431e5ed1f3286df5fe7e94ea0
