#!/usr/bin/env bash
# Run from the root of the flat APT repository, before either compressor.
set -euo pipefail
if [[ ! -f Release || -e InRelease || -e Release.gpg ]]; then
  echo 'Expected an unsigned flat repository with a metadata-only Release' >&2; exit 1
fi
if grep -Eiq '^(MD5Sum|SHA[0-9]+):' Release; then
  echo 'Release now carries checksums: regenerate them after both compressors before enabling this integration' >&2; exit 1
else
  rc=$?; [[ $rc == 1 ]] || exit "$rc"
fi
src=$(dirname "$0")/link-depictions.c
tmp=$(mktemp -d .repodock-index.XXXXXXXX)
trap 'rm -rf -- "${tmp:?}"' EXIT
cc -std=c11 -O2 -Wall -Wextra -Werror "$src" -lsqlite3 -o "$tmp/filter"
# A failed filter must not leave a truncated Packages behind.
"$tmp/filter" < Packages > "$tmp/Packages"
mv -- "${tmp:?}/Packages" Packages
