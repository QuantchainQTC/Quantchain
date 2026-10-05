#!/usr/bin/env bash
# Check macOS release binaries before they are packaged.
#
# Usage: check-macos-release.sh <arch> <minos> <binary>...
#
# Each binary must:
#   1. hold exactly one architecture, <arch> (arm64 or x86_64);
#   2. load libraries only from /usr/lib and /System/Library, so it needs
#      nothing from Homebrew, MacPorts or /usr/local;
#   3. state <minos> as its minimum macOS version;
#   4. exit 0 from "-version" with every read under /opt/homebrew and
#      /usr/local denied, as on a Mac that has neither.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <arch> <minos> <binary>..." >&2
  exit 2
fi
arch=$1
minos=$2
shift 2

deny='(version 1)(allow default)(deny file-read* (subpath "/opt/homebrew") (subpath "/usr/local"))'

# Check 4 passes for any binary if the profile denies nothing, so first
# confirm that it denies a read of each directory that exists here.
for dir in /opt/homebrew /usr/local; do
  if [ -d "$dir" ] && sandbox-exec -p "$deny" /bin/ls "$dir" >/dev/null 2>&1; then
    echo "sandbox-exec allowed a read of $dir" >&2
    exit 1
  fi
done

status=0
for bin in "$@"; do
  found=$(lipo -archs "$bin")
  if [ "$found" != "$arch" ]; then
    echo "$bin: architectures '$found', expected '$arch'" >&2
    status=1
  fi

  # otool -L prints one tab-indented line per library the binary loads:
  # the path, then " (compatibility version ...". Every macOS executable
  # loads libSystem, so a count of zero means the output was not parsed.
  count=0
  while IFS= read -r lib; do
    count=$((count + 1))
    # A "." or ".." segment can lead out of /usr/lib or /System/Library.
    case "$lib" in
      */./*|*/../*) ;;
      /usr/lib/*|/System/Library/*) continue ;;
    esac
    echo "$bin: loads $lib" >&2
    status=1
  done < <(otool -L "$bin" | awk -F' [(]compatibility version' '/^\t/ {sub(/^\t/, "", $1); print $1}')
  if [ "$count" -eq 0 ]; then
    echo "$bin: no libraries parsed from otool -L" >&2
    status=1
  fi

  found=$(vtool -show-build "$bin" | awk '$1 == "minos" {print $2}')
  if [ "$found" != "$minos" ]; then
    echo "$bin: minimum macOS '$found', expected '$minos'" >&2
    status=1
  fi

  if ! sandbox-exec -p "$deny" "$bin" -version >/dev/null; then
    echo "$bin: -version failed with /opt/homebrew and /usr/local unreadable" >&2
    status=1
  fi
done
exit "$status"
