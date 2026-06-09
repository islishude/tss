#!/usr/bin/env bash
set -euo pipefail

FUZZTIME="${FUZZTIME:-60s}"
PARALLEL="${PARALLEL:-4}"

# Usage:
#   ./fuzz.sh                     # fuzz all packages: ./...
#   ./fuzz.sh ./pkg/foo           # fuzz one package
#   ./fuzz.sh ./pkg/foo ./pkg/bar # fuzz multiple packages
#   ./fuzz.sh ./internal/...      # fuzz package pattern
PKG_PATTERNS=("$@")

if [ "${#PKG_PATTERNS[@]}" -eq 0 ]; then
  PKG_PATTERNS=("./...")
fi

for pkg in $(go list "${PKG_PATTERNS[@]}"); do
  targets=$(go test -run=^$ -list='^Fuzz' "$pkg" | grep '^Fuzz' || true)

  for target in $targets; do
    echo "==> fuzzing $pkg $target"
    go test -v -run=^$ \
      -fuzz="^${target}$" \
      -fuzztime="$FUZZTIME" \
      -fuzzminimizetime=10s \
      -parallel="$PARALLEL" \
      "$pkg"
  done
done
