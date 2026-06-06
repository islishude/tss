#!/usr/bin/env bash
set -euo pipefail

FUZZTIME="${FUZZTIME:-60s}"
PARALLEL="${PARALLEL:-2}"

for pkg in $(go list ./...); do
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
