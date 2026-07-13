#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

forbidden='internal/zk/signprep|payloadSignIdentification|signIdentificationRound|KPoint|ChiPoint|DeltaAggregate|signprep|LogCiphertext|LogProof|logProofDomain|VerificationKeyForContext|VerifySignatureForContext'
if rg -n --glob '*.go' --glob '!**/*_test.go' --glob '!internal/testvectors/**' "$forbidden" cggmp21 internal; then
  echo "CGGMP21 production code still references a retired protocol path" >&2
  exit 1
fi

if rg -n --glob '*.go' --glob '!**/*_test.go' '\.Exp\(' internal/mta cggmp21/secp256k1; then
  echo "CGGMP21 secret-bearing paths must route modular exponentiation through paillierct" >&2
  exit 1
fi

if rg -n --glob '*.go' 'shamir\.(Eval|LagrangeCoefficient)\(' .; then
  echo "repository code must not call retired fixed-coordinate Shamir APIs" >&2
  exit 1
fi

if rg -n --glob '*.go' 'func[[:space:]]+(Eval|LagrangeCoefficient)[[:space:]]*\(' internal/shamir; then
  echo "internal/shamir must not redefine retired fixed-coordinate APIs" >&2
  exit 1
fi

required=(
  'type EpochContext struct'
  'type normalizedPresignCommitment struct'
  'verifyFigure10Partial'
  'GenerationBinding'
  'LifecycleStore'
)
for symbol in "${required[@]}"; do
  if ! rg -q --glob '*.go' "$symbol" cggmp21/secp256k1 tssrun; then
    echo "missing required CGGMP21 paper-aligned symbol: $symbol" >&2
    exit 1
  fi
done
