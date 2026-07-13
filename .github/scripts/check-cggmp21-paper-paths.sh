#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

forbidden='internal/zk/signprep|payloadSignIdentification|signIdentificationRound|KPoint|ChiPoint|DeltaAggregate|signprep|LogCiphertext|LogProof|logProofDomain|VerificationKeyForContext|VerifySignatureForContext'
if git grep --untracked -n -E "$forbidden" -- \
  ':(glob)cggmp21/**/*.go' \
  ':(glob)internal/**/*.go' \
  ':(exclude,glob)**/*_test.go' \
  ':(exclude,glob)internal/testvectors/**'; then
  echo "CGGMP21 production code still references a retired protocol path" >&2
  exit 1
fi

if git grep --untracked -n -E '\.Exp\(' -- \
  ':(glob)internal/mta/**/*.go' \
  ':(glob)cggmp21/secp256k1/**/*.go' \
  ':(exclude,glob)**/*_test.go'; then
  echo "CGGMP21 secret-bearing paths must route modular exponentiation through paillierct" >&2
  exit 1
fi

if git grep --untracked -n -E 'shamir\.(Eval|LagrangeCoefficient)\(' -- \
  ':(glob)**/*.go'; then
  echo "repository code must not call retired fixed-coordinate Shamir APIs" >&2
  exit 1
fi

if git grep --untracked -n -E 'func[[:space:]]+(Eval|LagrangeCoefficient)[[:space:]]*\(' -- \
  ':(glob)internal/shamir/**/*.go'; then
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
  if ! git grep --untracked -q -E "$symbol" -- \
    ':(glob)cggmp21/secp256k1/**/*.go' \
    ':(glob)tssrun/**/*.go'; then
    echo "missing required CGGMP21 paper-aligned symbol: $symbol" >&2
    exit 1
  fi
done
