# Test Vectors

`internal/testvectors` is the canonical committed store for wire golden vectors,
protocol vectors, and expensive test fixture caches.

These categories have different meanings:

- Wire golden vectors are binary wire-format contracts.
- Protocol vectors are JSON cross-implementation or format-regression vectors.
- Fixtures are committed test-only caches used to avoid expensive setup during
  tests.

Current inventory: 33 binary wire golden files, 2 protocol JSON files, and 1
fixture JSON file.

## Categories

### Wire golden vectors

Location: `wire/v1/**/*.golden`

Each `.golden` file contains one canonical hex-encoded binary object. Golden
tests verify that current marshal output matches the committed bytes, that the
bytes decode, and that re-encoding is canonical.

Current files:

```text
wire/v1/
  envelope/   1 file   Envelope.golden
  tss/        4 files  BlameEvidence, SigningContext, BroadcastAck,
                       BroadcastCertificate
  frost/      6 files  KeyShare, VerificationShare, KeygenCommitmentsPayload,
                       KeygenSharePayload, NonceCommitmentPayload,
                       SignPartialPayload
  cggmp21/    14 files KeyShare, VerificationShare, PaillierPublicShare,
                       RingPedersenPublicShare, SignVerifyShare,
                       KeygenSharePayload, RefreshSharePayload,
                       ReshareSharePayload, Presign, Presign.fast,
                       PresignRound3Payload, ResharePlan,
                       SignAttemptRecord, SignPartialPayload
  zk/         8 files  SecurityParams, ModulusProof, RingPedersenParams,
                       RingPedersenProof, EncProof, AffGProof,
                       LogStarProof, SchnorrProof
```

### Protocol vectors

Location: `protocol/*/*_vectors.json`

These JSON files are for cross-implementation or protocol-format regression
checks.

```text
protocol/
  frost-ed25519/frost_ed25519_vectors.json
  cggmp21-secp256k1/cggmp21_secp256k1_vectors.json
```

FROST Ed25519 vectors are deterministic for key generation: the stored seed
reproduces the group public key and key-share encodings. Stored signatures are
verified for validity; fresh signing uses fresh nonces and may produce different
signatures.

CGGMP21 secp256k1 vectors are non-deterministic to generate because the protocol
uses `crypto/rand` for proof nonces. The committed file is a format regression
check: stored TLV encodings must decode, validate, round-trip, and produce a
verifiable signature.

### Fixtures

Location: `fixtures/cggmp21-secp256k1/keygen_fixtures.json`

This file is a committed fixture cache, not a cross-implementation protocol
vector. It contains reduced-parameter CGGMP21 keygen shares for test-only cache
warmup and must not be used as production material.

## Common commands

Use the Makefile as the source of truth for exact command lines and timeouts.

```sh
make vectors-list
make vectors-update-wire
make vectors-update-protocol
make vectors-update-fixtures
make vectors-update-all
make vectors-verify-wire
make vectors-verify-protocol
make vectors-verify-fixtures
make vectors-verify-all
```

Legacy aliases remain available:

```sh
make golden-update
make golden-update-protocol
make golden-update-all
make golden-verify
make golden-verify-protocol
make golden-verify-all
```

The `golden-*` aliases are compatibility entrypoints. Prefer `vectors-*` for new
work because the repository now distinguishes wire golden vectors, protocol
vectors, and fixture caches explicitly.

## `tvgen` runner

The Makefile delegates to `internal/testvectors/cmd/tvgen`. The runner is
orchestration only: it executes package-local `go test` targets with the right
tags, environment, and timeout. It does not construct vector objects centrally.

```sh
go run ./internal/testvectors/cmd/tvgen list
go run ./internal/testvectors/cmd/tvgen update wire
go run ./internal/testvectors/cmd/tvgen update protocol
go run ./internal/testvectors/cmd/tvgen update fixtures
go run ./internal/testvectors/cmd/tvgen update all
go run ./internal/testvectors/cmd/tvgen verify all
```

Single-target commands are available when only one vector group is affected:

```sh
go run ./internal/testvectors/cmd/tvgen update wire/frost
go run ./internal/testvectors/cmd/tvgen update fixtures/cggmp21-keygen
go run ./internal/testvectors/cmd/tvgen verify protocol/frost-ed25519
```

Use `-timeout` to override the default `30m` `go test` timeout:

```sh
go run ./internal/testvectors/cmd/tvgen -timeout 45m verify all
```

The canonical targets are:

```text
wire/envelope
wire/tss
wire/frost
wire/zk
wire/cggmp21-fast
wire/cggmp21-integration
protocol/frost-ed25519
protocol/cggmp21-secp256k1
fixtures/cggmp21-keygen
```

## Helper API

Tests and generators should address files by slash-separated paths relative to
`internal/testvectors`; callers should not derive paths from the current working
directory, package depth, or `go.mod`.

Verification reads use embedded committed files:

```go
data := testvectors.Read(t, "protocol/frost-ed25519/frost_ed25519_vectors.json")
```

Golden checks use the same embedded read path during verification and a real
filesystem path during update:

```go
testvectors.CheckHexGolden(t, "wire/v1/frost/KeyShare.golden", raw)
```

Generators that must write committed artifacts use `testvectors.Path`:

```go
path, err := testvectors.Path("protocol/frost-ed25519/frost_ed25519_vectors.json")
if err != nil {
	t.Fatal(err)
}
```

`testvectors.Path` is anchored to the `internal/testvectors` package source
directory via `runtime.Caller`; it does not search upward for `go.mod`. If a
trimpath or alternate-checkout workflow prevents an absolute source path,
`TSS_TESTVECTORS_DIR=/absolute/path/to/internal/testvectors` may be set
explicitly.

## When to regenerate

- Wire encoder or decoder shape changed intentionally: update affected wire
  golden vectors.
- Transcript, proof domain, or protocol binding changed intentionally: update
  affected wire golden vectors and protocol vectors together.
- Required fixture combinations or fixture shape changed intentionally: update
  fixtures.
- Ordinary implementation bugfix with unchanged wire/protocol shape: verify only;
  do not update vectors.

Never update vectors merely to make a failing test pass. Treat any vector churn as
evidence of a wire, protocol, or fixture-lifecycle change that needs review.

## Safety rules

- Fixtures and some golden vectors contain private test material such as shares,
  nonces, witnesses, or presign material.
- Never paste vector contents into logs, issues, review comments, or failure
  messages.
- Golden mismatch output intentionally reports path, byte lengths, and SHA-256
  digests only. It must not print raw got/want hex.
- Committed fixtures are test-only material. They are not production keys,
  reference secrets, or public cross-implementation vectors.

## Versioning

The repository is not yet production-stable. Before production compatibility is
required, intentional wire or domain changes regenerate the existing `wire/v1`
vectors after review. Do not add fallback decoders, compatibility versions, or
`v2`/`v3` wire/proof/challenge-label trees unless a future production-stability
decision explicitly requires them.

## Adding vectors

1. Add generation and verification in the package that owns the wire or protocol
   helper. Do not export internal protocol APIs just for vector generation.
2. Use `internal/testvectors.CheckHexGolden` for hex-encoded wire golden files.
3. Keep protocol JSON generation behind the `vectorgen` build tag.
4. Use `internal/testvectors.Read` for committed vector reads and
   `internal/testvectors.Path` for generator writes.
5. Document whether the new file is a wire golden vector, protocol vector, or
   fixture cache.
6. Run the smallest matching `make vectors-verify-*` target, then `make check`
   when the change affects committed artifacts or shared helpers.
