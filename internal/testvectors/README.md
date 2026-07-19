# Test Vectors

`internal/testvectors` is the canonical committed store for wire golden vectors,
protocol vectors, and expensive test fixture caches.

These categories have different meanings:

| Category            | Location                    | Meaning                                                                       |
| ------------------- | --------------------------- | ----------------------------------------------------------------------------- |
| Wire golden vectors | `wire/v1/**/*.golden`       | Canonical binary-format contracts                                             |
| Protocol vectors    | `protocol/*/*_vectors.json` | Independent vectors or self-generated format regressions, as documented below |
| Fixtures            | `fixtures/**`               | Committed test-only caches for expensive setup                                |

Run `make vectors-list` for the authoritative target and output inventory.

## Categories

### Wire golden vectors

Each `.golden` file contains one canonical hex-encoded binary object. Golden
tests verify that current marshal output matches the committed bytes, that the
bytes decode, and that re-encoding is canonical.

### Protocol vectors

These JSON files are for cross-implementation or protocol-format regression
checks.

```text
protocol/
  ed25519-bip32/khovratovich_law_vectors.json
  frost-ed25519/frost_ed25519_vectors.json
  cggmp21-secp256k1/cggmp21_secp256k1_vectors.json
```

The Ed25519-BIP32 file contains public-only, independent Khovratovich-Law
non-hardened derivation vectors. It records the pinned `cardano-address` 4.0.7
release, tag commit, release-asset SHA-256, and the complete one-time CLI oracle
commands. The CLI requires exactly two child-path segments for an account public
key, so the vector provenance records that interface constraint and how the
paper's public equation was used to expose the intermediate role-0 parent while
the pinned CLI independently fixed the `0/0`, `0/1`, and `0/2147483647`
endpoints. The committed file and recorded CLI inputs contain public keys and
chain codes only. Verification is fully local. This target deliberately has no
`tvgen update` operation, and CI neither downloads nor executes the external
binary.

FROST Ed25519 vectors are self-generated protocol-format regressions, not
independent-implementation vectors. Key generation is deterministic: the stored
seed reproduces the proof-gated three-round DKG, group public key, transcript,
and key-share encodings. Stored signatures are verified for validity; fresh
signing uses fresh nonces and may produce different signatures. Only RFC 9591
Appendix E.1 is the independent exact specification vector for the signing
ciphersuite operations; repository DKG and production nonce-binding flows are
not labeled as complete RFC flows.

CGGMP21 secp256k1 vectors are non-deterministic to generate because the protocol
uses `crypto/rand` for proof nonces. The committed file is a format regression
check: stored TLV encodings must decode, validate, round-trip, and produce a
verifiable signature.

### Fixtures

`fixtures/cggmp21-secp256k1/keygen_fixtures.json` is a committed fixture cache,
not a cross-implementation protocol vector. It contains reduced-parameter
CGGMP21 keygen shares for test-only cache warmup and must not be used as
production material.

## Common commands

Use the Makefile as the source of truth for selectors, command lines, and
timeouts:

```sh
make vectors-list
make vectors-verify-all
make vectors-update-wire       # only after an intentional wire change
make vectors-update-protocol   # only after an intentional protocol change
make vectors-update-fixtures   # only after an intentional fixture change
```

`make help` lists category-wide and compatibility aliases. Prefer `vectors-*`
because those targets distinguish wire, protocol, and fixture artifacts.

## `tvgen` runner

The Makefile delegates to `internal/testvectors/cmd/tvgen`. The runner only
orchestrates package-local `go test` targets with the required tags,
environment, and timeout; vector construction remains in the owning package.

```sh
go run ./internal/testvectors/cmd/tvgen list
go run ./internal/testvectors/cmd/tvgen verify all
```

Use a target name from `list` when only one group is affected:

```sh
go run ./internal/testvectors/cmd/tvgen update wire/frost
go run ./internal/testvectors/cmd/tvgen verify protocol/frost-ed25519
```

Use `-timeout` to override the default `30m` `go test` timeout:

```sh
go run ./internal/testvectors/cmd/tvgen -timeout 45m verify all
```

The runner rejects update requests for verify-only targets. Its manifest is the
source of truth for target names, tiers, packages, and outputs.

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
3. Keep self-generated protocol JSON generation behind the `vectorgen` build
   tag. Independent external-oracle vectors must instead be verify-only targets
   with no `tvgen update` operation.
4. Use `internal/testvectors.Read` for committed vector reads and
   `internal/testvectors.Path` for generator writes.
5. Document whether the new file is a wire golden vector, protocol vector, or
   fixture cache.
6. Run the smallest matching `make vectors-verify-*` target, then `make check`
   when the change affects committed artifacts or shared helpers.
