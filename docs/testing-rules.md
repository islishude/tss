# Test Rules

This document defines the testing rules for `github.com/islishude/tss`.

The goal is not to maximize test count or global coverage. The goal is to make security invariants executable: bad inputs must fail closed, protocol state must not advance incorrectly, presigns must be exactly-once, and wire encodings must remain strict and canonical.

## Test Tiering

Tests are grouped by cost and purpose.

| Tier   | Trigger                   | Purpose                                                                                                                                                                     |
| ------ | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tier 0 | default / `-short`        | Fast deterministic tests: wire encoding, guards, replay, party sets, state-machine units, malformed inputs, domain construction, and blame evidence. No full crypto keygen. |
| Tier 1 | default non-short         | Fast crypto correctness with reduced parameters, cached fixtures, MtA correctness, proof correctness, and small deterministic protocol components.                          |
| Tier 2 | `integration`             | Full protocol lifecycle tests: keygen, presign, sign, refresh, reshare, BIP32, duplicate/replay handling, and guard integration.                                            |
| Tier 3 | `slowcrypto`              | Production-parameter Paillier and ZK smoke tests. Keep these narrow and intentional.                                                                                        |
| Tier 4 | `stress`, race, long fuzz | Concurrency, repeated randomized schedules, long fuzzing, race-sensitive flows, and repeated protocol execution. Explicit or nightly only.                                  |

Rules:

- Tier 0 must be deterministic, fast, and free of full Paillier keygen or complete CGGMP21 keygen/presign flows.
- Tier 1 may use reduced crypto parameters and cached fixtures, but must remain suitable for local fast feedback.
- Tier 2 must use the `integration` build tag.
- Tier 3 must use the `slowcrypto` build tag and should cover production-parameter smoke behavior, not exhaustive matrices.
- Tier 4 must be opt-in and must not run as part of ordinary local checks.
- Prefer deterministic test randomness. If randomized tests are necessary, print or accept a reproducible seed.
- Reject-path tests must not assert only `err != nil`; they must also assert no unsafe side effect where applicable.

## Parallelism and Performance Rules

The repository has many tests in a small number of packages. Package-level parallelism alone is not enough: tests within the same package run sequentially unless they call `t.Parallel()`.

Use intra-package parallelism deliberately:

- Add `t.Parallel()` to pure, deterministic, state-isolated unit tests.
- Do not add `t.Parallel()` to tests that mutate package globals, change process-wide environment, call `t.Setenv`, call `t.Chdir`, use fixed filesystem paths, bind fixed ports, mutate shared testdata, rely on execution order, or share mutable fixtures without synchronization.
- A `TestMain` that initializes global limits before `m.Run()` and clears them after `m.Run()` is not by itself a blocker. Individual tests that modify those globals are not parallel-safe.
- Parallel tests must use deterministic or concurrency-safe randomness. Do not share a mutable deterministic reader across parallel tests unless it is locked or cloned per test.
- When enabling parallelism in a package, first run the package repeatedly with `-count=1`, elevated `-parallel`, and the race detector when practical.

Top-level pattern:

```go
func TestSomething(t *testing.T) {
    t.Parallel()
    // existing body
}
```

Table-driven subtest pattern:

```go
func TestSomething(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name string
        // fields...
    }{
        // cases...
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
        })
    }
}
```

Low-risk first candidates for `t.Parallel()`:

- `internal/wire` tests for TLV encoding, decoding, field validation, limits, canonicalization, and golden vectors.
- `internal/wire/wireutil` tests.
- `internal/secret` tests for scalar construction, equality, marshaling, destruction API behavior, and redaction.
- `internal/shamir` tests for polynomial evaluation, Lagrange interpolation, and sharing round trips.
- `internal/bip32util` tests.
- `internal/curve/secp256k1` and `internal/curve/edwards25519` tests that do not mutate shared fixtures.
- Root package tests for broadcast, config, envelope, errors, evidence, guard, limits, logging, storage helpers, and transport helpers.
- `internal/testutil` tests that do not mutate shared global fixtures.

Protocol-package candidates:

- FROST encoding, golden, HD derivation, lifecycle unit, RFC/vector, and isolated keygen/sign tests may use `t.Parallel()` when each test builds its own sessions and shares.
- FROST tests that modify package-level test limits or other globals must remain sequential.
- CGGMP21 Tier 0 tests for encoding, golden vectors, domain construction, key-share accessors, lifecycle units, state transitions, reshare plans, scheduler behavior, proof omission, presign policy, HD derivation, and vectors may use `t.Parallel()` when they do not run full keygen/presign flows.
- CGGMP21 tests that run full keygen, presign, sign, refresh, reshare, adversarial delivery, or guard full-flow scenarios should use integration throttling instead of unconstrained parallelism.

Recommended test-run knobs:

```make
TEST_PARALLEL ?= $(shell nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)
PKG_PARALLEL ?= 8
INTEGRATION_PARALLEL ?= 2
```

Recommended behavior:

```sh
go test -short -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -timeout 1m ./...
go test -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -timeout 5m ./...
go test -tags=integration -p 2 -parallel $(INTEGRATION_PARALLEL) -timeout 20m ./...
```

Keep integration concurrency lower than unit-test concurrency. Crypto-heavy tests can saturate CPU and memory quickly, so more parallelism is not always faster.

Coverage should also be split by cost:

```sh
go test -short -coverprofile=coverage.unit.out -covermode=atomic ./...
go test -tags=integration -coverprofile=coverage.integration.out -covermode=atomic ./...
```

A combined all-tier coverage target is useful as an explicit heavyweight job, but it should not be the default local feedback loop.

## Integration Cost Control

Full CGGMP21 integration tests are expensive and should be parallelized with a package-local semaphore rather than unconstrained `t.Parallel()`.

Recommended helper:

```go
var integrationParallel = make(chan struct{}, 2)

func runLimitedParallel(t *testing.T) {
    t.Helper()
    t.Parallel()

    integrationParallel <- struct{}{}
    t.Cleanup(func() { <-integrationParallel })
}
```

Use this helper at the top of heavy integration tests for keygen, presign, sign, refresh, reshare, HD derivation, adversarial delivery, and full guard flows.

Rules:

- Acquire the semaphore after `t.Parallel()` resumes, as shown above.
- Keep the default limit small, usually `2`.
- Combine the semaphore with `go test -p 2` or similar so cross-package integration concurrency is also bounded.
- Do not use this helper for tests requiring exclusive package-level state. Keep those tests sequential and document why.
- Do not hide flakiness by reducing concurrency. If a test fails only under parallel execution, treat it as a shared-state or isolation bug until proven otherwise.

## Test Structure

Organize tests by invariant, not by incidental helper function.

Recommended package-level grouping:

```text
internal/wire/
  canonical_test.go
  golden_test.go
  limits_test.go
  mutation_test.go
  fuzz_test.go

root package tss
  guard_test.go
  replay_test.go
  envelope_test.go
  evidence_test.go
  storage_test.go

frost/ed25519/
  invariant_guard_test.go
  invariant_state_test.go
  integration_keygen_test.go
  integration_sign_test.go
  integration_reshare_test.go

cggmp21/secp256k1/
  invariant_guard_test.go
  invariant_state_test.go
  invariant_domain_test.go
  invariant_presign_test.go
  invariant_blame_test.go
  integration_keygen_test.go
  integration_presign_test.go
  integration_sign_test.go
  integration_refresh_test.go
  integration_reshare_test.go
```

Use shared helpers for deterministic parties, sessions, reduced fixtures, envelope mutations, network scheduling, and protocol assertions. Avoid each test inventing its own mini-network or party setup.

## Naming Convention

Use names that encode the protocol, phase, invariant, and expected behavior:

```go
func TestCGGMP21_Presign_WrongSessionRejectsWithoutStateMutation(t *testing.T)
func TestCGGMP21_Sign_PresignConcurrentConsumeExactlyOnce(t *testing.T)
func TestFROST_Sign_Round2BeforeRound1DoesNotAdvance(t *testing.T)
func TestWire_Envelope_NonCanonicalIntegerRejected(t *testing.T)
func TestGuard_AuthenticatedPartyMismatchRejected(t *testing.T)
```

Avoid vague names such as `TestBadInput`, `TestMalformed`, `TestAdversary`, or `TestIntegration2`.

## Required Invariants

When changing protocol behavior, wire encoding, storage, or public API, update tests for every affected invariant below.

### 1. Wire and Encoding

Required behavior:

- Same object marshals to identical bytes across repeated calls.
- `Unmarshal(Marshal(x))` preserves the intended public state.
- Duplicate tags are rejected.
- Trailing bytes are rejected.
- Wrong type IDs are rejected.
- Missing required fields are rejected.
- Non-minimal integers are rejected.
- Oversized fields are rejected.
- Malformed scalars and points are rejected.
- Unknown critical fields are rejected.
- Key shares, presign records, proof payloads, and blame evidence use strict binary decoding only; no JSON fallback.

Golden vectors are compatibility contracts:

- Valid vectors must continue to decode.
- Reject vectors must continue to fail.
- Do not silently update golden bytes. If bytes change, explain whether the wire contract changed intentionally.

### 2. Envelope Guard and Transport Boundary

Required behavior:

- Wrong protocol, version, session, round, sender, recipient, signer set, or transcript hash is rejected.
- Authenticated transport identity must match `Envelope.From`.
- Direct messages must not be accepted as broadcasts.
- Broadcast messages must not be accepted as direct messages.
- Messages requiring confidentiality must not be accepted in plaintext.
- Public messages must not be accepted in an unexpected secret-bearing envelope unless the policy explicitly allows it.
- Missing or invalid broadcast consistency certificates must fail closed.
- Replay and equivocation must be detected deterministically.

Reject-path assertions should verify, where relevant:

- The protocol handler was not called.
- Session state did not advance.
- No outbound envelope was emitted.
- No presign, nonce, or secret-bearing state was consumed.
- Replay cache or evidence state was not corrupted.

### 3. Protocol State Machines

Required behavior:

- Round transitions are monotonic.
- Early messages must not skip prerequisites.
- Duplicate messages must not advance state twice.
- Replayed messages must be rejected.
- Equivocated messages must be rejected and, where possible, produce public blame evidence.
- Corrupted payloads must be rejected.
- Wrong-recipient direct messages must be rejected.
- Messages from non-signers, old committee members, removed parties, or unknown parties must be rejected.
- Threshold checks, signer-set checks, committee checks, and reshare-plan checks must happen before emitting the next round.

If a phase explicitly buffers early messages:

- The message may be stored but must not be processed early.
- The session must not advance because of the buffered message alone.
- No outbound message may be emitted because of the buffered message alone.
- The buffered message must be revalidated after prerequisites arrive.

### 4. Identity Binding

Tests must bind all relevant identity layers:

- Transport-authenticated party.
- `Envelope.From`.
- Envelope recipient.
- Payload-internal party ID, when present.
- Proof statement party ID, when present.
- Committee set.
- Online signer set.

Required rejection cases:

- Transport identity says party 2, envelope says party 3.
- Envelope says party 2, payload internally claims party 3.
- Party is in the keygen committee but not in the current signer set.
- Party was removed by reshare but continues sending messages.
- New party acts before reshare completion.
- Old and new committee shares are mixed.

### 5. Domain Separation

Proofs, commitments, transcript hashes, challenges, and signature shares must not verify under the wrong context.

Tests should cover wrong:

- Protocol.
- Version.
- Session ID.
- Round.
- Sender.
- Recipient for direct messages.
- Committee set.
- Signer set.
- Threshold.
- Group public key.
- Message digest.
- BIP32 path.
- Presign context.

Required rejection cases:

- A valid proof from session A is used in session B.
- A valid keygen proof is used in presign, sign, refresh, or reshare.
- A valid direct proof for recipient A is used for recipient B.
- A valid signature share for digest A is used for digest B.
- A valid presign for BIP32 path A is used for BIP32 path B.
- A payload with threshold or signer set changed after proof generation is accepted. This must not happen.

### 6. CGGMP21 Presign Safety

CGGMP21 presigns are one-use security material. Treat presign reuse as a critical vulnerability.

Required behavior:

- A presign is consumed exactly once.
- The same presign cannot sign two digests.
- The same presign cannot sign the same digest twice.
- The same presign cannot be reused across sessions.
- The same presign cannot be reused across signer sets.
- The same presign cannot be reused across key shares.
- The same presign cannot be reused across BIP32 paths.
- A consumed presign remains consumed after marshal/unmarshal.
- A consumed presign remains consumed after encrypt/decrypt.
- A shallow copy must not bypass the consumed state.
- Concurrent signing attempts using the same presign allow at most one success.
- If a partial signature has been produced or could have been externally observed, the presign must be considered consumed.
- Bad inputs must not cause partial signature emission.

For concurrent tests, assert both the number of successful `StartSign` calls and the number of emitted partial signatures.

### 7. Refresh and Reshare Safety

Required behavior:

- Refresh preserves the group public key.
- Reshare preserves the group public key unless the protocol explicitly defines otherwise.
- Old and new committees must not be mixed.
- Removed parties must not participate after reshare completion.
- New parties must not act before reshare completion.
- Failed or interrupted refresh/reshare must not leave two usable inconsistent shares.
- Refresh epochs, reshare plans, party sets, and thresholds must be bound into relevant transcript or proof contexts.

### 8. Crash and Restart Safety

Where storage or consumed-state behavior is involved, tests should model restart-like reloads.

Required behavior:

- Incomplete keygen cannot export a usable key share.
- Keygen without required confirmation cannot be used for MPC.
- Incomplete presign cannot be used for signing.
- Consumed presign remains unusable after reload.
- If a partial signature was generated before crash, the presign is consumed after reload.
- Incomplete refresh leaves the old share usable and the new share unusable.
- Completed refresh makes the new share usable and prevents unsafe old/new mixing.
- Incomplete reshare does not let old and new committees mix.
- Completed reshare prevents removed parties from participating.

### 9. Blame Evidence

Blame evidence must be deterministic and public-only.

Required behavior:

- Invalid commitments blame the sender when attribution is possible.
- Invalid proofs blame the sender when attribution is possible.
- Invalid signature shares blame the sender when attribution is possible.
- Broadcast equivocation blames the equivocated sender.
- Replay or duplicate delivery must not be mislabeled as cryptographic blame against an honest sender.
- Transport-authentication failure must not be mislabeled as cryptographic proof failure.
- Local storage corruption must not blame a remote party.
- Evidence must not contain private shares, nonces, Paillier private-key material, MtA secrets, presign secrets, or witness material.

## Fuzzing Rules

Fuzz reject paths before success paths.

High-priority fuzz targets:

- `internal/wire.Unmarshal`.
- Envelope decoding and guard acceptance.
- Blame evidence decoding and verification.
- Key-share decoding.
- Presign decoding.
- ZK proof decoding and verification.

Fuzz expectations:

- No panic.
- No unbounded allocation.
- No timeout on malformed input.
- Malformed input rejects.
- Non-canonical encoding rejects.
- Oversized payloads reject.
- Trailing bytes reject.

Seed fuzz corpora from golden vectors and historical regression cases.

## Coverage Rules

Do not rely on one global coverage percentage. Use area-specific expectations.

Recommended targets:

| Area                                 |                                                                Target |
| ------------------------------------ | --------------------------------------------------------------------: |
| `internal/wire`                      |                                                                  90%+ |
| envelope / guard / replay / evidence |                                                                  90%+ |
| storage encryption helpers           |                                                                  85%+ |
| FROST state-machine orchestration    |                                                                  80%+ |
| CGGMP21 state-machine orchestration  |                                                                  75%+ |
| Paillier / ZK internals              | Correctness, adversarial, and slowcrypto coverage over raw percentage |

A lower coverage number is acceptable only when the missing paths are unreachable, defensive, or covered by heavier integration tests. Document the reason in the PR or test comments.

## Test Data and Fixtures

- Keep deterministic fixtures small and clearly labeled.
- Do not store secret production material in testdata.
- Do not log fixture secrets in failing tests.
- Reduced-parameter crypto fixtures must be visibly marked as test-only.
- Production-parameter fixtures or long-running generation must live behind `slowcrypto` or explicit fixture-generation tooling.

Recommended layout:

```text
testdata/
  golden/
    wire/v1/
    protocol/
  fuzz/
  regression/
```

## Fixture Caching Rules

Expensive fixtures are allowed when they reduce repeated crypto setup cost, but cached objects must not weaken test isolation.

Keygen fixture caching is appropriate when:

- The test only needs a valid baseline key share set.
- The test does not mutate shares in adversarial ways.
- The cache key includes all parameters that affect the result: protocol, version, threshold, party count, party set, HD mode, test limits, security parameters, deterministic seed or fixture identity, and relevant build tags.
- Cached objects are treated as immutable.
- Every caller receives deep clones, not pointers into the cached originals.

Use `sync.Once`, `singleflight`, or a cache entry containing a `sync.Once` to prevent multiple expensive constructors from racing on a cold cache. A plain `sync.Map` with separate `Load` and `Store` may still allow duplicate keygen work under concurrent first access.

Example shape:

```go
type fixtureKey struct {
    threshold int
    parties   int
    hd        bool
    limitsID  string
    seedID    string
}

type fixtureEntry struct {
    once   sync.Once
    shares map[tss.PartyID]*KeyShare
    err    error
}
```

Rules for cached key shares:

- Store only deep-cloned cache originals.
- Return fresh deep clones to each test.
- Verify clone methods copy secret-bearing fields safely and do not share mutable buffers, maps, slices, consumed flags, destroyed flags, or mutex-protected state.
- Tests that intentionally corrupt, destroy, consume, or mutate shares must bypass the cache.

Rules for cached Paillier and ZK fixtures:

- Reuse deterministic reduced-parameter fixtures for Tier 1 correctness tests when safe.
- Keep production-parameter fixture generation behind `slowcrypto` or explicit generation tooling.
- Never print private-key material or witnesses in fixture cache errors or test logs.
- Public verification fixtures may be shared more freely than private-key fixtures.

Rules for presigns:

- Do not broadly cache reusable presign objects. CGGMP21 presigns are one-use security material.
- If a test needs a presign cache for setup speed, the cache must store only immutable source material and must return a fresh, unconsumed, test-isolated presign object.
- Tests for consumption, concurrency, copy-safety, marshal/unmarshal, encrypt/decrypt, or restart behavior must not reuse presign fixtures across test cases.

## Coverage Gap Priorities

When adding new tests for coverage, prefer security-relevant gaps over incidental line coverage.

High-priority root package gaps:

- Guard builder and policy binding validation.
- Session and party validation in guard construction.
- Envelope open/marshal/unmarshal limit failures.
- Inbound validation fast-fail paths.
- Full broadcast consistency verification.
- Bounded replay-cache creation, check/store behavior, duplicate detection, equivocation detection, and eviction.
- Party-set sorting, membership checks, duplicate rejection, and boundary values.

High-priority FROST gaps:

- Guard construction and policy/session/party binding.
- Ack or confirmation verification error paths.
- Key-share JSON, string, and GoString redaction.
- Default and threshold-limit fail-closed paths.
- Chain-code and public accessor copy-safety.

High-priority CGGMP21 gaps:

- `StartReshare` invalid-parameter paths.
- Presign consumed-state helpers: double-consume, wrong session, concurrent consume.
- Result/Complete behavior in not-done, aborted, and destroyed states.
- Group commitments, share-proof bytes, chain-code bytes, keygen transcript hash, and public-key accessor copy-safety.
- Key-share string, GoString, JSON, and formatting redaction.
- Keygen transcript hash stability.

High-priority Paillier and ZK gaps:

- Encryption with caller-provided randomness and invalid-randomness rejection.
- Bit-size validation boundaries.
- Post-unmarshal consistency of `N`, `N²`, and `G`.
- JSON/string redaction for private-key material.
- Sampling helper range boundaries.
- Constant-time signed exponent helpers checked against public-reference implementations.
- Ring-Pedersen commitment algebraic relation checks.

Copy-safety pattern:

```go
func TestXReturnsCopy(t *testing.T) {
    t.Parallel()

    obj := makeTestObject(t)
    got := obj.SomeBytes()
    got[0] ^= 0xff

    got2 := obj.SomeBytes()
    if bytes.Equal(got, got2) {
        t.Fatal("SomeBytes returned a mutable internal buffer")
    }
}
```

Apply this pattern to byte slices, maps, slices of commitments, public-key encodings, verification shares, transcript hashes, chain codes, and any accessor that returns internal state.

## Parallelization Rollout Checklist

Apply performance changes in batches so regressions are easy to isolate.

### Batch 1: Low-risk parallel unit tests

- Add `t.Parallel()` to pure unit tests in low-risk internal packages and root package tests.
- Add configurable `TEST_PARALLEL`, `PKG_PARALLEL`, and `INTEGRATION_PARALLEL` knobs if Makefile targets are updated.
- Run short and fast suites repeatedly with elevated parallelism.

Verification:

```sh
go test -short -p 4 -parallel 8 -count=1 ./...
go test -p 4 -parallel 8 -count=1 ./...
```

### Batch 2: Integration throttling and fixture caching

- Add package-local semaphores for heavy CGGMP21 integration tests.
- Cache expensive keygen fixtures only when tests need valid baseline shares and do not mutate them.
- Cache Paillier fixtures for reduced-parameter correctness tests where private material remains isolated.
- Keep adversarial, mutation, consumption, and crash/restart tests on fresh fixtures unless the test explicitly validates caching behavior.

Verification:

```sh
go test -tags=integration -p 2 -parallel 2 -count=1 ./...
```

Measure wall-clock time before and after this batch. Do not trade correctness or determinism for speed.

### Batch 3: Coverage gap filling

- Add coverage for root guard/envelope/replay/broadcast/config gaps.
- Add FROST guard, confirmation, redaction, limit, and copy-safety gaps.
- Add CGGMP21 presign lifecycle, reshare validation, result state, redaction, transcript, and accessor copy-safety gaps.
- Add Paillier and ZK boundary, redaction, consistency, and algebraic relation checks.

Verification:

```sh
go test -short -coverprofile=coverage.unit.out ./...
go tool cover -func=coverage.unit.out
```

Before considering a performance batch complete, run the project’s normal CI-equivalent checks for the affected tier.

## Review Checklist

Before merging test changes, check:

- Does the test belong to the correct tier?
- Is randomness deterministic or reproducible?
- Does a reject-path test verify no unsafe side effect?
- Does the test cover an invariant rather than only a helper implementation detail?
- Are heavy tests behind the correct build tag?
- Are golden vector changes intentional and explained?
- Are secrets absent from logs, errors, fixtures, blame evidence, and failure messages?
