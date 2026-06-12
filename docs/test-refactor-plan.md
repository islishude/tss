# Test Refactor Plan

This document defines the plan for refactoring and rewriting the test suite of `github.com/islishude/tss`.

The refactor is not a cosmetic rewrite. The goal is to turn the test suite into an executable security specification for the TSS library while also improving local feedback speed.

## 1. Goals

The refactor has five goals:

1. Make tests faster through safe intra-package parallelism, integration throttling, and fixture caching.
2. Make tests easier to maintain through table-driven grouping and shared harnesses.
3. Make security invariants explicit and executable.
4. Remove, rewrite, or merge tests that are duplicated, vague, slow without value, flaky, or structurally inconsistent.
5. Allow production-code changes when tests expose API, design, correctness, or security defects.

A successful refactor should leave the repository with fewer ad hoc tests, more invariant-driven tests, faster short feedback, and clearer failure diagnostics.

## 2. Non-Negotiable Requirements

The refactor must follow these requirements.

### 2.1 Prefer Table-Driven Tests

Tests should be table-driven where it improves clarity and maintainability. Table-driven grouping makes related cases visible together and reduces duplication in setup and assertions.

For a given production function, method, state transition, or invariant, related test cases are usually clearer when grouped into one table-driven test function with named cases.

For example:

```go
func TestEnvelopeGuard_Accept(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name    string
        mutate  func(*Envelope)
        wantErr error
        assert  func(t *testing.T, before, after guardSnapshot)
    }{
        {name: "wrong session rejects", mutate: mutateSession, wantErr: ErrWrongSession},
        {name: "wrong protocol rejects", mutate: mutateProtocol, wantErr: ErrWrongProtocol},
        {name: "sender spoof rejects", mutate: mutateSender, wantErr: ErrUnauthenticatedSender},
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            // test body
        })
    }
}
```

Separate test functions are a reasonable choice when they test different behavior families, have different setup costs, belong to different tiers, use different build tags, or guard materially different safety invariants:

```go
func TestEnvelopeGuardRejectsWrongSession(t *testing.T) {}
func TestEnvelopeGuardRejectsWrongProtocol(t *testing.T) {}
func TestEnvelopeGuardRejectsSenderSpoof(t *testing.T) {}
```

### 2.2 Tests May Drive Production-Code Changes

If a test exposes a design, correctness, race, API, encoding, storage, or security problem, production code may be changed as part of the test refactor.

Allowed production-code changes include:

- Adding missing validation.
- Making error behavior fail closed.
- Preventing presign reuse.
- Fixing domain separation.
- Fixing wire canonicalization or strict decoding.
- Adding copy-safe accessors.
- Adding redaction for secret-bearing types.
- Adding synchronization or no-copy protection where shared mutable state is unsafe.
- Adding test-only hooks behind `_test.go` or unexported package-local helpers.
- Splitting code to make invariants testable.
- Removing retired fallback paths that weaken strictness.

Production-code changes must not weaken cryptographic checks, broaden accepted wire formats, leak secret material, or introduce compatibility shims for retired formats.

### 2.3 Existing Tests May Be Rewritten or Deleted

Existing tests are not sacred. They may be rewritten, merged, renamed, moved, or deleted if they do not match the new rules.

Delete or replace tests that are:

- Duplicate coverage of the same case without additional invariant value.
- Non-deterministic without reproducible seeds.
- Slow without clear security or integration value.
- Vague, such as tests that only check that something “works”.
- Pure happy-path tests that duplicate a stronger integration test.
- Testing implementation details that should not be contractual.
- Split into many tiny functions where a table would be clearer.
- Asserting only `err != nil` without checking side effects for reject paths.
- Logging or comparing secret-bearing values unsafely.

When deleting a test, ensure its useful assertion is either unnecessary or preserved in a stronger table-driven test.

## 3. Scope

The refactor covers:

- Root package `tss` tests.
- `internal/wire` and wire utility tests.
- `internal/secret`, `internal/shamir`, `internal/bip32util`, and curve helper tests.
- `frost/ed25519` unit and integration tests.
- `cggmp21/secp256k1` unit and integration tests.
- `internal/paillier`, `internal/mta`, and `internal/zk/*` tests.
- Test harnesses, fixtures, deterministic randomness, mutation helpers, protocol runners, and Makefile test targets.
- Coverage, fuzz, golden vector, and slowcrypto organization.

The refactor does not attempt to claim production audit readiness. It improves test structure and executable safety coverage, but cryptographic audit status remains separate.

## 4. Target Test Architecture

Tests should be organized by invariant and cost tier.

Recommended structure:

```text
internal/testharness/
  rng.go                  — 1. Deterministic RNG
  parties.go              — 2. Party factory
  protocol_runner.go      — 3. Protocol runner
  network.go              — 4. Network simulator (with fault injection)
  state_snapshot.go       — 5. State snapshot
  envelope_mutation.go    — 6. Mutation library
  crash_store.go          — CrashPoint, CrashyStore for crash/restart
  golden.go               — golden vector contracts
  fuzz.go                 — fuzz corpus seeding
  budget.go               — test runtime budget checker

internal/testvectors/
  wire/
    v1/
      envelope/
      frost/
      cggmp21/
      zk/
  protocol/
    frost-ed25519/
    cggmp21-secp256k1/

internal/wire/
  canonical_test.go
  golden_test.go
  limits_test.go
  mutation_test.go
  fuzz_test.go

root package tss
  envelope_test.go
  guard_test.go
  replay_test.go
  broadcast_test.go
  evidence_test.go
  storage_test.go

frost/ed25519/
  encoding_test.go
  invariant_guard_test.go
  invariant_state_test.go
  integration_keygen_test.go
  integration_sign_test.go
  integration_reshare_test.go
  integration_refresh_test.go
  vectors_test.go

cggmp21/secp256k1/
  encoding_test.go
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
  vectors_test.go
```

The exact file names may vary, but each file should have a clear invariant or lifecycle purpose.

## 5. Test Tiering

Follow `docs/testing-rules.md` for the authoritative tier definitions. This refactor plan uses the following operational interpretation.

| Tier   | Trigger             | Contents                                                                                                                                               |
| ------ | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Tier 0 | default / `-short`  | Fast deterministic tests: wire, guard, replay, encoding, redaction, copy safety, state-machine units, malformed input. No full CGGMP21 keygen/presign. |
| Tier 1 | `smallcrypto` tag   | Reduced-parameter crypto correctness: small-param Paillier, ZK proof checks, MtA, Shamir, curve ops, FROST small flows.                                |
| Tier 2 | `integration` tag   | Full FROST and CGGMP21 lifecycle tests.                                                                                                                |
| Tier 3 | `slowcrypto` tag    | Production-parameter Paillier/ZK smoke. Narrow and intentional.                                                                                        |
| Tier 4 | `stress` / explicit | Stress, race-heavy, long fuzz, repeated randomized schedules.                                                                                          |

Corresponding Makefile targets:

```make
test-unit:
	go test -short -timeout 1m ./...

test-fast:
	go test -tags=smallcrypto -timeout 5m ./...

test-integration:
	go test -tags=integration -timeout 20m ./...

test-slowcrypto:
	go test -tags=slowcrypto -timeout 1h ./...

test-stress:
	go test -race -tags='integration slowcrypto stress' -count=10 -timeout 5h ./...
```

Tier 0 is always compiled. Tier 1 uses `//go:build smallcrypto` to separate small-parameter crypto tests from pure unit tests at compile time. This is explicit and cannot be silently bypassed by forgetting `testing.Short()`.

## 6. Table-Driven Testing Guidance

### 6.1 Case Table Shape

When using table-driven tests, each table should name the security condition and expected side effects.

Suggested shape:

```go
tests := []struct {
    name       string
    setup      func(t *testing.T) fixture
    mutate     func(t *testing.T, fx fixture)
    wantErr    error
    wantBlame  *tss.PartyID
    assert     func(t *testing.T, before, after snapshot, err error)
}{
    // cases
}
```

For pure functions, keep the table smaller:

```go
tests := []struct {
    name    string
    input   []byte
    want    Value
    wantErr bool
}{
    // cases
}
```

### 6.2 One Function, One Behavior Family

A single production function may have multiple test functions only when the behavior families are meaningfully different.

Acceptable split:

```text
TestEnvelopeGuard_Accept_ValidInputs
TestEnvelopeGuard_Accept_RejectsInvalidInputs
TestEnvelopeGuard_Accept_ReplayAndEquivocation
```

Bad split:

```text
TestEnvelopeGuardRejectsWrongSession
TestEnvelopeGuardRejectsWrongProtocol
TestEnvelopeGuardRejectsWrongRound
TestEnvelopeGuardRejectsWrongSender
```

### 6.3 Reject-Path Assertions

Reject-path cases must assert more than an error.

Where applicable, assert:

- No state advancement.
- No outbound envelope emission.
- No presign or nonce consumption unless the safety model requires fail-closed consumption.
- No unsafe replay-cache mutation.
- No secret material in errors, logs, blame evidence, or string formatting.
- Correct blame attribution when attribution is possible.

## 7. Parallelism Plan

The repository currently has many test functions but no intra-package parallelism. Package-level parallelism alone is insufficient because many tests live in a small number of packages.

### 7.1 Low-Risk Parallelization

Add `t.Parallel()` first to pure deterministic unit tests in these areas:

- `internal/wire`.
- `internal/wire/wireutil`.
- `internal/secret`.
- `internal/shamir`.
- `internal/bip32util`.
- `internal/curve/secp256k1`.
- `internal/curve/edwards25519`.
- Root package tests for envelope, guard, replay, broadcast, evidence, config, errors, limits, storage, logging, and transport helpers.
- `internal/testutil` tests that do not mutate shared global fixtures.

Add `t.Parallel()` to FROST and CGGMP21 Tier 0 tests only when each test owns its fixtures and does not mutate package globals.

### 7.2 Parallelism Blockers

Do not parallelize tests that:

- Mutate package globals.
- Use `t.Setenv` or `t.Chdir`.
- Rely on current working directory side effects.
- Use fixed filesystem paths or fixed ports.
- Mutate shared testdata.
- Share mutable crypto fixtures.
- Depend on test ordering.
- Use a shared deterministic reader without locking or cloning.
- Require exclusive access to package-level test limits.

### 7.3 Integration Concurrency (revised 2026-06-11)

**Lesson learned:** A channel-semaphore throttling helper (`runLimitedIntegration`) was implemented and later removed. It made integration tests **slower**, not faster.

The semaphore (capacity 2) combined `t.Parallel()` with channel acquire/release. In practice this created double-gating: Go's test runner already manages parallelism via `-p` and `-parallel` flags. Adding a second gate on top caused scheduling contention (tests queuing on both the runner's internal slots and the channel), increased goroutine switching, and provided no benefit because `-p 2 -parallel 2` already limits concurrent integration tests to the intended level.

**Current approach:** Integration tests use `go test` flags directly for concurrency control. No in-code semaphore is needed. The Makefile targets already provide the right knobs:

```make
test-integration:
	go test -tags=integration -p 2 -parallel $(INTEGRATION_PARALLEL) -timeout 20m ./...
```

With fixture caching (`CachedKeygenShares`) reducing keygen cost, there is even less reason to throttle test entry — tests spend most time in protocol flows that benefit from unconstrained `t.Parallel()` when tests own their own state.

### 7.4 Makefile Knobs

Use explicit concurrency knobs:

```make
TEST_PARALLEL ?= $(shell nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)
PKG_PARALLEL ?= 8
INTEGRATION_PARALLEL ?= 2
```

Recommended targets:

```make
test:
	go test -short -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -timeout 1m ./...

test-fast:
	go test -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -timeout 5m ./...

test-integration:
	go test -tags=integration -p 2 -parallel $(INTEGRATION_PARALLEL) -timeout 20m ./...

coverage-unit:
	go test -short -coverprofile=coverage.unit.out -covermode=atomic ./...

coverage-integration:
	go test -tags=integration -coverprofile=coverage.integration.out -covermode=atomic ./...
```

A combined all-tier coverage target may remain, but it must be treated as heavyweight and non-default.

## 8. Fixture Caching Plan

Fixture caching is allowed for expensive immutable fixtures. It must not weaken isolation.

### 8.1 Allowed Cached Fixtures

Good candidates:

- Reduced-parameter Paillier keys used only for tests.
- CGGMP21 keygen output used as a read-only base for integration tests.
- Public parameters and public test vectors.
- Immutable proof contexts.

### 8.2 Forbidden or Dangerous Cached Fixtures

Do not cache one-use or mutable security material as ordinary shared state:

- CGGMP21 presigns.
- Nonces.
- Mutable session state.
- Consumed flags.
- Buffers that tests mutate.
- Shared deterministic RNG readers.

Presigns may be created from cached key shares, but each test must receive a fresh presign unless it is explicitly testing consumed-state persistence or reuse rejection.

### 8.3 Cache Safety Rules

Cached fixtures must follow these rules:

- Cache keys must include every behavior-affecting option: threshold, party count, HD mode, curve, parameter size, protocol variant, and any reduced-parameter mode.
- Cache entries must be immutable.
- Return deep clones to callers.
- Never return pointers to mutable cached originals.
- Use `sync.Once`, `sync.Map`, or `singleflight` to prevent duplicate expensive construction under parallel tests.
- If fixture construction fails, do not poison the cache with a partial object.

Recommended pattern:

```go
type fixtureKey struct {
    threshold int
    parties   int
    hd        bool
    params    string
}

var keygenFixtureCache sync.Map // map[fixtureKey]*keygenFixture

func cachedKeygenFixture(t testing.TB, key fixtureKey) map[tss.PartyID]*KeyShare {
    t.Helper()

    if v, ok := keygenFixtureCache.Load(key); ok {
        return cloneKeyShares(t, v.(*keygenFixture).shares)
    }

    shares := runFreshKeygen(t, key)
    cached := &keygenFixture{shares: cloneKeyShares(t, shares)}
    actual, _ := keygenFixtureCache.LoadOrStore(key, cached)

    return cloneKeyShares(t, actual.(*keygenFixture).shares)
}
```

## 9. Required Invariant Matrices

The refactor must preserve or add coverage for these invariants.

### 9.1 Wire and Encoding

Tests must cover (using table-driven grouping where practical):

- Repeated marshal stability.
- Marshal/unmarshal round trip.
- Duplicate tags.
- Trailing bytes.
- Wrong type IDs.
- Missing required fields.
- Non-minimal integers.
- Oversized fields.
- Malformed scalars and points.
- Unknown critical fields.
- Golden valid vectors.
- Golden reject vectors.

### 9.2 Envelope Guard and Transport Boundary

Tests must cover (using table-driven grouping where practical):

- Wrong protocol.
- Wrong version.
- Wrong session.
- Wrong round.
- Wrong sender.
- Unknown sender.
- Sender not in party set.
- Authenticated transport party mismatch.
- Direct message accepted as broadcast.
- Broadcast message accepted as direct.
- Missing confidentiality for secret-bearing message.
- Unexpected confidentiality for public message if policy forbids it.
- Missing or invalid broadcast certificate.
- Wrong transcript hash.
- Replay.
- Equivocation.

### 9.3 Protocol State Machines

Protocol tests must cover:

- Round transitions are monotonic.
- Early messages do not advance state.
- Duplicate messages do not advance state.
- Equivocated messages produce deterministic rejection.
- Valid payloads in wrong rounds are rejected.
- Messages from non-signers or removed parties are rejected.
- Buffered messages are revalidated before use.
- Threshold, signer-set, committee-set, and reshare-plan checks happen before emitting the next round.

### 9.4 Domain Separation

Tests must verify that proofs, commitments, transcript hashes, and signature shares do not verify under the wrong:

- Protocol.
- Version.
- Session.
- Round.
- Sender.
- Recipient.
- Party set.
- Signer set.
- Threshold.
- Public key.
- Digest.
- BIP32 path.
- Presign context.

### 9.5 CGGMP21 Presign Safety

Tests must verify:

- Presign is exactly-once.
- Same presign cannot sign two digests.
- Same presign cannot sign the same digest twice.
- Same presign cannot be reused across sessions.
- Same presign cannot be reused across signer sets.
- Same presign cannot be reused across BIP32 paths.
- Concurrent use allows at most one success.
- Consumed state survives marshal/unmarshal.
- Consumed state survives encrypt/decrypt.
- Shallow copy cannot bypass consumed state.
- Restart-style reload cannot revive consumed presign.
- If a partial signature is emitted or could have been observed externally, the presign is consumed.

### 9.6 Refresh and Reshare

Tests must verify:

- Refresh preserves the group public key.
- Reshare preserves the group public key unless a documented protocol rule says otherwise.
- Old and new committees cannot be mixed.
- Removed parties cannot participate after reshare completion.
- New parties cannot act before reshare completion.
- Failed or interrupted refresh/reshare does not leave two inconsistent usable shares.

### 9.7 Blame Evidence

Tests must verify:

- Evidence is deterministic.
- Evidence is public-only.
- Invalid commitments blame the responsible sender when possible.
- Invalid proofs blame the responsible sender when possible.
- Invalid signature shares blame the responsible sender when possible.
- Equivocation blames the equivocated sender.
- Replay does not incorrectly blame the original honest sender as a cryptographic violator.
- Transport-authentication failures are not mislabeled as cryptographic blame.
- Local storage corruption is not mislabeled as remote-party blame.

### 9.8 Copy Safety and Redaction

Tests must verify:

- Byte accessors return copies, not mutable internal buffers.
- Commitment and public-key accessors return copies or immutable values.
- Key share, presign, secret scalar, Paillier private material, and proof objects do not leak secret material through `String`, `GoString`, JSON, logs, errors, or failure messages.

Recommended copy-safety pattern:

```go
func TestKeyShare_AccessorsReturnCopies(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name string
        get  func(*KeyShare) []byte
    }{
        {name: "chain code", get: (*KeyShare).ChainCodeBytes},
        {name: "transcript hash", get: (*KeyShare).KeygenTranscriptHashBytes},
    }

    share := makeTestKeyShare(t)

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()

            got := tc.get(share)
            if len(got) == 0 {
                t.Fatal("empty accessor result")
            }
            got[0] ^= 0xff

            again := tc.get(share)
            if bytes.Equal(got, again) {
                t.Fatalf("%s returned mutable internal buffer", tc.name)
            }
        })
    }
}
```

## 10. Coverage Gap Workstream

Coverage work must focus on security-significant gaps, not global percentage vanity.

### 10.1 Root Package

Add or rewrite table-driven tests for:

- Guard builder behavior.
- Policy binding.
- Session and party validation.
- Envelope opening and validation limits.
- Marshal/unmarshal with limits.
- Broadcast full verification.
- Bounded replay-cache creation, check/store, duplicate detection, equivocation detection, and eviction.
- Party sorting, containment, and boundary values.

### 10.2 FROST Ed25519

Add or rewrite tests for:

- Guard construction and policy/session/party binding.
- Ack verification error paths.
- KeyShare string, JSON, and formatting redaction.
- Default and threshold limit failures.
- Chain code copy safety.
- HD derivation edge cases.
- Lifecycle state rejection paths.

### 10.3 CGGMP21 secp256k1

Add or rewrite tests for:

- Invalid `StartReshare` parameter paths.
- Presign consume lifecycle, including double consume, wrong session, concurrent consume, shallow copy, and reload.
- Result/Complete behavior in not-done, aborted, and destroyed states.
- Group commitment copy safety.
- Share proof copy safety.
- Chain code copy safety.
- Keygen transcript hash stability.
- KeyShare redaction through formatting and JSON.

### 10.4 Paillier and MtA

Add or rewrite tests for:

- Encryption with explicit randomness and deterministic test vectors.
- Invalid randomness rejection.
- Bit-size validation boundaries.
- Post-unmarshal consistency for `N`, `N²`, and `G`.
- JSON/string redaction for private material.
- MtA relation correctness and invalid relation rejection.

### 10.5 ZK Paillier

Add or rewrite tests for:

- Random sampling helper ranges.
- `ExpSignedMod`, `ExpSignedModCT`, and `MultiExpSignedMod` correctness against a public non-constant-time reference where safe.
- Ring-Pedersen commitment algebraic relation verification.
- Proof verification under wrong domain parameters.
- Malformed proof rejection.

### 10.6 Benchmark Organization

Benchmarks should be split by cost category (offline, online, verification, serialization, primitive) rather than collected in a single file per package. Recommended organization:

**Per-package benchmark files:**

```text
cggmp21/secp256k1/
  benchmark_keygen_test.go
  benchmark_presign_test.go
  benchmark_sign_test.go
  benchmark_wire_test.go

frost/ed25519/
  benchmark_keygen_test.go
  benchmark_sign_test.go

internal/paillier/
  benchmark_test.go

internal/zk/paillier/
  benchmark_test.go
```

**Benchmark naming should encode the cost category:**

```go
// Offline cost: pre-compute before signing.
func BenchmarkCGGMP21Keygen3of5(b *testing.B)
func BenchmarkCGGMP21Presign3of5(b *testing.B)

// Online latency: interactive signing path.
func BenchmarkCGGMP21OnlineSign3of5(b *testing.B)
func BenchmarkFROSTSign3of5(b *testing.B)

// Verification cost: proof verification, partial verification.
func BenchmarkZKProofVerify(b *testing.B)

// Serialization cost: envelope encode/decode.
func BenchmarkWireMarshalEnvelope(b *testing.B)
```

Online signing latency matters more for TSS engineering than total keygen or presign cost, because signing is interactive. Benchmarks must use reduced parameters unless explicitly behind a `slowcrypto` or `benchmark` build tag.

## 11. Production-Code Change Policy

Tests may reveal that the current production code does not satisfy the desired invariant. In that case, fix production code rather than weakening the test.

### 11.1 Required Fixes

Production code must be changed if tests show:

- Non-canonical wire encodings are accepted.
- Wrong session, protocol, round, sender, recipient, signer set, or threshold is accepted.
- Presign can be reused.
- Presign consumed state can be bypassed by copy or serialization.
- Secret material appears in string, JSON, logs, errors, or blame evidence.
- Accessors expose mutable internal buffers.
- Domain separation is incomplete.
- Replay or equivocation is not detected.
- Invalid proof or signature share advances protocol state.
- Crash/reload behavior can revive unsafe material.

### 11.2 Fix Boundaries

Production fixes should be minimal and security-preserving:

- Prefer stricter validation over permissive compatibility.
- Prefer unexported helpers over public API expansion.
- Prefer fail-closed errors over best-effort recovery.
- Do not add broad fallback decoding.
- Do not weaken proof verification to satisfy old tests.
- Do not log secrets to improve test diagnostics.

### 11.3 Documentation Updates

If production behavior changes, update relevant documentation:

- `docs/testing-rules.md` if testing policy changes.
- Protocol or API docs if public behavior changes.
- Examples if public API usage changes.
- Golden vector notes if wire behavior changes.

## 12. Migration Phases

### Phase 0: Inventory and Baseline

Deliverables:

- List all test files, top-level tests, subtests, build tags, and approximate runtime.
- Identify tests that are pure unit, reduced crypto, integration, slowcrypto, stress, fuzz, or obsolete.
- Record current short-test and fast-test wall-clock time.
- Record package-level coverage for root, `internal/wire`, FROST, CGGMP21, Paillier, MtA, and ZK packages.

Acceptance:

- A test inventory exists.
- The refactor has a baseline for runtime and coverage comparisons.
- Slow or flaky tests are labeled before rewriting begins.

### Phase 1: Harness and Conventions

Deliverables:

- Add or consolidate deterministic RNG helpers.
- Add party/session factory helpers.
- Add envelope mutation helpers.
- Add state snapshot helpers.
- Add copy-safety assertion helpers.
- Add integration semaphore helper.
- Add fixture-cache helpers for immutable expensive fixtures.

Acceptance:

- New tests can be written without each package inventing its own setup machinery.
- Harness helpers do not import protocol packages in a way that creates cycles.
- Helpers are deterministic and parallel-safe.

### Phase 2: Low-Risk Parallelization

Deliverables:

- Add `t.Parallel()` to low-risk pure unit tests.
- Group related test cases into table-driven tests for root, wire, secret, Shamir, BIP32, and curve packages where it improves clarity.
- Update Makefile test concurrency knobs.

Acceptance:

- `go test -short -parallel 8 -p 4 -count=1 ./...` passes repeatedly.
- Race detector passes on packages where it is practical.
- No test relies on ordering or shared mutable fixtures.

### Phase 3: Root and Wire Rewrite

Deliverables:

- Rewrite `internal/wire` tests around canonical, limits, mutation, golden, and fuzz categories.
- Rewrite root guard/envelope/replay/broadcast/evidence tests with table-driven grouping around invariants.
- Add reject-path side-effect assertions.

Acceptance:

- `internal/wire` has strict accept/reject coverage.
- Guard tests cover transport identity, direct/broadcast mode, confidentiality, replay, equivocation, and transcript mismatch.
- Golden valid and reject vectors are treated as compatibility contracts.

### Phase 4: FROST Rewrite

Deliverables:

- Rewrite FROST encoding, HD, lifecycle, guard, keygen, sign, refresh, reshare, and vector tests.
- Apply `t.Parallel()` where safe.
- Group invalid-parameter, wrong-round, wrong-sender, and domain-error cases where the setup is shared.

Acceptance:

- FROST happy paths are covered by a small number of lifecycle integration tests.
- FROST reject paths assert no unsafe state advancement, with related cases grouped where practical.
- Redaction and copy-safety tests exist for public accessors and key-share formatting.

### Phase 5: CGGMP21 Presign and Sign Rewrite

Deliverables:

- Rewrite presign lifecycle tests around exactly-once safety.
- Add concurrent consume tests.
- Add serialization, encryption, shallow-copy, restart-style reload, BIP32 path, signer-set, and digest reuse tests.
- Rewrite sign tests with grouped invalid-input cases and side-effect assertions.

Acceptance:

- Presign reuse is impossible across digest, session, signer set, BIP32 path, serialization, copy, restart, and concurrency scenarios.
- Bad sign inputs do not emit partial signatures.
- If a partial signature could be externally observed, presign is consumed.

### Phase 6: CGGMP21 Keygen, Refresh, Reshare Rewrite

Deliverables:

- Rewrite keygen validation and confirmation tests.
- Rewrite refresh tests for public-key preservation and interrupted-state behavior.
- Rewrite reshare tests for old/new committee separation and removed/new party behavior.
- Add reshare-plan invalid-parameter matrix.

Acceptance:

- Old and new committees cannot be mixed.
- Removed parties are rejected after reshare completion.
- New parties cannot act before reshare completion.
- Failed refresh/reshare does not create two usable inconsistent shares.

### Phase 7: Paillier, MtA, and ZK Rewrite

Deliverables:

- Add or rewrite tests for Paillier encryption/decryption, randomness, bit boundaries, unmarshal consistency, and redaction.
- Add fixture caching for reduced Paillier keys where safe.
- Add MtA relation tests.
- Add ZK helper, proof, domain, malformed proof, and algebraic relation tests.

Acceptance:

- Reduced-parameter crypto tests are fast enough for Tier 1.
- Production-parameter tests are narrow and behind `slowcrypto`.
- Secret-exponent and private-material paths do not leak through tests or diagnostics.

### Phase 8: Coverage, Fuzz, Stress, and Cleanup

Deliverables:

- Split coverage targets by cost.
- Seed fuzz corpus with golden and regression cases.
- Add fuzz smoke target for wire and proof parsers.
- Remove obsolete, duplicate, and low-value tests.
- Update `docs/testing-rules.md` if final conventions differ from this plan.

Acceptance:

- Short and fast test runtime improves versus baseline.
- Security-critical coverage improves in root, wire, FROST, CGGMP21, Paillier, MtA, and ZK packages.
- CI uses fast tests by default and expensive tests intentionally.
- Test suite structure follows the invariant-driven rules and uses table-driven grouping where beneficial.

## 13. Verification Strategy

After each phase, run the smallest meaningful verification set.

Phase 1 and Phase 2:

```sh
go test -short -parallel 8 -p 4 -count=1 ./...
go test -short -parallel 8 -p 4 -count=1 ./...
```

Phase 3 and Phase 4:

```sh
go test -short -timeout 1m ./...
go test -timeout 5m ./...
```

Phase 5 and Phase 6:

```sh
go test -tags=integration -p 2 -parallel 2 -timeout 20m ./...
go test -race -tags=integration -p 2 -parallel 2 -timeout 1h ./cggmp21/secp256k1 ./frost/ed25519
```

Phase 7:

```sh
go test -timeout 5m ./internal/paillier ./internal/mta ./internal/zk/...
go test -tags=slowcrypto -timeout 1h ./internal/paillier ./internal/zk/...
```

Phase 8:

```sh
go test -short -coverprofile=coverage.unit.out -covermode=atomic ./...
go test -tags=integration -coverprofile=coverage.integration.out -covermode=atomic ./...
go test -run=^$ -fuzz=. -fuzztime=10s ./internal/wire ./internal/zk/...
```

Before considering the refactor complete, run the repository’s standard CI target and record before/after runtime and coverage.

## 14. Review Checklist

Each PR in the refactor should answer these questions:

- Do tests use table-driven grouping where it improves clarity?
- Are related cases grouped instead of scattered?
- Are subtest loop variables captured before parallel subtests?
- Is `t.Parallel()` used only where state isolation is clear?
- Do reject-path tests assert side effects, not just errors?
- Are expensive tests behind the correct build tag?
- Are fixtures immutable, cloned, and safely cached?
- Are presigns, nonces, and session states never shared accidentally?
- Did any test expose a production-code flaw?
- If production code changed, was the change minimal and fail-closed?
- Were obsolete or weaker duplicate tests removed?
- Are errors, logs, string formats, JSON, and blame evidence free of secret material?
- Are docs and golden vectors updated when behavior changes?

## 15. Definition of Done

The test refactor is complete when:

1. The main test suite uses table-driven grouping where beneficial and is invariant-driven.
2. Related cases for the same production function or invariant are grouped in the same test function or clearly justified behavior-family split.
3. Low-risk unit tests use safe intra-package parallelism.
4. Heavy integration tests use bounded concurrency and cached immutable fixtures where safe.
5. CGGMP21 presign exactly-once safety is covered across concurrency, serialization, copy, restart, digest, signer-set, session, and BIP32 scenarios.
6. Wire encoding tests enforce strict canonical accept/reject behavior.
7. Guard tests cover transport identity, direct/broadcast mode, confidentiality, replay, equivocation, and transcript binding.
8. Domain separation tests prevent cross-session, cross-round, cross-protocol, cross-recipient, cross-signer-set, and cross-BIP32 reuse.
9. Redaction and copy-safety tests cover secret-bearing and accessor APIs.
10. Obsolete, duplicated, flaky, and non-conforming tests have been deleted or rewritten.
11. Short and fast test runtime is measurably better than the baseline.
12. Documentation reflects the final testing rules and any production-code behavior changes.

## 16. Harness-First Rewrite Plan (6 PRs)

This is a complementary rewrite strategy to the 8-phase migration plan in Section 12. It focuses on building `internal/testharness/` first, then rewriting tests protocol-by-protocol on top of unified harnesses.

### PR 1: Establish testharness (no protocol changes)

Add `internal/testharness/` with the six core harnesses:

```text
internal/testharness/rng.go        — deterministic RNG + TSS_TEST_SEED
internal/testharness/parties.go    — party/session factory helpers
internal/testharness/network.go    — Network fault simulator
internal/testharness/mutation.go   — envelope mutation library
internal/testharness/assert.go     — state snapshot + fail-closed assertions
```

Also add `internal/testvectors/` directory skeleton and `testdata/golden/` with versioned subdirectories.

### PR 2: Rewrite root + wire tests

Highest leverage — these are the foundation every protocol depends on:

```text
internal/wire/*         — canonical, limits, golden, fuzz, mutation matrices
envelope_test.go        — marshal/unmarshal, limits, round-trip
guard_test.go           — full 17-scenario EnvelopeGuard matrix
replay_test.go          — duplicate, equivocation, eviction
broadcast_test.go       — commit, ack, equivocation
evidence_test.go        — blame marshal, verify, tamper resistance
storage_test.go         — encrypt/decrypt round-trip, tamper resistance
```

### PR 3: Rewrite FROST tests

FROST is simpler than CGGMP21 — use it to validate the harness design:

```text
unit_encoding_test.go        — wire format, keyshare marshal/unmarshal
invariant_guard_test.go      — fail-closed matrix via mutation library
invariant_state_test.go      — state machine monotonicity
integration_keygen_test.go   — happy path (one per threshold/party combo)
integration_sign_test.go     — happy path + reject paths
integration_reshare_test.go  — committee transitions
vectors_test.go              — RFC 9591 compliance
```

### PR 4: Rewrite CGGMP21 presign + sign tests

Highest risk area — presign exactly-once must be bulletproof:

```text
invariant_presign_test.go    — exactly-once: concurrent, marshal, encrypt, shallow copy, crash reload
invariant_domain_test.go     — domain separation across all proof types
invariant_blame_test.go      — blame accuracy matrix
integration_presign_test.go  — happy path + adversary cases
integration_sign_test.go     — happy path + reject paths + BIP32 binding
```

### PR 5: Rewrite CGGMP21 keygen + refresh + reshare tests

```text
unit_encoding_test.go        — keyshare wire format, redaction, copy safety
invariant_guard_test.go      — fail-closed matrix
invariant_state_test.go      — state machine, scheduling, committee transitions
integration_keygen_test.go   — happy path + confirmation
integration_refresh_test.go  — epoch transition, public key preservation
integration_reshare_test.go  — membership changes, removed party rejection
slowcrypto_test.go           — production-parameter smoke
```

### PR 6: Rebuild CI / coverage / fuzz / slowcrypto

```text
Makefile              — tiered targets with explicit build tags
GitHub Actions        — fast PR checks + nightly integration + weekly stress
coverage thresholds   — per-area enforcement
fuzz corpus           — seeded from golden + regression cases
test budget           — runtime checker integrated into CI
```

After PR 6, adding a new protocol or round requires only implementing the `ProtocolCase` interface and registering it with the shared harnesses — most adversarial tests are inherited automatically.

_Last updated: 2026-06-12 (testing-rules.md enhanced + .agents/test.md integration + new work items 20–25)_

### Completed

#### Phase 0: Inventory and Baseline ✅

- All 848 test functions across ~100 test files inventoried.
- Build tags (`integration`, `slowcrypto`, `vectorgen`, `stress`) documented per file.
- Makefile concurrency knobs (`PKG_PARALLEL`, `TEST_PARALLEL`, `INTEGRATION_PARALLEL`) in place.
- ~~Integration semaphore (`runLimitedIntegration`) implemented in `cggmp21/secp256k1`.~~ **Removed**: tested and found to slow down tests; Go's `-p`/`-parallel` flags provide sufficient throttling.

#### Phase 1: Harness and Conventions ✅

- `internal/testutil` provides: deterministic reader (`DeterministicReader`), session IDs (`MustSessionID`), party sets (`MustPartySet`), envelope delivery (`MustDeliverAll`), byte mutation (`MutateBytes`), protocol error assertions (`AssertProtocolError`), hex decoding (`MustDecodeHex`), zero-byte checks (`IsZeroBytes`), clone helpers (`CloneByteSlices`), big.Int and byte clearing assertions (`AssertBigIntCleared`, `AssertBytesCleared`, `AssertMapCleared`), wire field rewriting (`RewriteWireField`, `RewriteNestedWireField`), and deterministic round-trip assertions (`AssertDeterministicRoundTrip`).
- ~~Integration semaphore helper in `cggmp21/secp256k1`: `runLimitedIntegration` with `chan struct{}{2}`.~~ **Removed** (2026-06-11): channel semaphore on top of `t.Parallel()` created double-gating that slowed tests down instead of speeding them up.
- Fixture caching: ZK paillier tests have `testPaillierKeyCache sync.Map` for Paillier key reuse.

#### Phase 2: Low-Risk Parallelization ✅ (substantially complete)

- `t.Parallel()` added to 600+ test functions across low-risk packages:
  - `internal/wire` (137 parallel tests)
  - `frost/ed25519` (86 parallel tests)
  - `cggmp21/secp256k1` tier0 (90 parallel tests — +18 from `hd_test.go` 2026-06-11 late evening; 3 tests modifying `hmacSHA512` intentionally sequential)
  - `internal/shamir` (27 table-driven tests, consolidated from 43; all parallel)
  - `internal/shamir` further improvement (2026-06-11 final): `TestEvalKnownPolynomial` and `TestLagrangeCoefficientReconstructs` converted from `t.Fatalf`-in-loop to proper `t.Run()` subtests with named cases.
  - `internal/paillier` (27 parallel tests)
  - `internal/bip32util` (25 parallel tests)
  - `internal/curve/secp256k1` (19 parallel tests)
  - `internal/mta` (27 parallel tests — finish, response, start; `mta_test.go` intentionally kept sequential due to `SetSecurityParamsForTesting`)
  - `internal/zk/paillier` (20+ files updated — pure unit tests and Tier 1 proof tests; `relation_audit_test.go` 12 tests parallel 2026-06-11 late evening)
  - `internal/zk/signprep` (12 parallel tests)
  - `internal/zk/schnorr` (11 parallel tests)
  - `internal/secret` (10 parallel tests)
  - `internal/curve/edwards25519` (8 parallel tests)
  - `internal/paillier/paillierct` (8 parallel tests)
  - Root package: `broadcast_test.go` (27), `guard_test.go` (29), `storage_test.go` (20), `limits_test.go` (15), `config_test.go` (12), `replay_test.go` (10), `errors_test.go` (7), `evidence_test.go` (8), `transport_test.go` (5), `slog_test.go` (4)
- Makefile targets use `-parallel $(TEST_PARALLEL)` and `-p $(PKG_PARALLEL)`.

#### Phase 3: Root and Wire Rewrite ✅ (largely complete)

- `internal/wire` tests organized across: `message_test.go`, `fields_test.go`, `validate_test.go`, `limits_test.go`, `record_test.go`, `records_test.go`, `stream_test.go`, `primitives_test.go`, `envelope_test.go`, `hash_test.go`.
- Root package tests organized by concern: `guard_test.go`, `envelope_test.go`, `replay_test.go`, `broadcast_test.go`, `evidence_test.go`, `storage_test.go`, `config_test.go`, `errors_test.go`, `limits_test.go`, `transport_test.go`, `golden_test.go`, `slog_test.go`.
- Table-driven reject-path and accept-path matrices present in guard, envelope, wire encoding, replay, broadcast, evidence, and config tests.
- Golden valid and reject vectors (`golden_test.go` files) provide wire compatibility contracts.

#### Phase 4: FROST Rewrite ✅ (largely complete)

- FROST tests organized across: `encoding_test.go`, `frost_test.go`, `sign_test.go`, `hd_test.go`, `lifecycle_test.go`, `keygen_confirm_test.go`, `reshare_test.go`, `rfc9591_test.go`, `golden_test.go`, `vector_test.go`, `guard_integration_test.go`.
- Redaction and copy-safety tests: `TestFROSTKeyShareFormatRedacts`, `TestFROSTKeyShareChainCodeBytesReturnsCopy`, `TestFROSTKeySharePublicKeyBytesReturnsCopy`, `TestFROSTKeyShareCloneIsDeepCopy`, `TestFROSTKeyShareStringAndGoStringDoNotLeak`.
- Guard integration tests behind `integration` build tag.
- RFC 9591 vector compliance tests in `rfc9591_test.go`.

#### Phase 5/6: CGGMP21 Rewrite ✅ (substantially complete)

- Tier 0 tests: `tier0_encoding_test.go`, `tier0_golden_test.go`, `tier0_fuzz_test.go`, `tier0_regression_test.go` with `t.Parallel()`.
- Integration tests behind `integration` build tag: `integration_keygen_test.go`, `integration_presign_test.go`, `integration_sign_test.go`, `integration_refresh_test.go`, `integration_reshare_test.go`, `integration_hd_test.go`, `integration_adversary_test.go`.
- **2026-06-11 table-driven consolidation**:
  - `integration_reshare_test.go`: 4 membership-change tests consolidated into `TestThresholdECDSAReshareMembershipChange` (table-driven with "add party", "remove party", "threshold increase", "disjoint dealer subset" cases).
  - `integration_adversary_test.go`: 5 online-signing tamper tests consolidated into `TestIntegration_SignPartialTamperingBlamesSender` (table-driven with 5 mutation cases) + extracted `assertSignPartialBlamesOnlySender` helper. 4 presign round3 tamper tests consolidated into `TestIntegration_PresignRound3TamperingBlamesSender` (table-driven with 4 cases) + extracted `runPresignRound3TamperTest` helper. Removed 2 redundant standalone tests (`TestIntegration_TamperedSProducesEquationFailure`, `TestIntegration_TamperedPartialEquationHashAloneBlamesSender`).
  - `integration_refresh_test.go`: 2 multi-party refresh flow tests consolidated into `TestThresholdECDSAProactiveRefreshScenarios` (table-driven with "2-of-3 non-HD" and "2-of-2 HD preserves chain code" cases) + extracted `runRefresh` helper.
- Presign safety tests: `TestThresholdECDSA_PresignRejectReuse`, `TestThresholdECDSA_PresignConsumedRoundTrip`, `TestCGGMP21SignRejectsBadDigestAndPresignReuseBeforeOutbound`, `TestPresignCannotBeReusedAcrossDerivedPaths`, `TestPresignContextRejectsReuseAcrossBoundDomains`.
- Domain separation tests: `domain_test.go`, `TestCGGMP21KeyShareProofDomainBindsContext`, `TestCGGMP21MTADomainsBindPresignContext`.
- State transition tests: `state_transition_test.go`, `lifecycle_test.go`.
- Blame evidence tests: `TestBlameEvidenceDoesNotNameSecretFields`, `TestBlameEvidenceField`, `TestBlameEvidenceMarshalDeterministic`, adversary tests.
- HD derivation tests: `hd_test.go` with multi-level, chain code, and accessor copy safety.
- Reshare plan validation: `reshare_plan_test.go` with table-driven invalid parameter matrices.
- Scheduler tests: `scheduler_test.go`.

#### Phase 7: Paillier, MtA, and ZK Rewrite ✅ (substantially complete)

- **ZK Paillier (2026-06-11 update)**: `t.Parallel()` added to all pure unit tests and Tier 1 proof tests:
  - `unit_test.go`: `TestIntegerEncodingCanonical`, `TestIntegerRangeChecks`, `TestGroupMembershipChecks`, `TestRingPedersenParamsValidation`, `TestSecurityParamsValidationAndBindingValues`, `TestTranscriptDomainSeparation`.
  - `proofs_test.go`: `TestProofMarshalCanonicalBinary`, `TestProofRejectsNonCanonicalAndMalformedInputs`, `TestNewProofUnmarshalRejectsNonCanonicalPositiveIntegers`.
  - `new_proofs_test.go`: `TestEncProofVerificationMatrix`, `TestEncProofSpecialSoundness`, `TestAffGProofRelationCompleteness`, `TestLogStarProofRelationCompleteness`, etc.
  - `ring_pedersen_test.go`: `TestRingPedersenProofChecks`.
  - `modulus_test.go`: `TestModulusProofCGGMP24Checks`.
  - `encryption_test.go`: `TestEncryptionProofTamper`.
  - `legacy_proofs_test.go`: `TestLegacyLogProofTamper`, `TestLegacyProofWireTypesAreSeparated`.
  - `relation_audit_test.go`: `TestEncProofRelationCompleteness`, `TestAffGProofRelationCompleteness`.
  - `params_consistency_test.go`: `TestDefaultSecurityParamsValues`, `TestEncRangeFormula`, `TestEncRangeStatisticalHiding`, `TestChallengeBitsDoNotExceedHashOutput`, `TestTranscriptBindsAllSecurityParams`, `TestFastSecurityParamsSanity`, `TestSecurityParamsValidate`, `TestEllPrimeExceedsEll`.
  - `adversarial_test.go`, `leakage_test.go`, `challenge_*_test.go`, `extractor_test.go`, `range_boundary_test.go`, `mta_response_test.go`: Retain existing structure; tests that mutate package-level `activeSecurityParams` via `SetSecurityParamsForTesting` intentionally kept sequential.
- **2026-06-11 additional parallelism**: `t.Parallel()` added to 8 more ZK paillier test files that were previously sequential but have no package-global mutation: `mta_response_test.go` (1), `new_proofs_test.go` (5), `adversarial_test.go` (13), `extractor_test.go` (7), `range_boundary_test.go` (8), `challenge_hash_test.go` (4), `challenge_zero_test.go` (4), `golden_test.go` (1). Total 43 additional parallel test functions.
- **MTA**: Tier 0 helper tests (`helpers_test.go`) already use `t.Parallel()` with table-driven patterns. Tier 1 tests (`finish_test.go`, `mta_test.go`) intentionally kept sequential due to package-global `SetSecurityParamsForTesting` mutations.
- **Paillier internals**: `crypto_test.go`, `encoding_test.go`, `keygen_test.go`, `paillier_test.go`, `paillierct_test.go` all have `t.Parallel()` for safe tests.
- Fixture caching via `testPaillierKeyCache sync.Map` with `sync.Map.LoadOrStore` to avoid duplicate keygen.

#### Phase 8: Progress (2026-06-11)

Coverage baseline, test audit, duplicated helper consolidation, slowcrypto review, and race detector pass completed.

**Coverage baseline recorded:**

| Package                        | Unit (short) | Integration |
| ------------------------------ | ------------ | ----------- |
| `tss` (root)                   | 77.7%        | 77.7%       |
| `cggmp21/secp256k1`            | 16.0%        | 74.9%       |
| `frost/ed25519`                | 75.3%        | 75.3%       |
| `internal/bip32util`           | 98.6%        | 98.6%       |
| `internal/curve/edwards25519`  | 64.4%        | 64.4%       |
| `internal/curve/secp256k1`     | 90.4%        | 90.4%       |
| `internal/mta`                 | 86.2%        | 92.4%       |
| `internal/paillier`            | 76.3%        | 82.5%       |
| `internal/paillier/paillierct` | 80.8%        | 80.8%       |
| `internal/secret`              | 78.8%        | 78.8%       |
| `internal/shamir`              | 94.6%        | 94.6%       |
| `internal/wire`                | 78.8%        | 78.8%       |
| `internal/wire/wireutil`       | 100.0%       | 100.0%      |
| `internal/zk/paillier`         | 23.4%        | 78.2%       |
| `internal/zk/schnorr`          | 92.6%        | 92.6%       |
| `internal/zk/signprep`         | 76.1%        | 76.1%       |

**Race detector pass:** All packages pass `make test-race` with no race conditions detected.

**Obsolete/duplicate test cleanup:**

- Deleted `TestInterpolateConstantLegacy` (byte-for-byte duplicate of `TestInterpolateConstant`).
- Deleted `TestLagrangeRejectsDuplicate` (duplicate of `TestLagrangeCoefficientDuplicateInSet`).
- Deleted `TestEncRangeDoesNotOverflow` (redundant — big.Int handles arbitrary-precision; the constants are already verified by other tests).
- Fixed no-op `TestModulusProofRejectsEvenModulus` (had zero assertions; now documents the limitation clearly).
- Fixed missing assertion in `TestCheckPaillierModulus` (was logging "correctly rejected" without actually asserting rejection).
- Moved `TestXCoordinateRecoveryIsConsistent` from `internal/zk/paillier/adversarial_test.go` to `internal/curve/secp256k1/secp256k1_test.go` as `TestPointEncodingRoundTrip` (table-driven).
- Moved `TestProofsUseV1Version` from `leakage_test.go` to `new_proofs_test.go`.
- Moved `TestChallengeLabelsV1` from `leakage_test.go` to `unit_test.go` (with `t.Parallel()`).

**Duplicated test helper consolidation:**

- Replaced 4 local `assertPayloadRemarshals[P any]` definitions (frost/ed25519, mta, zk/schnorr, paillier) with `testutil.AssertDeterministicRoundTrip`.
- Replaced local `allZeroBytes` in frost/ed25519/lifecycle_test.go with `testutil.IsZeroBytes`.

**Slowcrypto test scope review:**

- Confirmed `slowcrypto_test.go` is a narrow smoke test (1 proof per type), not an exhaustive matrix.
- Confirmed `challenge_distribution_test.go` tests are statistical Fiat-Shamir analysis, correctly behind `slowcrypto`.
- Identified 4 lightweight challenge distribution tests that were moved out of `slowcrypto` build tag into new `challenge_hash_test.go` (no build constraint), giving normal CI builds coverage of challenge entropy, modular bias, legacy distribution, and cross-session uniqueness.
- Confirmed the remaining 5 tests in `challenge_distribution_test.go` correctly stay behind `slowcrypto` (require 3072-bit Paillier key generation).

**DeliverEnvelope helper consolidation:**

- Added `testutil.DeliverEnvelope` to centralize the envelope transport-authentication pattern.
- Replaced 77+ call sites across 20 files (frost/ed25519 and cggmp21/secp256k1).
- Removed local `deliverEnv`/`deliverCGGMPEnv` definitions.

**CheckGolden helper consolidation:**

- Added `testutil.CheckGolden` with `UPDATE_GOLDEN=1` environment support and parent-directory creation.
- Replaced 3 local definitions: `checkGolden` (frost, cggmp21) and `checkPaillierGolden` (zk/paillier).
- Replaced 11+ call sites across golden test files.

**Full CI verification:** `make ci` passes (build, vet, golangci-lint, fmt-check, tidy-check, verify, test-fast).

**CGGMP21 integration fixture caching (2026-06-11):**

- Extended `fixtureKey` to include `enableHD bool` to distinguish HD vs non-HD keygen fixtures.
- Added exported `CachedKeygenShares(t, threshold, n, enableHD)` — returns deep-cloned shares from cache, generates fresh keygen via `sync.Once` on first use per key tuple.
- Replaced 85+ `secpKeygen`/`secpKeygenWithOptions` calls across 15 test files with cached variant.
- Integration test time reduced from ~401s → ~215s (46% improvement).
- Caching is safe: every caller receives independently cloned shares; cache entries are immutable after `sync.Once` completes.

**FROST fixture caching (2026-06-11):**

- Added `frostFixtureKey{threshold, n, hd}` and `frostKeygenFixtureCache sync.Map` in `frost_test.go`.
- `frostKeygen` and `frostKeygenHD` now delegate to `cachedFrostKeygen(t, threshold, n, hd)` which uses `sync.Once` per key tuple.
- Inner DKG logic extracted to `frostKeygenInner` and `frostKeygenHDInner` (uncached, shared across cache wrappers).
- All callers receive deep-cloned shares via `cloneFrostKeyShareMap`.

**Fuzz corpus analysis (2026-06-11):**

- Inventoried all 48 fuzz targets across 13 files with their seed coverage.
- Identified 21 golden vector files that could potentially serve as fuzz seeds.
- Discovered golden files use TLV-wrapped wire format incompatible with individual payload fuzz targets (which expect raw payload binary without version/type headers).
- All fuzz targets already have programmatic seeds via `f.Add()` providing good coverage.
- Fuzz CI script lacks `-tags=integration` flag, causing 10 integration-tagged fuzz targets to be silently skipped in CI (documented as known limitation).

**Table-driven consolidation (2026-06-11 evening):**

- **`integration_reshare_test.go`**: 4 membership-change tests (add/remove/threshold/disjoint) → single `TestThresholdECDSAReshareMembershipChange` with 4 table cases. Added `collectShares` helper.
- **`integration_adversary_test.go`**: 5 online-signing tamper tests → `TestIntegration_SignPartialTamperingBlamesSender` with 5 mutation cases + `assertSignPartialBlamesOnlySender` helper. 4 presign round3 tamper tests → `TestIntegration_PresignRound3TamperingBlamesSender` with 4 cases + `runPresignRound3TamperTest` helper. Removed 2 redundant standalone tests.
- **`integration_refresh_test.go`**: 2 multi-party flow tests → `TestThresholdECDSAProactiveRefreshScenarios` with 2 cases + `runRefresh` helper.
- **`integration_presign_test.go`**: 2 round-trip tests → `TestThresholdECDSA_PresignRoundTripScenarios` (fresh + consumed).
- **`keygen_confirm_test.go`**: 7 standalone tests → 2 table-driven tests (`TestKeygenConfirmationRejectsTamperedFields` 3 cases, `TestKeygenConfirmationRejectsInvalidSenderSets` 4 cases).
- **`frost/ed25519/encoding_test.go`**: Removed duplicated `cloneFROSTKeyShare` (→ `KeyShare.Clone()`) and `rewriteFROSTWireField` (→ `testutil.RewriteWireField`).
- **ZK paillier parallelism**: Added `t.Parallel()` to 46 test functions across 9 files that were safe for parallelism (no package-global mutation).
- **MTA parallelism (evening)**: Added `t.Parallel()` to 11 test functions in `finish_test.go` (2), `response_test.go` (5), `start_test.go` (4). Verified safe: no `SetSecurityParamsForTesting` calls, no environment dependencies. `mta_test.go` (1 test) correctly kept sequential due to global security params mutation.
- **Helper audit (evening)**: Audited `assertProtocolErrorCode` vs `testutil.AssertProtocolError` — both are small (~10 lines), unification would require changing 36+ call sites, deferred as low-ROI. Confirmed `cloneFROSTKeyShare` and `rewriteFROSTWireField` already removed in favor of `KeyShare.Clone()` and `testutil.RewriteWireField`.
  - **Dead testutil helpers identified (final evening)**: `AssertDeterministicRoundTrip`, `MutateBytes`, and `AssertProtocolError` have zero callers outside `internal/testutil`. These were created during Phase 1 harness work but never adopted — existing tests use inline assertions for deterministic round-trips and error checking. Intentionally kept for future use.
  - **Presign reuse consolidation (final evening)**: `TestThresholdECDSAPresignReuseRejected` (same-session reuse) + `TestThresholdECDSA_PresignRejectReuse` (cross-session, `ErrCodeConsumed`) → merged into single 3-case table-driven `TestThresholdECDSA_PresignReuseRejected` ("same session same digest", "different session same digest", "same session different digest"), all asserting `ErrCodeConsumed`.
  - **Presign VerifyShares tamper consolidation (final evening)**: `TestIntegration_PresignRejectsTamperedKPoint` + `TestIntegration_PresignRejectsTamperedChiPoint` → `TestIntegration_PresignRejectsTamperedVerifySharePoints` (2-case table: KPoint, ChiPoint). Eliminated ~30 lines of near-duplicate code.
  - **Shamir t.Fatalf → t.Run fix (final evening)**: `TestEvalKnownPolynomial` (5 eval cases) and `TestLagrangeCoefficientReconstructs` (3 pair cases) converted from `t.Fatalf`-in-loop to proper `t.Run()` subtests with named cases.

### Pending / Incomplete

#### Phase 2: Remaining Files Without Parallelism

The following files intentionally **do not** use `t.Parallel()` because tests mutate package globals (`SetSecurityParamsForTesting`, `activeSecurityParams`, test limits) or are behind build tags that limit concurrent execution:

- `cggmp21/secp256k1/`: Most integration tests (`guard_*`, `adversary_*`, `keygen_confirm`, `presign_policy`, `proof_omission`, `vector_*`, `concurrency_*`, `benchmark_*`, `domain_*`, `encoding_*`, `golden_*`, `guard_full_flow_*`, `integration_adversary_*`, `integration_example_*`, `integration_hd_*`, `integration_refresh_*`, `integration_reshare_*`, `integration_sign_*`) remain sequential as full protocol flows respecting integration build tag. `integration_keygen_test.go` and `integration_presign_test.go` now use `t.Parallel()` (2026-06-12) as they use `CachedKeygenShares` (read-only). `slowcrypto_test.go` now uses `t.Parallel()` (2026-06-12). 3 tests in `hd_test.go` (`TestDeriveNonHardenedBIP32_InvalidChildErrorMode`, `TestDeriveNonHardenedBIP32_InvalidChildSkipMode`, `TestDeriveNonHardenedBIP32_InvalidChildSkipModeStopsBeforeHardenedRange`) intentionally sequential because they modify package-level `hmacSHA512`.
- `frost/ed25519/`: `guard_integration_test.go`, `test_setup_test.go`, `vectorgen_test.go` are integration/vector-generation.
- `internal/zk/paillier/`: `TestActiveSecurityParamsRespectsOverride` in `params_consistency_test.go` intentionally sequential (modifies `overrideSecurityParams`). `slowcrypto_test.go` and `challenge_distribution_test.go` now use `t.Parallel()` (2026-06-12) — each test creates independent Paillier keys and proofs.
- `internal/mta/`: `main_test.go` (`TestMain` only) is not a test function.

#### Phase 7: ZK Production-Parameter Tests

- `slowcrypto_test.go` and `challenge_distribution_test.go` now use `t.Parallel()` (2026-06-12). Each test creates independent Paillier keys and proofs; no global mutation. Users control concurrency via `-parallel` flag.
- `leakage_test.go` — uses `t.Parallel()` (2026-06-11 evening); confirmed safe: no package-global mutation, creates independent Paillier keys per test.

#### Phase 8: Remaining Work Items

1. ~~**Fuzz corpus seeding**~~ — Completed (analysis done; golden files incompatible with payload fuzz targets; programmatic seeds sufficient).
2. ~~**CGGMP21 integration fixture caching**~~ — Completed: `CachedKeygenShares` with `sync.Map`/`sync.Once` pattern, 46% integration time reduction.
3. ~~**FROST fixture caching**~~ — Completed: `cachedFrostKeygen` with `frostKeygenFixtureCache sync.Map`.
4. ~~**Table-driven completeness**~~ — Completed (2026-06-11):
   - `integration_reshare_test.go`: 4 membership-change tests → `TestThresholdECDSAReshareMembershipChange`.
   - `integration_adversary_test.go`: 9 tamper tests → 2 table-driven tests (`TestIntegration_SignPartialTamperingBlamesSender`, `TestIntegration_PresignRound3TamperingBlamesSender`). Common helpers extracted.
   - `integration_refresh_test.go`: 2 multi-party refresh tests → `TestThresholdECDSAProactiveRefreshScenarios`. `runRefresh` helper extracted.
5. ~~**Lightweight challenge tests**~~ — Completed.
6. ~~**DeliverEnvelope helper**~~ — Completed.
7. ~~**CheckGolden helper**~~ — Completed.
8. ~~**ZK paillier additional parallelism**~~ — Completed (2026-06-11): `t.Parallel()` added to 43 test functions across 8 previously-sequential files (`mta_response_test.go`, `new_proofs_test.go`, `adversarial_test.go`, `extractor_test.go`, `range_boundary_test.go`, `challenge_hash_test.go`, `challenge_zero_test.go`, `golden_test.go`).
9. ~~**Leakage test parallelism**~~ — Completed (2026-06-11 evening): `t.Parallel()` added to 3 leakage tests — confirmed safe (no `SetSecurityParamsForTesting` calls, independent Paillier keys).
10. ~~**FROST duplicated helpers**~~ — Completed (2026-06-11 evening): Replaced `cloneFROSTKeyShare` with `KeyShare.Clone()` and `rewriteFROSTWireField` with `testutil.RewriteWireField` in `frost/ed25519/encoding_test.go`.
11. ~~**Presign round-trip consolidation**~~ — Completed (2026-06-11 evening): `TestThresholdECDSA_PresignRoundTrip` + `TestThresholdECDSA_PresignConsumedRoundTrip` → `TestThresholdECDSA_PresignRoundTripScenarios` (2-case table: fresh + consumed).
12. ~~**Keygen confirmation consolidation**~~ — Completed (2026-06-11 evening): 7 standalone tests → 2 table-driven tests: `TestKeygenConfirmationRejectsTamperedFields` (3 cases: transcript hash, public key, commitments hash) + `TestKeygenConfirmationRejectsInvalidSenderSets` (4 cases: duplicate, missing, unknown, wrong count).
13. ~~**CGGMP21 hd_test.go parallelism**~~ — Completed (2026-06-11 late evening): `t.Parallel()` added to 18 of 21 test functions in `cggmp21/secp256k1/hd_test.go`. 3 tests (`TestDeriveNonHardenedBIP32_InvalidChildErrorMode`, `TestDeriveNonHardenedBIP32_InvalidChildSkipMode`, `TestDeriveNonHardenedBIP32_InvalidChildSkipModeStopsBeforeHardenedRange`) intentionally kept sequential — they modify package-level `hmacSHA512`. Subtests in `TestDeriveNonHardenedBIP32Vectors` (6 cases) and `TestDeriveNonHardenedBIP32Errors` (8 cases) also use `t.Parallel()`.
14. ~~**ZK paillier relation_audit_test.go parallelism**~~ — Completed (2026-06-11 late evening): `t.Parallel()` added to 10 previously sequential test functions in `relation_audit_test.go`. Confirmed safe: no `SetSecurityParamsForTesting` calls, uses thread-safe `testPaillierKeyCache sync.Map`. All 12 test functions now parallel (including subtests in `TestLegacyProofRelationCompleteness` and `TestTranscriptBindsAllPaillierKeys`).
15. ~~**Shamir table-driven consolidation**~~ — Completed (2026-06-11 late evening): 43 standalone test functions → 27 table-driven tests (37% reduction). Consolidations: `TestNormalize` (5→1, 5 cases), `TestAdd`/`TestSub`/`TestMul` (7→3, 2+2+3 cases), `TestLagrangeCoefficientRejectsInvalidInputs` (5→1, 5 cases), `TestInterpolateConstantRejectsInvalidInputs` (2→1, 2 cases), `TestRandomScalarRejectsInvalidOrder` (3→1, 3 cases), `TestRandomPolynomialRejectsInvalidThreshold` (2→1, 2 cases).
16. ~~**Integration test parallelism (2026-06-12)**~~: `t.Parallel()` added to 16 previously sequential integration test functions:

- `integration_keygen_test.go`: 3 tests (`TestThresholdECDSAKeygenHDChainCode`, `TestThresholdECDSAKeygenPaillierPublicKeyMismatchRejected`, `TestThresholdECDSAKeyShareRoundTrip`). All use `CachedKeygenShares` (read-only, `sync.Once`-backed) and create independent sessions.
- `integration_presign_test.go`: 6 tests + subtest parallelism in table-driven subtests (`TestThresholdECDSA_PresignReuseRejected` 3 subtests, `TestThresholdECDSATamperedRound2ProofBlamesSender` 3 subtests, `TestThresholdECDSA_PresignRoundTripScenarios` 2 subtests). All create fresh sessions per subtest.
- `internal/zk/paillier/params_consistency_test.go`: `TestCheckPaillierModulus` (uses thread-safe `testPaillierKey` cache with `sync.Once`).
- `internal/mta/mta_test.go`: `TestMTAProductShares` (security params set once in `TestMain`; creates independent Paillier keys per test).

17. ~~**Slowcrypto test parallelism (2026-06-12)**~~: `t.Parallel()` added to 11 previously sequential slowcrypto test functions:

- `cggmp21/secp256k1/slowcrypto_test.go`: 5 tests (`TestSlowCrypto_Keygen3of5Production`, `TestSlowCrypto_Presign3of5Production`, `TestSlowCrypto_Sign3of5Production`, `TestSlowCrypto_Refresh2of3Production`, `TestSlowCrypto_BIP32DeriveAndSignProduction`). Each test runs independent production-parameter keygen/presign/sign cycles.
- `internal/zk/paillier/slowcrypto_test.go`: `TestSlowCrypto_PaillierZKProductionProofs` (uses thread-safe `testPaillierKey` cache).
- `internal/zk/paillier/challenge_distribution_test.go`: 5 tests (`TestModulusProofChallengeDistribution`, `TestRingPedersenChallengeDistribution`, `TestRingPedersenChallengeBitIndependence`, `TestModulusProofChallengeIndependence`, `TestSecurityParamsAuditBitBoundary`). All use thread-safe `testPaillierKey` cache with `sync.Once`.

18. ~~**Paillier key cache fix (2026-06-12)**~~: `testPaillierKeyCache` in `internal/zk/paillier/proofs_test.go` refactored to match the `CachedKeygenShares` pattern:

- Added `testPaillierKeyEntry` struct wrapping `sync.Once` to prevent duplicate key generation under parallel tests.
- Replaced `Load`/`LoadOrStore` race path with `sync.Once.Do` pattern (same pattern as cggmp21 and frost fixture caches).
- Cache entries are immutable after construction (`sync.Once` ensures single write; no external mutators exist).
- Every caller receives a deep clone via `PrivateKey.Clone()`.

19. ~~**Paillier PrivateKey.Clone() (2026-06-12)**~~: Added `Clone()` method to `*paillier.PrivateKey` in `internal/paillier/paillier.go`. Deep-copies all fields: `N`, `G`, `NSquared` (via `new(big.Int).Set`), `Lambda` and `Mu` (via `secret.Scalar.Clone()`), and `P`, `Q` (via `new(big.Int).Set`). Returns `nil` for nil receiver. Used by `testPaillierKey` cache to ensure callers receive isolated copies.

### Remaining Low-Priority Items

The following items are documented as intentionally deferred:

- **`integration_keygen_test.go`**: 3 standalone functions — now all have `t.Parallel()` (2026-06-12). Consolidation would be artificial (different concerns: HD chain code, Paillier key mismatch, key share round-trip).
- **`proof_omission_test.go`**: Each test documents a specific CVE-class vulnerability (missing modulus proof, Ring-Pedersen proof, signprep proof, etc.) — independent functions preferred for security audit clarity.
- **`integration_presign_test.go`**: 6 tests — now all have `t.Parallel()` with subtest parallelism (2026-06-12). Tests cover distinct concerns (presign reuse, EncK tampering, round2 proof tampering, Paillier key mismatch, round-trip, key binding mismatch).
- **`frost/ed25519/hd_test.go`**: 6 BIP32 tests share `frostKeygenHD(t, 1, 1)` skeleton — consolidation deferred due to edit complexity in large file; tests already have `t.Parallel()`.
- **`cggmp21/secp256k1/hd_test.go`**: Now has `t.Parallel()` on 18 of 21 tests (2026-06-11 late evening). 3 tests modifying `hmacSHA512` intentionally sequential. BIP32 valid-path and rejection-path pairs could still be further consolidated in a future PR.
- **`assertProtocolErrorCode` vs `testutil.AssertProtocolError`**: Both ~10-line functions, unification would require changing 36+ call sites — deferred as low-ROI. Additionally, `testutil.AssertDeterministicRoundTrip` and `testutil.MutateBytes` have zero callers (identified 2026-06-11 final) — created in Phase 1 but never adopted; kept as harness infrastructure for future tests.
- **Fuzz CI integration tags**: 10 integration-tagged fuzz targets silently skipped in CI due to missing `-tags=integration` flag in CI fuzz script.
- **Payload-level Fuzz\*Unmarshal cleanup**: ~~Completed (2026-06-11 late evening)~~: 33 payload-level fuzz targets removed across 8 files (cggmp21: 15, frost/ed25519: 7, internal/zk/paillier: 9, internal/zk/signprep: 1, internal/zk/schnorr: 1, internal/mta: 2, internal/paillier: 2, root tss: 1). Deleted files: `cggmp21/secp256k1/fuzz_test.go`, `cggmp21/secp256k1/tier0_fuzz_test.go`, `internal/zk/paillier/proof_fuzz_test.go`, `internal/zk/signprep/fuzz_test.go`. Cleaned up 7 unused imports. Moved `mustMarshalBinary`/`binaryProof` helpers to `proof_seed_test.go`. **Remaining fuzz targets:** only `internal/wire` (3 tests: `FuzzWireUnmarshalFields`, `FuzzCustomField`, `FuzzBigIntField`) — fuzzing at the correct TLV parser layer.
- **Payload-level fuzz analysis (2026-06-11 late evening)**: Analyzed all 30+ `Fuzz*Unmarshal` targets across the codebase. **Confirmed as JSON-era historical artifacts** — the JSON seed strings (e.g. `{"version":1}`, `{"share":"x"}`) are clear evidence. With TLV encoding, random bytes almost never parse, making these targets low-yield. The `internal/wire` fuzz targets (`FuzzWireUnmarshalFields`, `FuzzCustomField`, `FuzzBigIntField`) already cover the TLV parser at the correct abstraction layer. Field-level mutation at the payload layer (Plan A) was considered but rejected — it would still be testing the same TLV parser that wire fuzzing already covers, plus type-specific validation that is better covered by table-driven unit tests. **Recommendation:** remove all `Fuzz*Unmarshal` targets in a future cleanup PR and focus fuzz investment on `internal/wire`.

### New Work Items (from 2026-06-12 testing rules update)

The following items were identified in `.agents/test.md` and documented in `docs/testing-rules.md`. They are tracked here as implementation tasks:

20. **Build tag tiering migration**: Move existing Tier 1 tests behind `//go:build tier1` so that `test-fast` explicitly selects them rather than relying on `testing.Short()`. See `docs/testing-rules.md` Build Tag Strategy section.

21. **Test budget checker**: Implement `internal/testutil/cmd/testbudget` tool that parses `go test -json` output and warns when individual tests exceed their tier's budget (Tier 0: 500ms, Tier 1: 5s, Integration: 60s).

22. **Fault injection transport harness**: Implement `NetworkFault` struct and `RunProtocolWithFaults` in `internal/testharness/network_fault.go`. Supports: drop, duplicate, reorder, corrupt, swap sender, wrong authenticated identity, broadcast equivocation, partial delivery, party crash/restart.

23. **Benchmark reorganization**: Split existing benchmarks into per-category files (keygen, presign, sign, wire) for CGGMP21 and FROST. Add micro-benchmarks for Paillier and ZK primitives. Follow naming conventions in `docs/testing-rules.md` Benchmark Organization section.

24. **TSS_TEST_SEED support**: Add `TSS_TEST_SEED` environment variable parsing to `internal/testutil` so randomized tests can be reproduced from CI logs. Print seed in `t.Logf` on every test that uses randomness.

25. **Fuzz-smoke and fuzz-ci Makefile targets**: Add `fuzz-smoke` (10s per fuzz target) and `fuzz-ci` (2m per fuzz target) to Makefile. Fuzz corpora should be stored in `testdata/fuzz/`.

### Large-Scale Work (future dedicated PRs)

These files have 10+ standalone test functions that could benefit from structural reorganization, but the scale warrants dedicated workstreams:

| File                                         | Tests | Notes                                                                                                                                                                                                                                                  |
| -------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `internal/wire/message_test.go`              | 89    | Largest single file; most tests share encode/decode/validate patterns                                                                                                                                                                                  |
| `internal/shamir/shamir_test.go`             | 27    | Consolidated from 43→27 (37% reduction) 2026-06-11; normalize/add/sub/mul/lagrange/interpolate/random-reject groups table-driven; `TestEvalKnownPolynomial` and `TestLagrangeCoefficientReconstructs` converted to `t.Run()` subtests 2026-06-11 final |
| `cggmp21/secp256k1/tier0_regression_test.go` | 18    | Many tests share presign/sign session construction + single-field validation pattern                                                                                                                                                                   |
| `cggmp21/secp256k1/hd_test.go`               | 21    | 18/21 now parallel (2026-06-11); BIP32 + sign-with-derivation tests with remaining structural similarity                                                                                                                                               |
| `frost/ed25519/hd_test.go`                   | 21    | BIP32 derivation, keygen, and wire-format tests; heavy subtest use already                                                                                                                                                                             |
