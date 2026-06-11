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
  rng.go
  parties.go
  network.go
  envelope_mutation.go
  protocol_runner.go
  state_assert.go
  crash_store.go
  golden.go
  fuzz.go
  budget.go

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

| Tier   | Default?          | Contents                                                                                                                                               |
| ------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Tier 0 | Yes, `-short`     | Fast deterministic tests: wire, guard, replay, encoding, redaction, copy safety, state-machine units, malformed input. No full CGGMP21 keygen/presign. |
| Tier 1 | Yes, non-short    | Reduced-parameter crypto correctness, small proof/MtA checks, cached fixtures.                                                                         |
| Tier 2 | `integration` tag | Full FROST and CGGMP21 lifecycle tests.                                                                                                                |
| Tier 3 | `slowcrypto` tag  | Production-parameter Paillier/ZK smoke. Narrow and intentional.                                                                                        |
| Tier 4 | explicit only     | Stress, race-heavy, long fuzz, repeated randomized schedules.                                                                                          |

Short local feedback must remain fast. Expensive protocol flows must be behind build tags or explicit targets.

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

## 16. Implementation Status

_Last updated: 2026-06-11 (evening update)_

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
  - `cggmp21/secp256k1` tier0 (72 parallel tests)
  - `internal/shamir` (45 parallel tests)
  - `internal/paillier` (27 parallel tests)
  - `internal/bip32util` (25 parallel tests)
  - `internal/curve/secp256k1` (19 parallel tests)
  - `internal/mta` (27 parallel tests — finish, response, start; `mta_test.go` intentionally kept sequential due to `SetSecurityParamsForTesting`)
  - `internal/zk/signprep` (12 parallel tests)
  - `internal/zk/schnorr` (11 parallel tests)
  - `internal/secret` (10 parallel tests)
  - `internal/curve/edwards25519` (8 parallel tests)
  - `internal/paillier/paillierct` (8 parallel tests)
  - `internal/zk/paillier` (20+ files updated — pure unit tests and Tier 1 proof tests)
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

### Pending / Incomplete

#### Phase 2: Remaining Files Without Parallelism

The following files intentionally **do not** use `t.Parallel()` because tests mutate package globals (`SetSecurityParamsForTesting`, `activeSecurityParams`, test limits) or are behind build tags that limit concurrent execution:

- `cggmp21/secp256k1/`: Integration tests (`integration_*`, `guard_*`, `adversary_*`, `keygen_confirm`, `presign_policy`, `proof_omission`, `slowcrypto`, `vector_*`) use `runLimitedIntegration` semaphore instead. Pure tier0 tests already parallelized.
- `frost/ed25519/`: `guard_integration_test.go`, `test_setup_test.go`, `vectorgen_test.go` are integration/vector-generation.
- `internal/zk/paillier/`: `slowcrypto_test.go`, `challenge_distribution_test.go` — production-parameter or distribution-analysis tests behind `slowcrypto` tag.

#### Phase 7: ZK Production-Parameter Tests

- `slowcrypto_test.go` and `challenge_distribution_test.go` remain behind `slowcrypto` build tag and intentionally sequential.
- `leakage_test.go` — now uses `t.Parallel()` (2026-06-11 evening); confirmed safe: no package-global mutation, creates independent Paillier keys per test. Previously misclassified as needing sequential execution.

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

### Remaining Low-Priority Items

The following items are documented as intentionally deferred:

- **`integration_keygen_test.go`**: 3 standalone functions testing different concerns — consolidation would be artificial.
- **`proof_omission_test.go`**: Each test documents a specific CVE-class vulnerability (missing modulus proof, Ring-Pedersen proof, signprep proof, etc.) — independent functions preferred for security audit clarity.
- **`integration_presign_test.go`**: Remaining tamper/rejection tests have divergent setup patterns that don't justify a shared harness.
- **`frost/ed25519/hd_test.go`**: 6 BIP32 tests share `frostKeygenHD(t, 1, 1)` skeleton — consolidation deferred due to edit complexity in large file; tests already have `t.Parallel()`.
- **`cggmp21/secp256k1/hd_test.go`**: 11 tests with partial structural similarity — BIP32 valid-path and rejection-path pairs could be consolidated in a future PR.
- **`assertProtocolErrorCode` vs `testutil.AssertProtocolError`**: Both ~10-line functions, unification would require changing 36+ call sites — deferred as low-ROI.
- **Fuzz CI integration tags**: 10 integration-tagged fuzz targets silently skipped in CI due to missing `-tags=integration` flag in CI fuzz script.

### Large-Scale Work (future dedicated PRs)

These files have 10+ standalone test functions that could benefit from structural reorganization, but the scale warrants dedicated workstreams:

| File                                         | Tests | Notes                                                                                |
| -------------------------------------------- | ----- | ------------------------------------------------------------------------------------ |
| `internal/wire/message_test.go`              | 89    | Largest single file; most tests share encode/decode/validate patterns                |
| `internal/shamir/shamir_test.go`             | 43    | Pure function tests ideal for table-driven grouping                                  |
| `cggmp21/secp256k1/tier0_regression_test.go` | 18    | Many tests share presign/sign session construction + single-field validation pattern |
| `cggmp21/secp256k1/hd_test.go`               | 11    | BIP32 + sign-with-derivation tests with structural similarity                        |
| `frost/ed25519/hd_test.go`                   | 21    | BIP32 derivation, keygen, and wire-format tests; heavy subtest use already           |
