# Test Rules

This document defines the testing rules for `github.com/islishude/tss`.

The goal is not to maximize test count or global coverage. The goal is to make security invariants executable: bad inputs must fail closed, protocol state must not advance incorrectly, presigns must be exactly-once, and wire encodings must remain strict and canonical.

## Test Tiering

Tests are grouped by cost and purpose.

| Tier   | Trigger             | Purpose                                                                                                                                                                     |
| ------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tier 0 | default / `-short`  | Fast deterministic tests: wire encoding, guards, replay, party sets, state-machine units, malformed inputs, domain construction, and blame evidence. No full crypto keygen. |
| Tier 1 | `tier1` tag         | Fast crypto correctness with reduced parameters, cached fixtures, MtA correctness, proof correctness, and small deterministic protocol components.                          |
| Tier 2 | `integration` tag   | Full protocol lifecycle tests: keygen, presign, sign, refresh, reshare, BIP32, duplicate/replay handling, and guard integration.                                            |
| Tier 3 | `slowcrypto` tag    | Production-parameter Paillier and ZK smoke tests. Keep these narrow and intentional.                                                                                        |
| Tier 4 | `stress` / explicit | Concurrency, repeated randomized schedules, long fuzzing, race-sensitive flows, and repeated protocol execution. Explicit or nightly only.                                  |

Rules:

- Tier 0 must be deterministic, fast, and free of full Paillier keygen or complete CGGMP21 keygen/presign flows.
- Tier 1 must use the `tier1` build tag. May use reduced crypto parameters and cached fixtures, but must remain suitable for local fast feedback.
- Tier 2 must use the `integration` build tag.
- Tier 3 must use the `slowcrypto` build tag and should cover production-parameter smoke behavior, not exhaustive matrices.
- Tier 4 must be opt-in and must not run as part of ordinary local checks.
- Prefer deterministic test randomness. If randomized tests are necessary, print or accept a reproducible seed.
- Reject-path tests must not assert only `err != nil`; they must also assert no unsafe side effect where applicable.

### Build Tag Strategy

Tier separation uses Go build tags at compile time rather than runtime `testing.Short()` checks. The original tiering relied on `testing.Short()` to skip expensive Tier 1 tests in `-short` mode, but this was fragile: a new slow test that forgets `testing.Short()` would silently slow down `test-fast`. The migration to explicit build tags (completed 2026-06-12) fixes this:

```text
//go:build tier1       — small-param crypto correctness (requires explicit tag)
//go:build integration — full protocol flow
//go:build slowcrypto  — production parameter smoke
//go:build stress      — race + count + long-running
//go:build vectorgen   — test vector generation only
```

Tier 0 tests remain untagged and always compile. Tier 1 tests use `//go:build tier1`. Integration, slowcrypto, stress, and vectorgen tags separate the remaining tiers.

Corresponding Makefile targets:

```make
test-unit:
	go test -short -timeout 1m ./...

test-fast:
	go test -tags='tier1' -timeout 5m ./...

test-integration:
	go test -tags=integration -timeout 20m ./...
```

The migration from `testing.Short()` to `//go:build tier1` is complete for all tests. Zero `testing.Short()` calls exist in any always-compiled test file. The only `testing.Short()` call in the entire test suite is in `challenge_distribution_test.go` (behind `//go:build slowcrypto`), where it adjusts a statistical sampling parameter (10000→1000 rounds) rather than performing tier-skipping — see `docs/test-refactor-plan.md` for details.

### Test Budget

Test runtime budgets should be enforceable, not just comments in a Makefile. Recommended per-test and per-suite budgets:

| Tier        | Max Single Test | Max Suite | Enforcement          |
| ----------- | --------------- | --------- | -------------------- |
| Tier 0      | 500ms           | 30s       | `-timeout` flag      |
| Tier 1      | 5s              | 2m        | `-timeout` flag      |
| Integration | 60s             | 10m       | `-timeout` flag + CI |
| Slowcrypto  | 5m              | 1h        | explicit only        |
| Stress      | —               | >3h       | nightly only         |

A lightweight budget checker can parse `go test -json` output and warn on violations:

```bash
go test -json ./... | go run ./internal/testutil/cmd/testbudget
```

Areas most likely to exceed budget and need attention:

- Paillier keygen (dominates Tier 1 setup cost)
- ZK proof relation tests (can grow combinatorially)
- CGGMP21 keygen / presign / sign full flow (integration cost)
- Fuzz-like adversarial cases (unbounded by nature)

Without runtime budgets, CI latency drifts upward as tests accumulate.

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
go test -tags='tier1' -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -timeout 5m ./...
go test -tags=integration -p 2 -parallel $(INTEGRATION_PARALLEL) -timeout 20m ./...
```

Keep integration concurrency lower than unit-test concurrency. Crypto-heavy tests can saturate CPU and memory quickly, so more parallelism is not always faster.

Coverage should also be split by cost:

```sh
go test -short -coverprofile=coverage.unit.out -covermode=atomic ./...
go test -tags=integration -coverprofile=coverage.integration.out -covermode=atomic ./...
```

A combined all-tier coverage target is useful as an explicit heavyweight job, but it should not be the default local feedback loop.

## Test Structure

Organize tests by invariant, not by incidental helper function. Every test should decompose into five axes:

```text
test = invariant × protocol × phase × fault × expected behavior
```

For example, instead of a vague "test bad input", write it as:

```text
Invariant: wrong session must be rejected
Protocol:  CGGMP21 secp256k1
Phase:     presign round 2
Fault:     replace SessionID with a different value
Expected:  reject, no state mutation, no outbound message, no presign consumption
```

This makes test coverage auditable: when a new protocol or round is added, you can scan the invariant axes and see which combinations are missing.

Recommended package-level grouping:

```text
internal/testharness/
  rng.go                  — 1. Deterministic RNG
  parties.go              — 2. Party factory
  protocol_runner.go      — 3. Protocol runner
  network.go              — 4. Network simulator
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

Use shared helpers from `internal/testharness/` and `internal/testutil/` for deterministic parties, sessions, reduced fixtures, envelope mutations, network scheduling, and protocol assertions. Avoid each test inventing its own mini-network or party setup.

### Shared Harness Design

Rewriting tests without shared harnesses leads to each test building its own parties, network, and envelope construction — the test suite fragments again. These six harnesses are the foundation. Each lives in `internal/testharness/`.

#### 1. Deterministic RNG

```go
package testharness

// Reader returns a deterministic io.Reader seeded from t.Name().
// On failure the seed is printed via t.Logf so CI failures are reproducible.
// When TSS_TEST_SEED is set in the environment, it overrides the automatic seed.
func Reader(t *testing.T) io.Reader

// Seed returns the active seed bytes for diagnostic output.
func Seed(t *testing.T) []byte
```

Rules:

- Default deterministic — every test run with the same name produces the same byte stream.
- Failure prints the seed via `t.Logf("seed=%x", seed)`.
- `TSS_TEST_SEED` environment variable overrides the automatic seed for local reproduction.
- `slowcrypto` and stress tests may use `crypto/rand`, but must document that choice explicitly in the test name or a `t.Logf` annotation.

#### 2. Party Factory

```go
package testharness

// Parties returns a sorted party set {1, 2, ..., n}.
func Parties(n int) []tss.PartyID

// ThresholdCase bundles threshold and party count for table-driven tests.
type ThresholdCase struct {
    Threshold int
    Parties   int
}

func (tc ThresholdCase) N() int
func (tc ThresholdCase) T() int

// SignerSubset returns a subset of the given party set.
// ids are 1-based party indices.
func SignerSubset(all []tss.PartyID, ids ...int) []tss.PartyID
```

#### 3. Protocol Runner

```go
package testharness

// ProtocolCase is the interface every protocol test scenario implements.
type ProtocolCase interface {
    Name() string
    Start(t *testing.T) []Session
    Deliver(t *testing.T, env tss.Envelope) Result
    Done() bool
    AssertSuccess(t *testing.T)
    AssertFailClosed(t *testing.T, before StateSnapshot)
}

// Session wraps a protocol session with its outbox reader.
type Session struct {
    Party  tss.PartyID
    Outbox <-chan tss.Envelope
    // Underlying protocol session (type varies by protocol).
}

// Result captures the outcome of delivering one envelope.
type Result struct {
    Err      error
    Outbox   []tss.Envelope
    Advanced bool // true if round advanced after this delivery
}
```

`ProtocolCase` enforces a uniform shape: every protocol test must define how to start sessions, deliver envelopes, check completion, and assert success or fail-closed rejection. FROST keygen, FROST sign, CGGMP21 keygen, CGGMP21 presign, CGGMP21 sign, CGGMP21 refresh, and CGGMP21 reshare each get one implementation.

#### 4. Network Simulator

```go
package testharness

type Network struct {
    Drop       func(tss.Envelope) bool      // return true to drop
    Duplicate  func(tss.Envelope) bool      // return true to deliver twice
    Reorder    bool                          // shuffle delivery order
    Mutate     func(tss.Envelope) tss.Envelope // transform before delivery
}
```

`Network` is a composable fault description. A test configures which faults are active and the harness applies them during `Deliver`. Supported fault types:

```text
drop                  — message never reaches recipient
duplicate             — same envelope delivered twice
delay                 — delivery deferred until after the next round
reorder               — round messages delivered in shuffled order
corrupt               — bit-flip in payload bytes
swap sender           — Envelope.From replaced with a different party ID
swap recipient        — envelope delivered to wrong party
equivocate broadcast  — different payload for the same (round, sender) slot
partial delivery      — only a subset of expected messages delivered
```

#### 5. State Snapshot

```go
package testharness

type StateSnapshot struct {
    Round     int
    OutboxLen int
    Consumed  bool
    Completed bool
}

// Snapshot captures the externally observable state of a session.
// It must not expose secret-bearing fields.
func Snapshot(sess interface{ Round() int; Outbox() []tss.Envelope }) StateSnapshot

// AssertNoMutation fails if any field in `after` differs from `before`.
func AssertNoMutation(t *testing.T, before, after StateSnapshot)
```

`StateSnapshot` exposes only the public, non-secret fields needed to verify fail-closed behavior. Production types provide the necessary accessors (e.g., `Round()`, `Outbox()`, `IsConsumed()`) via interfaces defined in `_test.go` files or unexported test-only hooks. Secret fields (scalars, nonces, Paillier private material) must not appear in snapshots or assertion messages.

#### 6. Mutation Library

```go
package testharness

func WrongSession(env tss.Envelope) tss.Envelope
func WrongProtocol(env tss.Envelope) tss.Envelope
func WrongRound(env tss.Envelope) tss.Envelope
func WrongSender(env tss.Envelope) tss.Envelope
func WrongRecipient(env tss.Envelope) tss.Envelope
func CorruptPayload(env tss.Envelope) tss.Envelope
func StripBroadcastCert(env tss.Envelope) tss.Envelope
func StripConfidentiality(env tss.Envelope) tss.Envelope
func EquivocatePayload(env tss.Envelope) tss.Envelope
```

Each function takes a valid envelope and returns a mutated copy. These are the building blocks for the fail-closed scenario matrix in Section 0. All protocol tests (FROST keygen/sign, CGGMP21 keygen/presign/sign/refresh/reshare) use the same mutation functions — protocol-specific mutation (e.g., tampering a specific proof field) lives alongside the protocol's own test files, not in the shared library.

#### Additional Harness Files

- `crash_store.go` — `CrashPoint` enum (`BeforePersist`, `AfterPersist`, `BeforeOutbound`, `AfterOutbound`) and `CrashyStore` wrapper. Used by crash/restart tests (Section 8).
- `golden.go` — `CheckGolden` helper with `UPDATE_GOLDEN=1` support. Used by all golden vector tests (Section 1).
- `fuzz.go` — fuzz corpus seeding from golden vectors and historical regression cases. Used by fuzz tests (Fuzzing Rules).
- `budget.go` — parses `go test -json` output and warns when individual tests exceed tier budgets (Test Budget section).

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

### 0. General Fail-Closed Principles

Every protocol handler, guard, and state machine must fail closed. When any input is unexpected, the security behavior must be:

- Reject immediately — return an error before any state mutation.
- Do not mutate session state — round, buffers, transcripts, commitments, and consumed flags must stay unchanged.
- Do not emit outbound envelopes — a bad input must not cause the session to produce messages for other parties.
- Do not consume presigns, nonces, or secret-bearing state — one-use security material must survive rejection.
- Prefer returning blame evidence when attribution to a specific party is possible.

For guard-level rejections, the protocol handler must never be invoked — the guard rejects the envelope before the session sees it. For protocol-level rejections, the handler logic must reject before advancing state.

**Fail-closed scenario matrix for every protocol session:**

| Scenario                                           | Guard Layer     | Protocol Layer | Blame  |
| -------------------------------------------------- | --------------- | -------------- | ------ |
| Unknown sender (not in party set)                  | reject          | not reached    | no     |
| Non-committee party sends message                  | reject          | not reached    | no     |
| Self-send (sender == recipient for direct message) | reject          | not reached    | no     |
| Wrong session ID                                   | reject          | not reached    | no     |
| Wrong protocol ID                                  | reject          | not reached    | no     |
| Wrong round                                        | reject          | not reached    | no     |
| Wrong payload type for round                       | reject or route | reject         | sender |
| Malformed payload (cannot decode)                  | passthrough     | reject         | sender |
| Valid payload placed in wrong round                | passthrough     | reject         | sender |
| Direct message with envelope marked as broadcast   | reject          | not reached    | no     |
| Broadcast message with envelope marked as direct   | reject          | not reached    | no     |
| Secret-bearing message sent in plaintext envelope  | reject          | not reached    | no     |
| Non-secret message in unexpected secret envelope   | reject or deny  | reject         | no     |
| Missing broadcast certificate on broadcast message | reject          | not reached    | no     |
| Transcript hash mismatch                           | reject          | not reached    | no     |
| Replay (duplicate envelope)                        | reject          | not reached    | no     |
| Equivocation (same slot, different payload)        | reject          | not reached    | sender |

For every reject case, tests must verify that the rejection had no unsafe side effect. Use a snapshot-based assertion pattern:

```go
type sessionSnapshot struct {
    round    int
    outbound int
    consumed bool
}

func captureSnapshot(sess *Session) sessionSnapshot { ... }

func assertNoSideEffect(t *testing.T, before, after sessionSnapshot) {
    t.Helper()
    if before.round != after.round {
        t.Error("round advanced on rejected input")
    }
    if after.outbound != before.outbound {
        t.Error("outbound message emitted on rejected input")
    }
    if after.consumed && !before.consumed {
        t.Error("presign consumed on rejected input")
    }
}
```

**Protocol-specific fail-closed assertions:**

| Protocol Session | State to Snapshot                            | Extra Assertions                                        |
| ---------------- | -------------------------------------------- | ------------------------------------------------------- |
| FROST keygen     | round, outbound, commitments                 | no partial share emitted                                |
| FROST sign       | round, outbound, nonce state                 | nonce not consumed                                      |
| CGGMP21 keygen   | round, outbound, commitments, Paillier state | no share proof emitted                                  |
| CGGMP21 presign  | round, outbound, commitment state            | presign not consumed; MtA secrets not mutated           |
| CGGMP21 sign     | round, outbound, presign consumed flag       | partial signature not emitted; presign not consumed     |
| CGGMP21 refresh  | round, outbound, old share                   | old share still usable; new share not partially created |
| CGGMP21 reshare  | round, outbound, old/new committee state     | old/new shares not mixed                                |

Existing implementations: `TestCGGMP21KeygenEnvelopeFailClosed`, `TestCGGMP21PresignEnvelopeFailClosed`, `TestCGGMP21SignFailClosedAndEvidence` in `cggmp21/secp256k1/adversary_test.go`.

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

**Canonical-encoding rejection cases for all wire types:**

Tests must verify that every semantically equivalent but non-canonical encoding is rejected. Rejection cases apply uniformly across all TLV-encoded types:

| Category                  | Specific Mutation                                                    | Expected Rejection |
| ------------------------- | -------------------------------------------------------------------- | ------------------ |
| Duplicate tag             | Same tag appears twice in a field set                                | reject             |
| Unknown critical tag      | Tag not in schema with unknown handling                              | reject             |
| Trailing bytes            | Extra bytes after the last field                                     | reject             |
| Non-minimal integer       | Leading zero bytes in unsigned integer                               | reject             |
| Negative unsigned integer | Negative value where unsigned expected                               | reject             |
| Zero-length required      | Empty byte slice where non-empty expected                            | reject             |
| Oversized field           | Field exceeding max length or element count                          | reject             |
| Wrong type ID             | TLV wire type mismatch (e.g., `"keygen.proof"` for `"keygen.share"`) | reject             |
| Wrong version             | Version number not recognized                                        | reject             |
| Unsorted repeated fields  | Repeated field values not in canonical order                         | reject             |
| Duplicate party ID        | Same party ID appears twice in a party list                          | reject             |
| Missing required field    | Required tag absent from field set                                   | reject             |
| Field in wrong order      | Fields not in canonical tag order (if required)                      | reject             |
| Malformed scalar          | Scalar bytes not a valid curve element                               | reject             |
| Malformed point           | Point bytes not a valid curve point                                  | reject             |

**Keyshare and presign specific encoding contracts:**

- Same `KeyShare` marshal twice must produce byte-identical output.
- Same `Presign` marshal twice must produce byte-identical output.
- `Unmarshal(Marshal(x))` must preserve all public fields for keyshares, presign records, proof payloads, and blame evidence.
- A consumed presign that is marshaled and unmarshaled must still report `Consumed == true`.
- Non-canonical encodings that are semantically equivalent (e.g., different party ordering in a set) must either be canonicalized to a single representation or rejected.

**Golden vectors as compatibility contracts:**

Golden vectors live in `internal/testvectors/wire/v1/` as canonical compatibility contracts. Each valid golden vector should be paired with explicit negative mutation vectors:

```text
internal/testvectors/wire/v1/
  cggmp21/
    KeyShare.golden                  # valid — must continue to decode
    KeyShare.dup_tag.golden          # reject — duplicate tag (future)
    KeyShare.trailing_bytes.golden   # reject — trailing bytes (future)
    KeyShare.non_minimal.golden      # reject — non-minimal integer (future)
    KeyShare.wrong_type.golden       # reject — wrong type ID (future)
```

Negative golden vectors document the parser's strictness contract: they must continue to fail with the same error category across versions. Currently 21 valid binary golden vectors exist across `envelope/`, `frost/`, `cggmp21/`, and `zk/`; negative vectors are planned for future addition.

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

#### Out-of-Order Message Handling

Protocol round advancement is strictly monotonic — the session round must never regress, and messages for a future round must not cause state to skip past prerequisites without validation.

Early messages fall into two categories:

**Category A — Uncacheable early messages:** Messages whose payload type or content is completely inconsistent with the session's current state and that the protocol does not explicitly define as bufferable.

Behavior:

- Reject immediately.
- Do not mutate session state.
- Do not emit outbound messages.

Examples: presign round 1 arriving after round 2 has started, any message after the session is completed or aborted, a message with an unknown payload type.

**Category B — Allowed-to-buffer messages:** Messages for rounds that the protocol explicitly defines as buffered (e.g., reshare "share before commitments").

Behavior:

- The message may be stored but must not be processed early.
- The session must not advance its round.
- No outbound message may be emitted because of the buffered message alone.
- The buffered message must be revalidated — full context validation (session, sender, recipient, proof, domain) must happen when the message is processed, not just when it was buffered.

**CGGMP21 presign out-of-order scenario table:**

| Out-of-Order Scenario                                          | Category | Expected Behavior                           |
| -------------------------------------------------------------- | -------- | ------------------------------------------- |
| Round 2 arrives before Round 1 complete                        | A        | reject, no state mutation                   |
| Round 3 arrives before Round 2 complete                        | A        | reject, no state mutation                   |
| Same sender sends Round 1 twice                                | A        | duplicate rejection, no advance             |
| Sender sends Round 1 valid, then Round 1 different payload     | A        | equivocation + blame evidence               |
| Sender sends Round 2 to wrong recipient                        | A        | reject, no state mutation                   |
| Sender sends Round 3 with stale context                        | A        | reject, presign not consumed                |
| Party receives all messages except one proof invalid           | A        | reject round, blame sender of invalid proof |
| Party receives all messages except one missing broadcast cert  | A        | reject, no advance                          |
| Reshare share arrives before commitments (if protocol buffers) | B        | store, do not process, revalidate later     |

**Generic adversarial delivery test harness shape:**

```go
func TestProtocolRejectsInvalidDeliverySchedules(t *testing.T) {
    cases := []struct {
        name     string
        mutate   func([]Envelope) []Envelope
        wantErr  bool
        noOutput bool
    }{
        {
            name:     "round2_before_round1",
            mutate:   moveRound2BeforeRound1,
            wantErr:  true,
            noOutput: true,
        },
        {
            name:     "duplicate_same_payload",
            mutate:   duplicateFirstEnvelope,
            wantErr:  true,
            noOutput: true,
        },
        {
            name:     "equivocation_same_sender_same_round",
            mutate:   equivocateRound1Payload,
            wantErr:  true,
            noOutput: true,
        },
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            runProtocolWithMutatedSchedule(t, tc.mutate)
        })
    }
}
```

This test pattern should live in `internal/testharness/protocol_runner.go` so that FROST and CGGMP21 protocol tests share a single scheduling harness rather than each package implementing its own.

Existing implementations: `TestCGGMP21SessionStateIsMonotonic`, `TestCGGMP21AdversarialDeliveryOrder` in `cggmp21/secp256k1/adversary_test.go` and `concurrency_test.go`; `TestThresholdECDSAReshareBuffersShareBeforeCommitments` in `cggmp21/secp256k1/integration_reshare_test.go`.

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

These identity layers form a strict chain — all three must be consistent before a message is processed:

```text
Layer 1: Transport-authenticated identity   (Envelope.Security.AuthenticatedParty)
    ↓ must match
Layer 2: Envelope.From identity              (who the envelope claims sent it)
    ↓ must match
Layer 3: Payload/proof internal party ID     (party identifier in the protocol payload itself)
```

**Identity mismatch scenario table:**

| Identity Mismatch                                                  | Detection Layer      | Expected Rejection      | Blame  |
| ------------------------------------------------------------------ | -------------------- | ----------------------- | ------ |
| Transport says party 2, `Envelope.From` says party 3               | Guard (Layer 1→2)    | reject before handler   | no     |
| `Envelope.From` says party 2, payload internally claims party 3    | Protocol (Layer 2→3) | reject + blame evidence | sender |
| Proof statement party ID differs from `Envelope.From`              | Protocol (Layer 2→3) | reject + blame evidence | sender |
| Party is in the keygen committee but not in the current signer set | Protocol             | reject                  | no     |
| Party is a presign signer but not in the online signer set         | Protocol             | reject                  | no     |
| Old committee party sends in new committee reshare                 | Protocol             | reject                  | no     |
| Party was removed by reshare but continues sending messages        | Protocol             | reject                  | no     |
| New party sends messages before reshare completion                 | Protocol             | reject                  | no     |
| Old and new committee shares are mixed in a single message         | Protocol             | reject                  | no     |

**Committee set vs signer set distinction:**

A party that participated in keygen is not automatically authorized for every subsequent operation. Tests must verify:

- Keygen committee membership does not grant presign/sign authorization — the signer set is an explicit subset.
- Presign signer set membership does not grant online sign authorization if the online signer set differs.
- Old committee membership after reshare completion must be rejected for all protocol messages.
- New committee membership before reshare completion must be rejected for all protocol messages.

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

**Full domain binding field enumeration:**

Every proof, commitment, transcript hash, challenge, and signature share must bind all relevant context. The exact set depends on the proof type, but the union of fields that must be considered:

```text
protocol name       — e.g., "cggmp21-secp256k1", "frost-ed25519"
protocol version    — e.g., 1
session ID          — 32-byte unique session identifier
round number        — e.g., 1, 2, 3
sender party ID     — the party producing the proof
recipient party ID  — for direct (non-broadcast) proofs
committee set       — sorted list of all committee party IDs
signer set          — sorted list of signer party IDs (may be subset of committee)
threshold           — t
group public key    — the full public key
message digest      — the message being signed (for sign-phase proofs)
BIP32 path          — derivation path when HD is active
presign context     — key ID, chain ID, policy domain, message domain
```

**Cross-contamination scenario table:**

| Domain Field Swapped                                    | Protocol Phase | Expected Rejection     |
| ------------------------------------------------------- | -------------- | ---------------------- |
| Valid proof from session A used in session B            | all            | reject                 |
| Valid keygen proof used in presign                      | presign        | reject                 |
| Valid keygen proof used in sign                         | sign           | reject                 |
| Valid keygen proof used in refresh                      | refresh        | reject                 |
| Valid presign proof used in keygen                      | keygen         | reject                 |
| Valid direct proof for recipient A used for recipient B | all            | reject                 |
| Valid signature share for digest A used for digest B    | sign           | reject                 |
| Valid presign for BIP32 path A used for BIP32 path B    | sign           | reject                 |
| Valid presign + same digest + different BIP32 path      | sign           | reject                 |
| Valid presign + different digest + same BIP32 path      | sign           | reject or consumed     |
| Valid presign + empty path then used with child path    | sign           | reject                 |
| Signer set order permuted after proof generation        | all            | canonicalize or reject |
| Threshold changed after proof generation                | all            | reject                 |

**Proof domain verification test pattern:**

```go
func TestProofDomainBindsContext(t *testing.T) {
    // 1. Construct a valid proof under a known domain context.
    validProof, ctxA := makeValidProof(t)

    // 2. Verify it passes under the correct domain.
    if err := validProof.Verify(ctxA); err != nil {
        t.Fatalf("valid proof rejected: %v", err)
    }

    // 3. For each domain field, create a mutated copy and verify rejection.
    tests := []struct {
        name   string
        mutate func(*DomainContext)
    }{
        {"wrong_session", func(d *DomainContext) { d.SessionID = randomSessionID() }},
        {"wrong_round",   func(d *DomainContext) { d.Round++ }},
        {"wrong_recipient", func(d *DomainContext) { d.Recipient = otherPartyID }},
        {"wrong_signer_set", func(d *DomainContext) { d.SignerSet = differentSet }},

    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            ctxB := ctxA // shallow copy
            tc.mutate(&ctxB)
            if validProof.Verify(ctxB) == nil {
                t.Errorf("proof verified under %s", tc.name)
            }
        })
    }
}
```

Existing implementations: `TestCGGMP21KeyShareProofDomainBindsContext` and `TestCGGMP21MTADomainsBindPresignContext` in `cggmp21/secp256k1/domain_test.go`.

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

#### 6.1 Concurrent Reuse

When multiple goroutines race to consume the same presign, the `ClaimPresign` mutex must ensure exactly-once semantics. A test must verify:

```go
func TestPresignConcurrentConsumeExactlyOnce(t *testing.T) {
    shares := CachedKeygenShares(t, 1, 2, false)
    presigns := secpPresign(t, shares, allParties(shares))
    presign := presigns[1]

    var successes atomic.Int32
    var partials atomic.Int32

    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            digest := make([]byte, 32)
            digest[0] = byte(i)
            sess, _, err := StartSignDigest(shares[1], presign, nil, digest)
            if err == nil {
                successes.Add(1)
                if len(sess.Outbox()) > 0 {
                    partials.Add(1)
                }
            }
        }(i)
    }
    wg.Wait()

    if successes.Load() != 1 {
        t.Fatalf("presign consumed more than once: successes=%d", successes.Load())
    }
    if partials.Load() > 1 {
        t.Fatalf("unexpected partial signature emission: partials=%d", partials.Load())
    }
}
```

Key assertions:

- `successes == 1` — at most one `StartSignDigest` call succeeds.
- `partials <= 1` — at most one partial signature is emitted (the single successful signer).
- All other calls must return `ErrCodeConsumed`.

#### 6.2 Failure-Path Consumption

The presign must be marked consumed only when the code enters a path that could produce or externally observe a partial signature. The guiding principle: **if a partial signature could have been externally observed, the presign is consumed.**

| Failure Scenario                                    | Consumed? | Reason                                                              |
| --------------------------------------------------- | --------- | ------------------------------------------------------------------- |
| Digest has invalid length (not 32 bytes)            | no        | Rejected before entering the signing path                           |
| KeyShare does not match presign                     | no        | Rejected before entering the signing path                           |
| BIP32 path mismatch                                 | no        | Rejected before entering the signing path                           |
| Signer set mismatch                                 | no        | Rejected before entering the signing path                           |
| `StartSign` succeeds, partial ready but not emitted | yes       | In-memory consumed flag is set before any outbound envelope         |
| Partial signature emitted to outbox                 | yes       | Externally observable                                               |
| Partial signature generated but send fails          | yes       | Must be consumed — caller cannot prove the partial was not observed |
| Process crash after partial generated               | yes       | Reload must show consumed; presign must not be reusable             |
| Caller-provided `PresignStore.MarkConsumed` fails   | no        | In-memory consumed flag is reverted, error returned to caller       |

#### 6.3 Serialization Bypass

A consumed presign must not be revivable through serialization, copying, or cloning.

**Shallow copy:**

```go
func TestPresignShallowCopyDoesNotBypassConsumedState(t *testing.T) {
    shares := CachedKeygenShares(t, 1, 2, false)
    presigns := secpPresign(t, shares, allParties(shares))
    presign := presigns[1]

    // Consume the presign.
    _, _, err := StartSignDigest(shares[1], presign, nil, make([]byte, 32))
    require.NoError(t, err)

    // Shallow copy must not revive the presign.
    shallow := *presign
    _, _, err = StartSignDigest(shares[1], &shallow, nil, make([]byte, 32))
    if err == nil {
        t.Fatal("shallow copy bypassed consumed state")
    }
}
```

**Marshal/unmarshal round-trip:** `UnmarshalPresign(MarshalBinary(consumedPresign))` must produce a presign where `IsPresignConsumed()` returns true.

**Encrypt/decrypt round-trip:** `DecryptPresignWithPassphrase(EncryptPresignWithPassphrase(consumedPresign, pw), pw)` must produce a presign where `IsPresignConsumed()` returns true.

**Clone:** If a `Clone()` method exists, a cloned consumed presign must also be consumed.

**Design constraint:** The `Presign` struct must use internal synchronization (mutex or atomic) so that the consumed flag is not bypassable by value copying. Consider a `noCopy` marker or ensuring the consumed flag is the only mutable post-construction field that matters for safety.

Existing implementations: `TestThresholdECDSA_PresignReuseRejected`, `TestThresholdECDSA_PresignRoundTripScenarios`, `TestCGGMP21SignRejectsBadDigestAndPresignReuseBeforeOutbound` in `cggmp21/secp256k1/integration_presign_test.go` and `guard_full_flow_test.go`.

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

**Crash point model:**

A crash/restart test harness should support injecting crashes at well-defined points in the protocol lifecycle:

```go
type CrashPoint int

const (
    CrashBeforePersist  CrashPoint = iota // abort before persisting new state
    CrashAfterPersist                      // new state persisted, abort before next action
    CrashBeforeOutbound                   // outbound messages constructed but not emitted
    CrashAfterOutbound                    // outbound messages emitted, abort before next round
)
```

A `CrashyStore` wraps a real storage backend and triggers a simulated crash (panic, process kill, or controlled abort) at the configured `CrashPoint`. On restart, the test reloads all persisted state from the store, resumes or re-creates the session, and verifies that no unsafe material is available.

This lives in `internal/testharness/crash_store.go`. The `CrashPoint` enum and `CrashyStore` type are shared across FROST and CGGMP21 crash-safety tests.

**Phase-specific crash safety expectations:**

| Protocol Phase                     | Crash Point    | Expected State After Restart                                          |
| ---------------------------------- | -------------- | --------------------------------------------------------------------- |
| Keygen incomplete                  | BeforePersist  | No exportable key share; `RequireMPC` must reject                     |
| Keygen incomplete                  | AfterPersist   | No exportable key share (missing confirmations)                       |
| Keygen complete                    | AfterOutbound  | Usable key share; `RequireMPC` must accept                            |
| Presign incomplete                 | BeforePersist  | No usable presign; presign record not found or not complete           |
| Presign complete                   | AfterOutbound  | Usable presign; `IsPresignConsumed()` returns false                   |
| Presign consumed, sign in progress | BeforeOutbound | Presign is consumed; no partial signature persisted                   |
| Sign partial generated             | AfterOutbound  | Presign is consumed; partial signature persisted or must be discarded |
| Sign complete                      | AfterOutbound  | Completed signature available; presign is consumed                    |
| Refresh incomplete                 | BeforePersist  | Old share continues to be the sole usable share                       |
| Refresh complete                   | AfterOutbound  | New share usable; old share must not be mixed with new                |
| Reshare incomplete                 | BeforePersist  | Old and new committee state not mixed; old shares still valid         |
| Reshare complete                   | AfterOutbound  | New committee shares valid; removed parties cannot participate        |

**Design notes:**

- The `PresignStore` interface (in `cggmp21/secp256k1/sign.go`) is the intended durability boundary for presign consumption. A production implementation should persist the consumed flag before any partial signature is emitted. If the store write fails, the in-memory consumed flag is reverted and the error is returned to the caller.
- Tests must verify that a presign whose `Consumed` flag was set before a crash is still consumed after reload — the serialization round-trip test (`TestThresholdECDSA_PresignRoundTripScenarios`) already covers the marshal/unmarshal path, but full crash simulation (process-level restart) is a valuable addition for production deployment testing.

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

**Blame accuracy scenario table:**

| Scenario                                                               | Expected Blame Target  | Blame Reason         | Not Blamed                                                  |
| ---------------------------------------------------------------------- | ---------------------- | -------------------- | ----------------------------------------------------------- |
| Party sends malformed commitment during keygen                         | sender of commitment   | proof failure        | honest parties                                              |
| Party sends invalid ZK proof during presign                            | sender of proof        | verification failure | honest parties                                              |
| Party sends invalid signature share during sign                        | sender of partial      | verification failure | honest parties                                              |
| Aggregator tampers with another party's partial                        | actual envelope sender | payload mismatch     | the party who generated the partial                         |
| Broadcast equivocation (same slot, two different payloads)             | equivocated sender     | equivocation         | honest recipients                                           |
| Replay of old valid message                                            | no blame               | replay detection     | original honest sender (gets `ErrCodeDuplicate`, not blame) |
| Transport-authentication failure (`Transport.Sender != Envelope.From`) | no cryptographic blame | transport boundary   | original sender (identity mismatch is not a proof failure)  |
| Local storage corruption (share bytes mangled on disk)                 | no remote party        | locally detectable   | no blame evidence emitted                                   |
| Programmer error (calling session after completion)                    | no blame               | API-level error      | `ErrCodeCompleted`, not blame                               |

**Error classification — five categories:**

```text
1. Malicious remote party
   Proofs, commitments, signature shares fail cryptographic verification.
   → Produce blame evidence: sender ID, reason, cryptographic context (public-only).
   → Error code: ErrCodeVerification.

2. Transport/replay violation
   Identity mismatch, duplicate payloads, equivocation at transport layer.
   → No cryptographic blame against the original honest sender.
   → Error class: ErrCodeInvalidMessage, ErrCodeDuplicate, or ErrEquivocation.

3. Local misuse
   Calling API with wrong arguments, corrupting own storage, using wrong session.
   → No blame evidence at all.
   → Error code: ErrCodeInvalidParameter, ErrCodeWrongSession, etc.

4. Storage corruption
   Share bytes mangled on disk, wrong key ID, decryption failures.
   → Must not produce blame evidence naming a remote party.
   → Error is local and non-attributable to any network participant.

5. Programmer error
   Calling session methods after completion, using destroyed objects.
   → No blame evidence.
   → Error code: ErrCodeCompleted, ErrCodeAborted.
```

### 10. Secret Zeroization

`Destroy()` and similar lifecycle methods must provide API-level safety: after destruction, the object must not be usable for cryptographic operations. Tests should verify:

- `Destroy()` on a key share prevents `StartSign`, `StartPresign`, `StartRefresh`, `StartReshare`, and `MarshalBinary`.
- `Destroy()` on a presign prevents `StartSign` and `MarshalBinary`.
- `Destroy()` on a session prevents further message handling.
- Repeated `Destroy()` calls are safe (idempotent, no panic).
- Public metadata accessors (party ID, threshold, public key bytes) may remain readable or may be zeroed by design — the contract must be explicit either way.

**Do not claim memory-forensic zeroization.** Go's compiler, garbage collector, and runtime may copy, move, or optimize away memory writes. In particular:

- Stack-allocated secrets may not be reliably zeroed.
- Compiler optimizations may elide "dead stores" to local variables.
- GC may move heap objects, leaving old copies in reclaimable memory.
- `big.Int` and byte slices may share underlying arrays; clearing one reference does not clear all.

Tests should assert API-level safety (destroyed objects reject use) but must not claim that the Go heap or stack is free of secret material after `Destroy()`. The `internal/secret.Scalar` type's destruction behavior should be tested for API-level correctness within these acknowledged Go limitations.

Existing implementations: `TestKeyShare_Destroy`, `TestPresign_Destroy_ClearsSecrets`, `TestPresignSession_Destroy_ClearsSecrets`, `TestDestroy_Idempotent` in `cggmp21/secp256k1/lifecycle_test.go` and `state_transition_test.go`.

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

**Fuzz Makefile targets:**

Distinguish between fast smoke fuzzing (local feedback) and CI fuzzing (broader coverage):

```make
fuzz-smoke:
	go test -run=^$ -fuzz=. -fuzztime=10s ./internal/wire ./internal/zk/...

fuzz-ci:
	go test -run=^$ -fuzz=. -fuzztime=2m ./internal/wire ./internal/zk/... ./cggmp21/secp256k1

fuzz-nightly:
	go test -run=^$ -fuzz=. -fuzztime=10m ./...
```

Fuzz corpora should live in `testdata/fuzz/` and include historical regression samples. New bugs found by fuzzing should add their input to the corpus as a permanent regression guard.

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

**Split coverage Makefile targets:**

A single combined coverage number is not actionable. Split coverage by area:

```make
coverage-unit:
	go test -short -coverprofile=coverage.unit.out ./...
	go tool cover -html=coverage.unit.out -o coverage.unit.html

coverage-wire:
	go test -coverprofile=coverage.wire.out ./internal/wire ./internal/wire/...
	go tool cover -func=coverage.wire.out

coverage-security:
	go test -short -coverprofile=coverage.security.out \
		. ./cggmp21/secp256k1 ./frost/ed25519 ./internal/wire

coverage-integration:
	go test -tags=integration -coverprofile=coverage.integration.out -covermode=atomic ./...
```

## Test Data and Fixtures

- Keep deterministic fixtures small and clearly labeled.
- Do not store secret production material in `internal/testvectors/`.
- Do not log fixture secrets in failing tests.
- Reduced-parameter crypto fixtures must be visibly marked as test-only.
- Production-parameter fixtures or long-running generation must live behind `slowcrypto` or explicit fixture-generation tooling.

All test vectors are consolidated in `internal/testvectors/`:

```text
internal/testvectors/
  wire/v1/              # binary golden vectors (wire format compatibility)
    envelope/
    frost/
    cggmp21/
    zk/
  protocol/             # JSON cross-implementation vectors
    frost-ed25519/
    cggmp21-secp256k1/
```

Fuzz corpora live in `internal/wire/testdata/fuzz/` (the only remaining per-package `testdata/` directory).

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

## Benchmark Organization

Benchmarks should be organized by cost category, not thrown into a single file. For TSS, distinguishing cost categories matters more than total operations per second:

| Category          | Examples                                                         | Why Measured                   |
| ----------------- | ---------------------------------------------------------------- | ------------------------------ |
| Offline cost      | `BenchmarkCGGMP21Keygen3of5`, `BenchmarkCGGMP21Presign3of5`      | Keygen/presign are pre-compute |
| Online latency    | `BenchmarkCGGMP21OnlineSign3of5`, `BenchmarkFROSTSign3of5`       | Signing is interactive         |
| Verification cost | `BenchmarkZKProofVerify`, `BenchmarkPartialVerify`               | Aggregation or blame checks    |
| Serialization     | `BenchmarkWireMarshalEnvelope`, `BenchmarkWireUnmarshalEnvelope` | Envelope encode/decode         |
| Primitive cost    | `BenchmarkPaillierEncrypt`, `BenchmarkPaillierKeygen1024`        | Micro-benchmarks of primitives |

Online signing latency is typically more important for TSS engineering than total keygen or presign cost, because signing is interactive.

Recommended benchmark file organization:

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

Benchmarks should use `testing.B` and report allocations. Avoid benchmarks that depend on external services, fixed ports, or non-deterministic timings. Crypto benchmarks must use reduced parameters unless explicitly behind a `slowcrypto` or `benchmark` build tag.

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

## Test Consolidation Guide

When refactoring the test suite, group existing tests into three categories.

### Keep As-Is

- Golden tests — wire compatibility contracts.
- Fuzz tests — malformed input rejection.
- Integration happy-path — one per protocol per lifecycle (keygen + presign + sign + refresh + reshare).
- Slowcrypto smoke — one narrow production-parameter test per proof family.
- Known regression tests — each with a comment linking to the issue or CVE it guards.
- BIP32 / HD derivation tests — edge cases around hardened/non-hardened boundaries.

### Merge into Invariant Matrices

Many scattered adversarial tests cover the same invariant from different angles. Merge them into table-driven matrices:

```text
adversary_test.go           \
integration_adversary_test.go |
guard_integration_test.go     |  →  invariant_guard_test.go
guard_full_flow_test.go      /       invariant_state_machine_test.go
                               →  invariant_delivery_faults_test.go
state_transition_test.go      →  invariant_blame_test.go
scheduler_test.go            /
```

The merged tests use the shared `internal/testharness/` harnesses and cover the full fail-closed matrix (Section 0) with a single table of mutation functions per protocol session.

### Delete or Downgrade

- Tests that only verify a function "does not error" without any security assertion.
- Pure happy-path unit tests that duplicate a stronger integration test.
- Tests that only cover trivial getter/setter behavior without redaction or copy-safety assertions.
- Non-deterministic randomized tests without reproducible seeds.
- Long-running repeated crypto flows without clear security value beyond what the integration test covers.
- Tests that exist only to hit a coverage line without exercising a security-relevant path.

When deleting, ensure the useful assertion is either unnecessary or already preserved in a stronger, invariant-driven test. Document the deletion reason in the PR.

## Implementation Priority

When adding new tests to close the security gaps described in this document, prioritize by safety impact. This ordering is distinct from the refactor migration phases in `docs/test-refactor-plan.md`.

### Phase 1: Foundational fail-closed and canonical encoding (Tier 0–1)

Highest safety return per test invested. Cover the guard-level and wire-level invariant matrices first — these rejections stop bad input before any protocol code runs.

- Guard-level fail-closed scenario table (Section 0) for each protocol session.
- Canonical-encoding rejection cases (Section 1) for all wire types.
- State-machine out-of-order rejection tests — Category A (uncacheable) cases (Section 3).

### Phase 2: Identity and domain separation (Tier 0–1)

Cheap to write, high value for preventing cross-protocol and cross-session attacks.

- Three-layer identity binding table (Section 4) for each protocol session.
- Domain separation proof verification matrix (Section 5) — test proofs under wrong session, round, recipient, protocol, signer set, and BIP32 path.

### Phase 3: Presign and sign safety (Tier 2–4)

The highest-risk area for threshold ECDSA.

- Concurrent presign reuse test (Section 6.1) — Tier 4, explicit only.
- Failure-path consumption table (Section 6.2) — Tier 2.
- Serialization bypass tests (Section 6.3) — Tier 0 for unit, Tier 2 for integration.
- Crash/restart harness for presign consumption (Section 8) — Tier 2.

### Phase 4: Blame evidence accuracy and full crash-recovery (Tier 2)

- Blame accuracy scenario table (Section 9) — verify blame targets the correct party.
- Crash-recovery harness across all protocol phases (Section 8).
- End-to-end restart verification with encrypted storage.

See `docs/test-refactor-plan.md` section 16 for current implementation status of each phase.
