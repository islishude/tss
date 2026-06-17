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
func Parties(n int) tss.PartySet

// ThresholdCase bundles threshold and party count for table-driven tests.
type ThresholdCase struct {
    Threshold int
    Parties   int
}

func (tc ThresholdCase) N() int
func (tc ThresholdCase) T() int

// SignerSubset returns a subset of the given party set.
// ids are 1-based party indices.
func SignerSubset(all tss.PartySet, ids ...int) tss.PartySet
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

#### Additional Infrastructure

The following functionality lives outside `internal/testharness/` but serves the same cross-cutting role:

- `crash_store.go` (in `internal/testharness/`) — `CrashPoint` enum (`BeforePersist`, `AfterPersist`, `BeforeOutbound`, `AfterOutbound`) and `CrashyStore` wrapper. Used by crash/restart tests (Section 8).
- `internal/testutil/testutil.go` — `CheckGolden` helper with `UPDATE_GOLDEN=1` support. Used by all golden vector tests (Section 1). Also provides `AssertProtocolError`, `DeliverEnvelope`, `SeedFromEnv`, `RewriteWireField`, and other shared assertion helpers.
- Fuzz corpus seeding — done programmatically via `f.Add()` in each fuzz target file (see Fuzzing Rules). Persistent corpora live in `internal/wire/testdata/fuzz/`.
- `internal/testutil/cmd/testbudget/` — standalone tool that parses `go test -json` output and warns when individual tests exceed tier budgets (Test Budget section). Invoked via `make test-budget`.
