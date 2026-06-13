# Test Rules

This document defines testing policy for `github.com/islishude/tss`.

The goal is not maximum test count or one global coverage number. Tests must make
security invariants executable: malformed input fails closed, protocol state does
not advance incorrectly, one-use material stays one-use, and wire encodings remain
strict and canonical.

The `Makefile` is the source of truth for commands, timeouts, parallelism, and CI
composition. Use `make help` rather than duplicating those details here.

## Test Tiers

| Tier | Selection            | Scope                                                                                                        |
| ---- | -------------------- | ------------------------------------------------------------------------------------------------------------ |
| 0    | untagged             | Fast deterministic units: wire, guards, replay, state-machine units, malformed input, domains, and evidence. |
| 1    | `tier1`              | Reduced-parameter crypto correctness, MtA, ZK proofs, and cached fixtures.                                   |
| 2    | `integration`        | Full protocol lifecycles: keygen, presign, sign, refresh, reshare, HD derivation, and adversarial delivery.  |
| 3    | `slowcrypto`         | Narrow production-parameter Paillier and ZK smoke tests.                                                     |
| 4    | `stress` or explicit | Race-sensitive flows, repeated schedules, long fuzzing, and repeated protocol execution.                     |

Rules:

- Tier 0 must remain fast, deterministic, and free of full Paillier keygen or
  complete CGGMP21 keygen/presign flows.
- Tagged tests must use the tier's build tag. Explicit race and fuzz jobs may
  form Tier 4 without a `stress`-tagged test. `vectorgen` is generation-only, not
  a test tier.
- Tier 1 must remain suitable for normal local feedback.
- Tier 3 and Tier 4 are explicit or scheduled runs, not ordinary local checks.
- Put a test in the lowest tier that can exercise the invariant without weakening
  its realism.
- Keep runtime budgets enforceable through test timeouts and the repository's
  budget checker. Investigate individual outliers instead of raising suite limits
  by default.

## Test Design

Organize tests by invariant, not by incidental helper:

```text
test = invariant x protocol x phase x fault x expected behavior
```

Names should identify those dimensions when useful, for example:

```go
func TestCGGMP21_Presign_WrongSessionRejectsWithoutStateMutation(t *testing.T)
func TestFROST_Sign_Round2BeforeRound1DoesNotAdvance(t *testing.T)
func TestWire_Envelope_NonCanonicalIntegerRejected(t *testing.T)
```

Avoid names such as `TestBadInput`, `TestMalformed`, or `TestIntegration2`.

Use `internal/testharness` and `internal/testutil` for deterministic randomness,
party/session construction, scheduling, mutations, snapshots, and assertions.
Their APIs and usage rules are documented in
[`internal/testharness/README.md`](../internal/testharness/README.md). Do not build
a new protocol runner or mutation library inside each test file.

General rules:

- Prefer deterministic randomness. Randomized tests must expose enough seed
  information to reproduce failures.
- User-facing `Example*` functions must use an external test package and only
  public APIs. They must not import `internal/*` packages or call test-only
  helpers such as `NewTestEnvelopeGuard`, `TestGuardConfig`, or `TestLimits`.
  Full cryptographic lifecycle examples must retain the build tag for their
  corresponding test tier.
- Reject-path tests must assert the error category and all relevant negative side
  effects, not only `err != nil`.
- Test failure messages, fixtures, snapshots, and logs must not expose shares,
  nonces, witnesses, Paillier private material, MtA secrets, or presign secrets.
- Use table-driven tests when cases share setup and assertions. Keep tests in the
  file that owns the invariant rather than creating broad catch-all files.

### Parallelism

Use `t.Parallel()` only for deterministic, state-isolated tests.

Do not parallelize tests that mutate package globals, process-wide environment,
working directories, fixed paths or ports, shared mutable fixtures, test limits,
or execution-order state. Give each parallel test its own deterministic reader
and mutable objects.

Crypto-heavy integration flows must use controlled concurrency. When changing
parallelism or fixture sharing, run the affected package repeatedly and use the
race detector where practical.

## Required Invariants

When behavior, wire encoding, storage, or public API changes, update every affected
invariant below.

### 1. Fail Closed

Unexpected input must:

- return an error before unsafe state mutation;
- not advance the round or alter transcripts, commitments, or buffers;
- not emit outbound envelopes;
- not consume a presign, nonce, or other one-use secret state; and
- produce public-only blame evidence only when a remote sender is attributable.

Guard-level rejection happens before the protocol handler and does not create
cryptographic blame. Protocol-level rejection happens before state advancement.

| Boundary | Required reject cases                                                                                                                                                                                 |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Guard    | Unknown, non-committee, or self sender; wrong protocol, version, session, round, recipient, or transcript; direct/broadcast mismatch; missing confidentiality; missing broadcast certificate; replay. |
| Protocol | Wrong payload type; malformed payload; payload in the wrong round; payload/proof identity mismatch; equivocation; invalid commitment, proof, or partial signature.                                    |

For every rejection, snapshot the relevant public state before delivery and verify
it is unchanged afterward. Depending on the phase, that includes round, outbound
count, completion, consumed state, old/new share usability, and whether a partial
share or signature was produced. Snapshots and assertion output must remain
public-only.

### 2. Wire Encoding and Vectors

Every wire type must have deterministic marshaling and strict decoding:

- `MarshalBinary` is byte-identical across repeated calls.
- `UnmarshalBinary(MarshalBinary(x))` preserves the intended public state.
- Duplicate or missing tags, unknown critical tags, trailing bytes, wrong type or
  version, non-minimal or invalid integers, oversized fields, invalid ordering,
  duplicate party IDs, and malformed scalars or points are rejected.
- Semantically equivalent non-canonical encodings are canonicalized before
  marshaling or rejected during decoding.
- JSON fallback decoding is forbidden for key shares, presigns, proofs,
  envelopes, and blame evidence.
- A consumed presign remains consumed across marshal/unmarshal and storage
  encryption round trips.

Golden vectors are wire compatibility contracts:

- Valid vectors must continue to decode and re-encode canonically.
- Reject vectors must continue to fail with the intended error category.
- Never update golden bytes merely to make a test pass. Any intentional wire
  change must be reviewed as a protocol compatibility change.

Canonical vectors and generation instructions live in
[`internal/testvectors/README.md`](../internal/testvectors/README.md).

### 3. Guard, Identity, and State Machines

The authenticated transport party, `Envelope.From`, recipient, payload identity,
proof identity, committee, and signer set must agree before processing.

Required behavior:

- Transport identity mismatch is rejected by the guard without cryptographic
  blame.
- Payload or proof identity mismatch is rejected by the protocol and may blame
  the envelope sender.
- Committee membership does not imply membership in the current signer set.
- Removed parties cannot act after reshare; new parties cannot act before reshare
  completes.
- Old and new committee shares cannot be mixed.
- Direct and broadcast messages, confidentiality policy, and broadcast
  certificates are enforced before handler execution.
- Replay and equivocation are detected deterministically.

Round transitions must be monotonic. Duplicates, replay, corruption, wrong
recipients, non-signers, invalid thresholds, and invalid committee or reshare
plans must not advance state or trigger outbound messages.

Early messages are either:

- **not bufferable:** reject without mutation; or
- **explicitly bufferable by the protocol:** store without processing or
  advancing, then fully revalidate after prerequisites arrive.

Completion, abort, and destruction are terminal states unless the public API
explicitly defines otherwise.

### 4. Domain Separation

Proofs, commitments, challenges, transcript hashes, presigns, and signature shares
must bind all context relevant to their phase:

- protocol and version;
- session and round;
- sender and direct-message recipient;
- committee, signer set, and threshold;
- group public key;
- message digest;
- BIP32 path; and
- presign context.

For each relevant field, generate a valid object in one context and verify that it
fails after substituting another context. At minimum, test cross-session,
cross-phase, cross-recipient, cross-signer-set, cross-digest, and cross-BIP32-path
use. Signer-set ordering must have one canonical interpretation.

### 5. CGGMP21 Presign Safety

CGGMP21 presigns are one-use security material. A presign must not be reusable
across digests, sessions, signer sets, key shares, BIP32 paths, copies,
serialization round trips, restarts, or concurrent calls.

Required behavior:

- Concurrent claims permit exactly one successful consumer and at most one
  emitted partial signature.
- All losing consumers receive the consumed error category.
- Shallow copies and test-only deep copies cannot create independent claims.
- Marshal/unmarshal and encrypt/decrypt preserve consumed state.
- Independently restored copies are still serialized by the same durable
  `PresignStore`.
- Production code does not expose an API that clones a reusable presign.

A presign is consumed before a partial signature can become externally observable.
Validation that fails before entering that path must not consume it.

| Failure point                                                               | Consumed          |
| --------------------------------------------------------------------------- | ----------------- |
| Invalid digest, key share, signer set, BIP32 path, or request configuration | no                |
| Temporary durable-store error before a successful claim                     | no                |
| Durable store reports already consumed                                      | yes               |
| Partial signature constructed, emitted, or send outcome is uncertain        | yes               |
| Crash after partial generation                                              | yes after restart |

Bad input must never cause partial signature emission.

### 6. Refresh and Reshare

Tests must verify:

- refresh and reshare preserve the group public key unless explicitly specified;
- epochs, plans, party sets, and thresholds are bound into transcripts and proofs;
- interrupted operations do not leave two inconsistent usable shares;
- incomplete refresh leaves only the old share usable;
- completed refresh makes the new share usable without unsafe old/new mixing;
- incomplete reshare does not mix old and new committee state; and
- completed reshare rejects removed parties and accepts only the new committee.

### 7. Crash and Restart

Storage-sensitive tests must reload serialized state into new objects; an in-memory
round trip alone is not a restart test.

Use the shared crash-store harness to inject failures around persistence and
outbound emission. Cover the points before persist, after persist, before
outbound, and after outbound when they are meaningful for the phase.

| State at crash                                 | Required state after restart                                |
| ---------------------------------------------- | ----------------------------------------------------------- |
| Keygen incomplete or unconfirmed               | No exportable MPC key share                                 |
| Keygen complete and confirmed                  | Usable key share                                            |
| Presign incomplete                             | No usable presign                                           |
| Presign complete, never claimed                | Usable unconsumed presign                                   |
| Presign claimed or partial possibly observable | Presign remains consumed                                    |
| Refresh incomplete                             | Old share is the only usable share                          |
| Refresh complete                               | New share is usable; old/new shares cannot mix              |
| Reshare incomplete                             | Committees cannot mix; prior valid state remains coherent   |
| Reshare complete                               | New committee state is usable; removed parties are rejected |

`PresignStore` is the durability boundary for consumption. Claiming the presign
must be atomic and durable before any partial signature is emitted.

### 8. Blame Evidence

Blame evidence must be deterministic, attributable, verifiable, and public-only.

- Invalid commitments, proofs, and signature shares blame the sender when
  attribution is possible.
- Broadcast equivocation blames the equivocating sender.
- Replay, duplicate delivery, transport authentication failure, local misuse,
  storage corruption, and programmer error do not become cryptographic blame
  against a remote party.
- Aggregator tampering must not blame the party whose original partial was
  altered by someone else.
- Evidence never contains private shares, nonces, witnesses, Paillier private
  material, MtA secrets, or presign secrets.

Tests must distinguish cryptographic verification failure, transport/replay
violation, local misuse, storage failure, and terminal-state misuse by error
category and blame behavior.

### 9. Destruction and Secret Handling

`Destroy()` provides API-level safety:

- destroyed key shares, presigns, and sessions reject cryptographic use and
  serialization;
- repeated destruction is safe and idempotent; and
- the contract for public metadata after destruction is explicit.

Do not claim memory-forensic zeroization. Go may copy or retain stack, heap,
`big.Int`, and slice storage. Tests should verify that destroyed objects cannot be
used through the API, not that no secret bytes remain anywhere in process memory.

## Fuzzing

Prioritize decoders and reject paths:

- wire and envelope decoding;
- guard acceptance;
- key-share and presign decoding;
- blame evidence decoding and verification; and
- ZK proof decoding and verification.

Fuzz targets must enforce:

- no panic, hang, or unbounded allocation;
- malformed, oversized, trailing, and non-canonical input rejects; and
- accepted input satisfies the same canonical and semantic checks as ordinary
  tests.

Seed corpora from canonical vectors and regression cases. Add every minimized
security-relevant failure as a permanent corpus entry. Use the Makefile's fuzz
targets for smoke, CI, and scheduled runs.

## Test Data and Fixtures

- Keep deterministic fixtures small and clearly marked as test-only.
- Do not store production secret material or print fixture secrets on failure.
- Keep production-parameter generation behind `slowcrypto` or explicit tooling.
- Store binary golden vectors and cross-implementation protocol vectors under
  `internal/testvectors/`; do not create competing per-package vector locations.
- Vector generation must be explicit and reproducible where the protocol permits.
  Verification must cover decoding, validation, canonical re-encoding, and the
  vector's cryptographic result.

Cached fixtures must not weaken isolation:

- Cache only when setup cost is material and the test needs an unmodified valid
  baseline.
- Include every behavior-affecting parameter in the cache key.
- Treat cache entries as immutable and return deep, independent clones.
- Prevent duplicate expensive construction during concurrent first use.
- Bypass caches for corruption, destruction, consumption, concurrency, copy
  safety, serialization, and restart tests.
- Never broadly cache reusable presign objects. Any cached source material must
  produce a fresh, isolated, unconsumed presign.
- Never expose private fixture material in cache errors or logs.

Copy-safety tests must mutate an accessor's return value and verify that a second
call does not expose the mutation. Apply this to byte slices, maps, commitments,
public-key encodings, verification shares, transcript hashes, and chain codes.

## Coverage and Benchmarks

Coverage is diagnostic, not the security objective. Review coverage by area and
prioritize wire parsing, guards, replay, evidence, storage boundaries, protocol
state machines, and cryptographic reject paths. A lower number is acceptable only
when the missing path is unreachable, defensive, or covered by a heavier tier.

Use the Makefile's area-specific coverage targets. Do not add slow full-protocol
coverage to the default feedback loop.

Benchmarks must report allocations, avoid external services and fixed ports, and
use deterministic setup. Separate offline cost, online signing latency,
verification, serialization, and primitive cost. Production-parameter crypto
benchmarks require an explicit heavy build tag or run mode.

## Test Refactoring

Keep:

- golden-vector and cross-implementation contract tests;
- fuzz and regression cases;
- one clear integration happy path per protocol lifecycle;
- narrow production-parameter smoke tests; and
- HD derivation boundary tests.

Merge tests when cases share an invariant, setup, and assertions. Prefer
table-driven cases and shared helpers within the owning package.

Delete or downgrade tests that:

- assert only that a call does not error;
- duplicate a stronger test without adding an invariant;
- cover trivial accessors without redaction or copy-safety value;
- use unreproducible randomness;
- repeat expensive crypto flows without additional security value; or
- exist only to increase line coverage.

Before deletion, confirm that every security-relevant assertion remains covered.

## Review Checklist

Before merging test changes, verify:

- The test is in the correct tier and heavy work is explicitly tagged.
- Randomness and scheduling are deterministic or reproducible.
- Reject paths assert no unsafe side effects.
- Identity, domain, committee, signer-set, and transcript bindings are covered
  where relevant.
- Presign consumption remains exactly-once across failures, copies, persistence,
  restarts, and concurrency.
- Golden changes are intentional compatibility changes.
- Fixtures and cached objects remain isolated.
- Secrets are absent from logs, errors, snapshots, fixtures, and blame evidence.
