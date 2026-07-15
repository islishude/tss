# Test Rules

This document defines how tests for `github.com/islishude/tss` are selected,
designed, and maintained. The goal is not maximum test count or one global
coverage number. Tests must make security invariants executable without making
the normal feedback loop unusably slow.

The required behavioral contracts are in
[`testing-invariants.md`](testing-invariants.md). Read both documents before
adding, moving, or changing security-relevant tests.

## Document Boundaries

Keep each testing document focused so this entry point remains stable:

| Source                                                                | Owns                                                                 | Does not own                                                 |
| --------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------ |
| This document                                                         | Tiers, test design, harness use, fuzzing, fixtures, and review rules | Protocol equations, one-off regressions, current file counts |
| [`testing-invariants.md`](testing-invariants.md)                      | Durable cross-cutting and protocol-specific test contracts           | Current test locations and repository statistics             |
| [`test-inventory.md`](test-inventory.md)                              | Current build tags, file locations, counts, and cleanup map          | Normative policy or protocol semantics                       |
| Protocol docs and [`security.md`](security.md)                        | Canonical behavior, equations, lifecycle, and security boundaries    | Test tier placement                                          |
| [`internal/testvectors/README.md`](../internal/testvectors/README.md) | Vector ownership, generation, and verification                       | General test design                                          |
| `Makefile`                                                            | Commands, suite timeouts, parallelism, and CI composition            | Per-regression rationale                                     |

Update this document only for a repository-wide testing practice. Update
`testing-invariants.md` when a durable invariant class or protocol phase changes.
A regression that exercises an existing contract belongs in code and, when its
location matters, in `test-inventory.md`; it does not need another rule here.
Avoid restating protocol field lists or equations when the canonical protocol
document can be linked instead.

## Test Tiers

The budgets below apply to individual tests and are enforced by
`internal/testutil/cmd/testbudget`. Suite timeouts remain defined by the
`Makefile`.

| Tier | Selection            | Per-test budget | Scope                                                                                                        |
| ---- | -------------------- | --------------- | ------------------------------------------------------------------------------------------------------------ |
| 0    | untagged             | 500 ms          | Fast deterministic units: wire, guards, replay, state-machine units, malformed input, domains, and evidence. |
| 1    | `tier1`              | 5 s             | Reduced-parameter crypto correctness, MtA, ZK proofs, and cached fixtures.                                   |
| 2    | `integration`        | 60 s            | Full protocol lifecycles, adversarial delivery, restart, and recovery.                                       |
| 3    | `slowcrypto`         | not enforced    | Narrow production-parameter Paillier and ZK smoke tests.                                                     |
| 4    | `stress` or explicit | not enforced    | Race-sensitive flows, repeated schedules, long fuzzing, and repeated protocol execution.                     |

Rules:

- Tier 0 must remain fast, deterministic, and free of full Paillier keygen or
  complete CGGMP21 keygen/presign flows.
- Tier 1 must remain suitable for normal local feedback. Reduced parameters do
  not make a complete multi-phase protocol lifecycle a Tier 1 test.
- Tier 2 owns full keygen, presign, sign, refresh, reshare, HD derivation,
  adversarial delivery, persistence, and recovery flows.
- Tier 3 and Tier 4 are explicit or scheduled runs, not ordinary local checks.
- Put a test in the lowest tier that can exercise the invariant without
  weakening its realism.
- Tagged tests must use the tier's build tag. Explicit race and fuzz jobs may
  form Tier 4 without a `stress`-tagged test.
- `vectorgen` is generation-only, not a test tier. Its files may define only
  `TestGenerate*` entry points. Helper-only files may compile under
  `integration || vectorgen`, but ordinary validation tests must not.
- `go test -short` is advisory unless a test explicitly calls
  `testing.Short()`. Heavy tests must be excluded from Tier 0 with build tags.
- Investigate individual budget outliers and test placement before raising a
  suite timeout or per-test budget.

## Test Design

Organize tests by invariant rather than incidental helper:

```text
test = invariant x protocol x phase x fault x expected behavior
```

Names should identify those dimensions when useful:

```go
func TestCGGMP21_Presign_WrongSessionRejectsWithoutStateMutation(t *testing.T)
func TestFROST_Sign_Round2BeforeRound1DoesNotAdvance(t *testing.T)
func TestWire_Envelope_NonCanonicalIntegerRejected(t *testing.T)
```

Avoid names such as `TestBadInput`, `TestMalformed`, or `TestIntegration2`.

Use `internal/testharness` and `internal/testutil` for deterministic randomness,
party/session construction, scheduling, mutations, snapshots, and assertions.
Their APIs and usage rules are documented in
[`internal/testharness/README.md`](../internal/testharness/README.md). Do not
build a competing protocol runner or mutation library inside a protocol
package.

General rules:

- Prefer deterministic randomness. Randomized tests must report enough seed
  information to reproduce failures.
- Reject-path tests must assert the error category and every relevant negative
  side effect from the universal reject contract, not only `err != nil`.
- Test failure messages, fixtures, snapshots, and logs must not expose shares,
  nonces, witnesses, Paillier private material, MtA secrets, reconstructed
  secrets, or presign secrets.
- Use table-driven tests when cases share setup and assertions. Keep tests in
  the file that owns the invariant instead of creating broad catch-all files.
- Tests must not alter package-level default limits or cryptographic security
  parameters. Pass explicit test `Limits` and `SecurityParams` through plan
  options or `WithLimits` APIs.
- Tests that need 1-of-1 thresholds or signer-set behavior outside the owning
  protocol's defaults must also use explicit limits. This includes FROST
  exact-threshold rejection.
- User-facing `Example*` functions must use an external test package and only
  public APIs. They must not import `internal/*` or call test-only helpers.
  Full cryptographic lifecycle examples retain their tier's build tag.

### Parallelism

Use `t.Parallel()` only for deterministic, state-isolated tests.

Do not parallelize tests that mutate package globals, process-wide environment,
working directories, fixed paths or ports, shared mutable fixtures, or
execution-order state. Give each parallel test its own deterministic reader,
limits, security parameters, and mutable objects.

Crypto-heavy integration flows must use controlled concurrency. When changing
parallelism or fixture sharing, run the affected package repeatedly and use the
race detector where practical.

## Applying the Invariant Catalog

Tests inherit every applicable section of
[`testing-invariants.md`](testing-invariants.md); protocol profiles add to the
cross-cutting contracts rather than replacing them.

| Change touches                       | Minimum contracts to apply                                                                 |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| Decoder, wire record, or vector      | Universal rejection, canonical wire, vectors, limits, and fuzzing                          |
| Envelope, guard, or inbound handler  | Identity, policy, replay/equivocation, transactional transition, and blame behavior        |
| Proof, commitment, or transcript     | Canonical encoding, complete statement binding, domain substitution, and secret redaction  |
| Protocol phase or lifecycle plan     | State ordering, plan/generation binding, terminal cleanup, and the owning protocol profile |
| Key share, presign, or durable store | Defensive copying, one-use ownership, atomic commit, crash/restart, and recovery           |
| Trusted import or reconstruction     | Explicit authorization, exact-generation binding, redaction, and non-consumption           |

Before editing, trace the public entry point, plan digest, wire record,
transcript, state transition, persistence boundary, and existing tests. For an
intentional contract change, update the canonical protocol/security document
and its test profile together.

## Fuzzing

Prioritize decoders and reject paths:

- wire and envelope decoding;
- guard acceptance;
- key-share and presign decoding;
- blame evidence decoding and verification; and
- cryptographic proof decoding and verification.

Fuzz targets must enforce:

- no panic, hang, or unbounded allocation;
- malformed, oversized, trailing, and non-canonical input rejects; and
- accepted input satisfies the same canonical and semantic checks as ordinary
  tests.

Seed corpora from canonical vectors and regression cases. Add every minimized
security-relevant failure as a permanent corpus entry. Protocol-specific seeds
are listed in the invariant catalog. Use the Makefile's fuzz targets for smoke,
CI, and scheduled runs.

## Test Data and Fixtures

- Keep deterministic fixtures small and clearly marked as test-only.
- Do not store production secret material or print fixture secrets on failure.
- Keep production-parameter generation behind `slowcrypto` or explicit tooling.
- Store binary golden vectors and cross-implementation protocol vectors under
  `internal/testvectors/`; do not create per-package vector locations.
- Vector generation must be explicit and reproducible where the protocol
  permits. Verification covers decoding, validation, canonical re-encoding,
  and the vector's cryptographic result.
- `internal/testvectors/cmd/tvgen` selects generation tests with the
  `vectorgen` tag and a narrow `-run` expression. Ordinary integration tests
  must not become visible through `vectorgen` merely to share helpers.

Cached fixtures must not weaken isolation:

- Cache only when setup cost is material and the test needs an unmodified valid
  baseline.
- Include every behavior-affecting parameter in the cache key.
- Treat cache entries as immutable and return deep, independent clones.
- Prevent duplicate expensive construction during concurrent first use.
- Bypass caches for corruption, destruction, consumption, concurrency,
  copy-safety, serialization, and restart tests.
- Never cache available presign candidates or lifecycle claims. Cached public
  setup may only create a fresh run with a new `PresignID` and store slot.
- Never expose private fixture material in cache errors or logs.

Copy-safety tests mutate an accessor's return value and verify that a second
call does not expose the mutation. Apply this to byte slices, maps,
commitments, public-key encodings, verification shares, transcript hashes, and
chain codes. Long-lived validated state remains opaque, returns defensive
snapshots, and shares destruction state across shallow secret-handle copies.

## Coverage and Benchmarks

Coverage is diagnostic, not the security objective. Review it by area and
prioritize wire parsing, guards, replay, evidence, storage boundaries, protocol
state machines, and cryptographic reject paths. A lower number is acceptable
when the missing path is unreachable, defensive, covered by a heavier tier, or
lower value than the test complexity required to hit it.

Use the Makefile's area-specific coverage targets. Do not add slow
full-protocol coverage to the default feedback loop.

Benchmarks must report allocations, avoid external services and fixed ports,
and use deterministic setup. Separate offline cost, online signing latency,
verification, serialization, and primitive cost. Production-parameter crypto
benchmarks require an explicit heavy build tag or run mode.

## Test Refactoring

Use this order when cleaning up a package:

1. Inventory the invariant, tier, and runtime cost.
2. Move or split the test into the file and tier that own the invariant.
3. Merge cases with shared setup and assertions, usually with a table.
4. Downgrade the tier only when the invariant remains realistic.
5. Delete only after a stronger remaining test covers every assertion.

Keep:

- golden-vector and cross-implementation contract tests;
- fuzz and security regression cases;
- one clear integration happy path per protocol lifecycle;
- narrow production-parameter smoke tests; and
- HD derivation boundary tests.

Delete or downgrade tests that:

- assert only that a call does not error;
- duplicate a stronger test without adding an invariant;
- cover trivial accessors without redaction or copy-safety value;
- use unreproducible randomness;
- repeat expensive crypto flows without additional security value; or
- exist only to increase line coverage.

Before deletion, map every security-relevant assertion to an equal or stronger
remaining test and update `test-inventory.md` when its routing map changes.

## Review Checklist

Before merging test changes, verify:

- The test is in the lowest realistic tier and heavy work is explicitly tagged.
- Randomness and scheduling are deterministic or reproducible.
- Reject paths assert the shared error, state, effects, ownership, and blame
  contract.
- Applicable identity, domain, committee, signer-set, transcript, and protocol
  profile requirements remain covered.
- One-use material remains exactly-once across failures, copies, persistence,
  restarts, and concurrency.
- Golden changes are intentional compatibility changes.
- Fixtures and cached objects remain isolated.
- Secrets are absent from logs, errors, snapshots, fixtures, and blame evidence.
- The invariant catalog, inventory, and canonical protocol docs are updated only
  in the document that owns the changed fact.
