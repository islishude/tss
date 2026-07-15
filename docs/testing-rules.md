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
- `vectorgen` files may define only vector-generation entry points such as
  `TestGenerate*`. Helper-only files may compile under `vectorgen`, but ordinary
  validation tests must not use `integration || vectorgen`.
- Tier 1 must remain suitable for normal local feedback.
- Tier 3 and Tier 4 are explicit or scheduled runs, not ordinary local checks.
- Put a test in the lowest tier that can exercise the invariant without weakening
  its realism.
- `go test -short` is an advisory switch, not a tier boundary unless a test
  explicitly calls `testing.Short()`. Heavy tests must be kept out of Tier 0 with
  build tags.
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
  helpers such as `NewTestEnvelopeGuard`, `TestGuardConfig`, or package-local
  test limit/profile factories.
  Full cryptographic lifecycle examples must retain the build tag for their
  corresponding test tier.
- Reject-path tests must assert the error category and all relevant negative side
  effects, not only `err != nil`.
- Test failure messages, fixtures, snapshots, and logs must not expose shares,
  nonces, witnesses, Paillier private material, MtA secrets, or presign secrets.
- Use table-driven tests when cases share setup and assertions. Keep tests in the
  file that owns the invariant rather than creating broad catch-all files.
- Tests must not alter package-level default limits or cryptographic security
  parameters. Tests that need 1-of-1 thresholds, signer-set behavior outside the
  owning protocol's defaults (including FROST exact-threshold rejection),
  reduced Paillier moduli, or fast ZK parameters must pass explicit test
  `Limits` and `SecurityParams` through plan options or `WithLimits` APIs.

### Parallelism

Use `t.Parallel()` only for deterministic, state-isolated tests.

Do not parallelize tests that mutate package globals, process-wide environment,
working directories, fixed paths or ports, shared mutable fixtures, or
execution-order state. Give each parallel test its own deterministic reader,
limits, security parameters, and mutable objects.

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

| Boundary    | Required reject cases                                                                                                                                                                            |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Decode/Open | Wrong wire type or frame schema version; retired body layout; duplicate, missing, malformed, or trailing fields.                                                                                 |
| Guard       | Unknown, non-committee, or self sender; wrong protocol, session, round, or recipient; direct/broadcast mismatch; missing confidentiality; missing broadcast certificate; replay.                 |
| Protocol    | Wrong payload type; malformed payload; payload in the wrong round; lifecycle plan hash mismatch; payload/proof identity mismatch; equivocation; invalid commitment, proof, or partial signature. |

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
- CGGMP21 private presign marshaling is side-effect free. Availability belongs
  to `LifecycleStore`; copying or round-tripping artifact bytes must not create
  a second available slot or bypass an atomic sign claim.

Golden vectors are wire compatibility contracts:

- Valid vectors must continue to decode and re-encode canonically.
- Reject vectors must continue to fail with the intended error category.
- Never update golden bytes merely to make a test pass. Any intentional wire
  change must be reviewed as a protocol compatibility change.
- When a retired body version field is removed, renumber the remaining schema
  tags contiguously and add a reject test for the complete retired layout.

Canonical vectors and generation instructions live in
[`internal/testvectors/README.md`](../internal/testvectors/README.md).

### 3. Guard, Identity, and State Machines

The authenticated transport party (`ReceiveInfo.Peer`), `Envelope.From`,
recipient, payload identity, proof identity, committee, and signer set must
agree before processing.

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
- Lifecycle plans for keygen, refresh, reshare, child derivation, presign, and sign bind global
  intent before local runtime configuration. Mixed threshold, party set, session,
  parent/child generation, PaillierBits, signer set, context, presign, or message intent must
  fail closed at the first plan-bound payload without outbound messages or
  secret/state advancement.
- Refresh and reshare plans must bind the exact source key generation, including
  its lifecycle session, transcript, plan, and group commitments. Equal group
  public keys are not sufficient evidence that local shares are from one
  generation.

Round transitions must be monotonic. Duplicates, replay, corruption, wrong
recipients, non-signers, invalid thresholds, and invalid committee or reshare
plans must not advance state or trigger outbound messages.

Inbound handler tests must enforce this transaction order:

```text
decode -> policy validate -> cryptographic verify -> prepare transition -> commit -> effects
```

- Snapshot state before malformed, invalid, duplicate, and conflicting input;
  rejected input must leave the snapshot unchanged.
- A prepared secret-bearing value must be destroyed unless commit explicitly
  transfers ownership to the session.
- Marshal and envelope-construction failure must happen before committing the
  state that authorizes an outbound message.
- Identical duplicates are either replay/idempotence outcomes defined by the
  handler lifecycle or explicit duplicate errors; they never reapply state.
- Conflicting duplicates are replay, equivocation, or verification errors and
  never overwrite accepted state.
- Readiness must be derived from accepted per-party state or an equivalent
  authoritative bitset, not from an independently maintained message counter.

Early messages are either:

- **not bufferable:** reject without mutation; or
- **explicitly bufferable by the protocol:** store without processing or
  advancing, then fully revalidate after prerequisites arrive.

Completion, abort, and destruction are terminal states unless the public API
explicitly defines otherwise.

FROST Ed25519 dealerless-keygen tests must cover the original paper's
constant-term proof-of-knowledge invariant:

- deterministic prove/verify, wrong secret/public/domain rejection, every
  statement-field substitution, canonical point/scalar boundaries, zero
  response parsing, and one-use nonce destruction;
- required proofs for 1-of-1, 2-of-2, threshold-less-than-committee,
  full-threshold, and trusted-dealer-import lifecycles;
- the 2-of-2 rogue-key regression and proof verification before any
  confidential round-2 share effect;
- bounded early-share buffering without phase advancement, followed by full
  revalidation against the accepted round-1 commitment;
- duplicate, equivocation, out-of-order, cross-session, malformed, invalid
  proof, and invalid-share paths with terminal cleanup;
- the separate nonterminal/no-cryptographic-blame behavior for guard rejection
  and lifecycle plan-hash mismatch; and
- public commitment evidence based on public-envelope data, while confidential
  share evidence contains neither the share, original payload, nor a hash of
  either.

FROST signing tests must prove that the default policy accepts every signer-set
size from threshold through committee size, an explicit exact-threshold policy
rejects oversized sets, and distinct signer sets produce distinct plan digests.
They must deterministically construct an identity aggregate nonce commitment and
assert an unblamed terminal verification error, no effects, and complete
cleanup of nonce, commitment, partial, message, derivation, and signature state.

CGGMP21 accountability tests distinguish two paper paths:

- Figure 7 decryption failure may disclose one ephemeral DH exponent only in
  the dedicated authenticated accusation payload. Tests must reject that
  witness in logs, ordinary errors, snapshots, or generic evidence and must
  validate the embedded signed direct envelope.
- Figure 9 begins only after a Figure 8 aggregate equation fails. While it is
  active, no available presign exists. The first invalid `Πaff-g*` or `Πdec`
  attributes only its authenticated sender; a complete valid proof set with the
  original alert unresolved returns an unblamed invariant and destroys all
  witnesses. Early Figure 9 payloads, duplicates, and conflicts must not alter
  replay or protocol state incorrectly.

Figure 10 has no additional proof phase. Tests must attribute an invalid partial
directly through the authenticated envelope and the normalized commitment
equation.

CGGMP21 Figure 7 tests cover missing or mutated `Πprm`, `Πmod`, and
receiver-specific `Πfac`, wrong prover/verifier, wrong SID/RID/epoch/plan/profile,
small or equal `N`/`Nhat`, direct versus broadcast reordering/equivocation,
dynamic-identifier zero/collision, and key-share canonical revalidation.
Ring-Pedersen generation tests use known local factors to confirm that both
bases are quadratic residues; public validation separately tests Jacobi `+1`.

### 4. Domain Separation

Proofs, commitments, challenges, transcript hashes, presigns, and signature shares
must bind all context relevant to their phase:

- protocol and semantic protocol version;
- session and round;
- sender and direct-message recipient;
- committee, signer set, and threshold;
- group public key;
- message digest;
- exact lifecycle epoch and, for child creation, parent/child derivation binding; and
- presign context.

For each relevant field, generate a valid object in one context and verify that it
fails after substituting another context. At minimum, test cross-session,
cross-phase, cross-recipient, cross-signer-set, cross-digest, and cross-epoch or
cross-child use. Signer-set ordering must have one canonical interpretation.

The FROST keygen constant-term proof challenge specifically binds protocol and
version, ciphersuite, session, round, dealer, threshold, canonical complete
party set, plan hash, every coefficient commitment, chain-code commitment,
constant commitment, and proof commitment. The completed keygen transcript must
bind the canonical proof bytes in dealer order. Tests substitute every field and
test party/dealer input permutation against the canonical result.

`frostReshareTranscriptHash` keeps its established label and implementation.
Its contract tests pin one digest, substitute every field independently, and
verify that dealer/party map insertion order cannot change canonical output.

Repository-defined SHA-256 transcripts must also test:

- the fixed labeled-entry encoding and domain-first rule;
- field-name, field-order, and domain separation;
- canonical integer, boolean, uint32-list, and byte-list encodings; and
- `Sum`/`Sum32` consistency without finalizing the builder.

Production code must use `internal/transcript` rather than constructing custom
SHA-256 streams directly. RFC-defined hashes and direct content hashes are
excluded from this rule.

### 5. CGGMP21 Presign Safety

CGGMP21 presigns are one-use security material. One public `PresignID` under one
exact `GenerationBinding` may have at most one lifecycle transition from
available to a committed attempt or burn.

Figure 8 tests must cover:

- round 1 `K_i,G_i,Y_i,A_i,B_i` with verifier-specific `Πenc-elg` for both
  ciphertexts;
- the canonical public round-1 hash and recipient-specific proof domains;
- round 2 `Gamma_i` `Πelog` and both pairwise `Πaff-g` paths;
- centered signed decoding of affine masks and `EllPrime` bounds;
- round 3 `delta_i,Delta_i,S_i` with `Πelog`;
- independent checks of `[delta]G=sum(Delta_i)` and
  `[delta]X=sum(S_i)`;
- zero `delta` and invalid ECDSA nonce as unattributed terminal failures; and
- exact normalized output `(Gamma,kTilde_i,chiTilde_i,DeltaTilde,STilde)` with
  raw witnesses destroyed.

Durability tests must verify:

- `StartPresign` loads and canonically revalidates the exact current generation
  before acquiring a `RunPresign` lease or emitting output.
- Figure 8 success atomically stores one available presign and completes the
  lease before exposing a public persisted descriptor.
- A presign commit failure leaves no descriptor, candidate secret, or active
  lease.
- Artifact byte copies and marshal/unmarshal round trips cannot create another
  available store slot.
- Concurrent different intents permit exactly one committed winner.
- Concurrent exact retries recover the same immutable attempt and canonical
  envelope.
- A conflicting intent, explicit burn, successful commit, or unknown outcome
  prevents every other claim.
- The available candidate's secret blob is absent after a sign-attempt commit;
  only public recovery metadata and the exact outbox remain.
- `ResumeSign` uses the exact `AttemptQuery`, never a new session or digest.
- Production code exposes no method that returns the normalized secret tuple
  from a completed presign session.

Figure 10 tests must verify every partial with:

```text
Gamma^sigma_i = DeltaTilde_i^m * STilde_i^r
```

Invalid partials are attributed immediately. Aggregation accepts only verified
partials, emits canonical low-S output, rejects high-S public verification, and
adjusts recovery-ID parity when `S` is normalized.

| Failure point                                                         | Availability result                       |
| --------------------------------------------------------------------- | ----------------------------------------- |
| Invalid plan, generation, epoch, signer set, or empty-path binding    | unchanged; no lease or attempt            |
| Ordinary load failure before an atomic mutation                       | unchanged                                 |
| Figure 8 protocol failure                                             | no available presign                      |
| Figure 8 store commit fails with known non-commit                     | no available presign; lease aborted       |
| Figure 8 atomic commit succeeds                                       | exactly one available presign             |
| Figure 10 validation or envelope construction fails before commit     | still available                           |
| Sign-attempt commit succeeds, conflicts, burns, or is outcome-unknown | unavailable to every new intent           |
| Crash after sign-attempt commit                                       | recover only the exact attempt and outbox |

Bad input must never cause a partial signature or secret presign artifact to
become externally visible.

### 6. Refresh and Reshare

Tests must verify:

- refresh and reshare preserve the group public key unless explicitly specified;
- Figure 7/F.1 commits public material before reveal, derives RID from every
  accepted contribution, and derives non-zero collision-free dynamic Shamir
  identifiers;
- independent Paillier and auxiliary moduli are generated and equality is
  rejected even when both satisfy the bit-size floor;
- epochs, SID, RID, plans, source epoch, party sets, and thresholds are bound
  into transcripts and proofs;
- FROST refresh/reshare output remains unavailable until every target key holder
  confirms the same transcript, commitments, public key, and preserved chain code;
- CGGMP21 refresh/reshare output remains unavailable until every target holder
  confirms the complete new epoch and the lifecycle cutover commits;
- serialized lifecycle shares reject missing, partial, and fully stripped
  confirmation sets;
- interrupted operations do not leave two inconsistent usable shares;
- FROST before-persist refresh/reshare crashes reload only the source generation
  and prove the old committee can still sign;
- FROST after-persist and outcome-unknown cutovers re-read the authoritative
  durable generation, reload only the target, and prove the target committee can
  sign;
- a definite FROST cutover non-commit destroys the candidate, while an unknown
  outcome retains callback ownership until authoritative reconciliation;
- incomplete refresh leaves only the old share usable;
- completed CGGMP21 refresh atomically retires the source blob and burns all
  source-epoch available presigns;
- a protocol-level refresh failure installs the durable refresh-disabled marker,
  while a pre-start or storage failure does not;
- incomplete reshare does not mix old and new committee state; and
- completed reshare rejects removed parties and accepts only the new committee;
- reshare provisional identifiers and transport proofs never enter the final
  epoch; and
- a non-hardened child uses a distinct key ID, fresh SID/RID/epoch and
  auxiliary material, installs through the first-generation transaction, and
  leaves the parent current.

### 7. Crash and Restart

Storage-sensitive tests must reload serialized state into new objects; an in-memory
round trip alone is not a restart test.

Use the shared clone-on-read, compare-and-swap `CrashyStore` harness to inject
failures around persistence and outbound emission. It must model stale-version
conflicts, before-persist failures, after-persist unknown outcomes, and explicit
replacement or rejection with secret-blob cleanup. Cover the points before
persist, after persist, before outbound, and after outbound when they are
meaningful for the phase.

| State at crash                                  | Required state after restart                                               |
| ----------------------------------------------- | -------------------------------------------------------------------------- |
| Keygen or Figure 7 incomplete/unconfirmed       | No current sign-ready generation                                           |
| Keygen and Figure 7 confirmed                   | Exactly one usable current generation                                      |
| Presign lease active but artifact not committed | No available presign; finish or abort the exact lease                      |
| Available-presign commit durable                | Exactly one available public slot and secret candidate                     |
| Attempt committed or outcome unknown            | Resume only the bound attempt and exact envelope while delivery is pending |
| Delivery certificate durable                    | Resume the session without outbound replay                                 |
| Completion computed but not durable             | Signature remains unavailable; retry persists the same result              |
| Burn durable                                    | Presign cannot start or resume an attempt                                  |
| FROST refresh/reshare before target persist     | Source is the only recoverable generation                                  |
| FROST target persist durable or outcome unknown | Re-read store; target is the only recoverable generation                   |
| FROST target definite non-commit                | Source remains current; candidate is destroyed                             |
| Refresh/reshare before fence                    | Source remains current                                                     |
| Cutover fence durable, target not committed     | Reconcile the exact fenced transition; do not admit new source work        |
| Cutover committed                               | Target current, source retired, source-epoch available presigns burned     |
| Child generation not committed                  | Parent remains current; child lineage absent                               |
| Child first generation committed                | Parent and distinct child lineages are both current                        |

`LifecycleStore` is the durability boundary. `CommitAvailablePresignFromLease`
must atomically store availability and finish the exact lease.
`CommitSignAttempt` must be the only online-sign linearization point. Binding
the presign and persisting the exact canonical base envelope is one atomic
commit before any partial is returned or emitted. Tests distinguish
`AttemptCreated`, `AttemptExistingSame`, conflict, burn, and outcome unknown.

External lifecycle stores should run `tssrun/conformance.RunConformance` and
add backend-specific tests for encrypted secret blobs, atomic generation
comparison, lease fencing, opaque identifiers, crash consistency, KMS policy,
and database transaction behavior.

Delivery state is durable attempt state. Tests must cover ACK idempotency,
certificate persistence, mismatched payload/transcript/recipient rejection, and
the rule that `ResumeSign` stops returning outbound replay once delivery is
complete. Completion must be durable before the final signature becomes
externally visible; completion timeout or unknown outcome should leave
`Signature()` unavailable until `RetryCompletion` persists the same result.

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

### 10. Trusted Import and Secret Reconstruction

Trusted-dealer import tests must bind the target public key, chain code,
session, parties, threshold, ordered constant-term commitments, and security
profile. Wrong-party, wrong-session, wrong-plan, substituted contribution,
changed degree-zero commitment, changed chain-code commitment, replayed local
claim, and malformed canonical records must fail before unsafe state mutation or
outbound effects. Every imported constant term must carry the same valid Schnorr
proof required by dealerless DKG. Snapshot tests distinguish constant-term
`Commitments` from deep-copied per-party `ChainCodeCommitments` and verify that
mutating either returned value cannot alter the plan.

CGGMP21 interactive import must prove that each participant generates and
retains only its own Paillier private material. Centralized import must execute
the same protocol state machines and destroy every partial share, contribution,
session, and ephemeral transport key on failure.

Reconstruction requires at least the threshold number of unique shares from one
exact lifecycle generation. Tests cover insufficient and duplicate shares,
mixed lifecycle sessions, equal-public-key but different generation metadata,
destroyed or malformed shares, reconstruction from threshold and larger
subsets, final public-key verification, redaction, and non-consumption of input
shares. Failure messages and fuzz artifacts must never contain reconstructed
scalars or contribution bytes.

FROST non-hardened HD tests must update each level as
`A_j = A_{j-1} + δ_j·B`, using the cumulative shift only to check the final
root-relative relation `A_j = A_root + Δ·B`. Cover empty/single/multi-level
paths, zero tweak, invalid-child skip/error behavior, index `2^31-1`, rejection
of hardened indices, and the `tss.MaxDerivationDepth = 255` boundary. Verify the
committed public-only `[0]`, `[0,1]`, and `[2147483647]` external-oracle vectors.

## Fuzzing

Prioritize decoders and reject paths:

- wire and envelope decoding;
- guard acceptance;
- key-share and presign decoding;
- blame evidence decoding and verification; and
- FROST keygen commitment/proof and confidential-share semantic decoding; and
- ZK proof decoding and verification.

Fuzz targets must enforce:

- no panic, hang, or unbounded allocation;
- malformed, oversized, trailing, and non-canonical input rejects; and
- accepted input satisfies the same canonical and semantic checks as ordinary
  tests.

Seed corpora from canonical vectors and regression cases. Add every minimized
security-relevant failure as a permanent corpus entry. FROST semantic-decode
corpora include the canonical keygen commitment-with-proof and keygen-share wire
records, including the retired proof-less commitment shape as a reject seed. Use
the Makefile's fuzz targets for smoke, CI, and scheduled runs.

## Test Data and Fixtures

- Keep deterministic fixtures small and clearly marked as test-only.
- Do not store production secret material or print fixture secrets on failure.
- Keep production-parameter generation behind `slowcrypto` or explicit tooling.
- Store binary golden vectors and cross-implementation protocol vectors under
  `internal/testvectors/`; do not create competing per-package vector locations.
- Vector generation must be explicit and reproducible where the protocol permits.
  Verification must cover decoding, validation, canonical re-encoding, and the
  vector's cryptographic result.
- Independent Ed25519-BIP32 oracle vectors are public-only and verify-only. They
  record the pinned oracle release, tag commit, release-asset digest, and exact
  one-time command; CI must neither download the oracle nor provide a vector
  update path through `tvgen` for those vectors.
- `internal/testvectors/cmd/tvgen` selects generation tests with the `vectorgen`
  tag and a narrow `-run` expression. Do not make ordinary integration tests
  visible through `vectorgen` just because generation needs shared helpers.

Cached fixtures must not weaken isolation:

- Cache only when setup cost is material and the test needs an unmodified valid
  baseline.
- Include every behavior-affecting parameter in the cache key.
- Treat cache entries as immutable and return deep, independent clones.
- Prevent duplicate expensive construction during concurrent first use.
- Bypass caches for corruption, destruction, consumption, concurrency, copy
  safety, serialization, and restart tests.
- Never cache available presign candidates or lifecycle claims. Cached public
  setup may be used only to create a fresh run with a new `PresignID` and store
  slot.
- Never expose private fixture material in cache errors or logs.

Copy-safety tests must mutate an accessor's return value and verify that a second
call does not expose the mutation. Apply this to byte slices, maps, commitments,
public-key encodings, verification shares, transcript hashes, and chain codes.

Long-lived validated protocol state (`KeyShare`, private CGGMP21 presign
artifacts, `EpochContext`, and CGGMP21 `ResharePlan`) must remain opaque:

- reflection tests assert that the public type has no exported fields;
- byte, slice, map, context-path, and nested-record getters return independent
  snapshots;
- shallow secret-handle copies share destruction state; and
- CGGMP21 presign completion returns only a repeatable public descriptor after
  the store owns the normalized secret tuple.

Reshare-plan wire tests must cover deterministic encoding, round trips, total
size limits, canonical tag order, exact field sets, old-party verification-share
order, trailing data rejection, and a golden vector.

## Coverage and Benchmarks

Coverage is diagnostic, not the security objective. Review coverage by area and
prioritize wire parsing, guards, replay, evidence, storage boundaries, protocol
state machines, and cryptographic reject paths. A lower number is acceptable when
the missing path is unreachable, defensive, covered by a heavier tier, or lower
value than the test complexity required to hit it.

Use the Makefile's area-specific coverage targets. Do not add slow full-protocol
coverage to the default feedback loop.

Benchmarks must report allocations, avoid external services and fixed ports, and
use deterministic setup. Separate offline cost, online signing latency,
verification, serialization, and primitive cost. Production-parameter crypto
benchmarks require an explicit heavy build tag or run mode.

## Test Refactoring

Use this order when cleaning up a package:

1. Inventory the invariant, tier, and runtime cost.
2. Move or split the test into the file/tier matching that invariant.
3. Merge cases with shared setup and assertions, usually with a table.
4. Downgrade the tier only when the same invariant remains realistic.
5. Delete only after a stronger remaining test covers the same assertion.

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
