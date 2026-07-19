# Testing Invariants

This catalog defines the behavior that tests must preserve. The companion
[`testing-rules.md`](testing-rules.md) defines tiering, test design, fixtures,
fuzzing, and review practice.

The sections are cumulative: every protocol profile inherits the cross-cutting
contracts. Protocol documents remain authoritative for equations and wire
semantics; this catalog records the distinct coverage obligations. Add a new
entry only for a durable invariant or protocol phase, not for every regression.

## 1. Universal Reject Contract

Unexpected input must:

- return an error before unsafe state mutation;
- not advance the round or alter transcripts, commitments, or buffers;
- not emit outbound envelopes;
- not consume a presign, nonce, or other one-use secret state; and
- produce public-only blame evidence only when a remote sender is attributable.

Guard-level rejection happens before the protocol handler and does not create
cryptographic blame. Protocol-level rejection happens before state advancement.

| Boundary    | Required reject cases                                                                                                                                                         |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Decode/Open | Wrong wire type or frame schema version; retired body layout; duplicate, missing, malformed, or trailing fields.                                                              |
| Guard       | Unknown, non-committee, or self sender; wrong protocol, session, round, or recipient; direct/broadcast mismatch; missing confidentiality or broadcast certificate; replay.    |
| Protocol    | Wrong payload type or round; malformed payload; plan mismatch; payload/proof identity mismatch; equivocation; invalid commitment, proof, partial signature, scalar, or point. |

Snapshot relevant public state before rejection and verify it is unchanged.
Depending on the phase, the snapshot includes round, outbound count,
completion, consumed state, old/new share usability, and whether a partial or
signature was produced. Snapshots and assertion output remain public-only.

Inbound handler tests enforce:

```text
decode -> policy validate -> cryptographic verify -> prepare transition -> commit -> effects
```

- A prepared secret-bearing value is destroyed unless commit transfers its
  ownership to the session.
- Marshal and envelope-construction failure occurs before committing the state
  that authorizes an outbound message.
- Identical duplicates produce the handler's defined replay/idempotence outcome
  or an explicit duplicate error; they never reapply state.
- Conflicting duplicates are replay, equivocation, or verification errors and
  never overwrite accepted state.
- Readiness derives from accepted per-party state or an equivalent authoritative
  bitset, not an independently maintained message counter.
- A non-bufferable early message rejects without mutation. An explicitly
  bufferable message is stored without processing or advancement and is fully
  revalidated after its prerequisites arrive.
- Completion, abort, and destruction are terminal unless the public API
  explicitly defines otherwise.

## 2. Canonical Wire and Vectors

Every wire type must have deterministic marshaling and strict decoding:

- repeated `MarshalBinary` calls are byte-identical;
- `UnmarshalBinary(MarshalBinary(x))` preserves the intended public state;
- duplicate, missing, or unknown tags, trailing bytes, wrong type
  or version, invalid ordering, oversized fields, duplicate party IDs,
  non-minimal integers, and malformed scalars or points reject;
- semantically equivalent non-canonical values are canonicalized before
  marshaling or rejected during decode; and
- JSON fallback decoding is forbidden for key shares, presigns, proofs,
  envelopes, and blame evidence.

CGGMP21 private-presign marshaling is side-effect free. Availability belongs to
`LifecycleStore`; copying or round-tripping artifact bytes cannot create a
second available slot or bypass an atomic sign claim.

Golden vectors are compatibility contracts:

- valid vectors decode and re-encode canonically;
- reject vectors fail with the intended error category;
- golden bytes change only for an intentional reviewed wire contract change;
  and
- removing a retired body version requires contiguous remaining tags and a
  reject vector for the complete retired layout.

Canonical vector ownership and commands are defined in
[`internal/testvectors/README.md`](../internal/testvectors/README.md).

## 3. Identity, Plans, State, and Domains

The authenticated transport party (`ReceiveInfo.Peer`), `Envelope.From`,
recipient, payload identity, proof identity, committee, and signer set must
agree before processing.

- Transport identity mismatch rejects at the guard without cryptographic blame.
- Payload or proof identity mismatch rejects in the protocol and may blame the
  envelope sender.
- Committee membership does not imply current signer-set membership.
- Removed parties cannot act after reshare; new parties cannot act before it
  completes; old and new committee shares cannot be mixed.
- Direct/broadcast policy, confidentiality, and broadcast certificates are
  enforced before handler execution.
- Replay and equivocation are detected deterministically.
- Round transitions remain monotonic under duplicates, corruption,
  out-of-order delivery, wrong recipients, non-signers, invalid thresholds, and
  invalid committee or reshare plans.

Lifecycle plans for keygen, refresh, reshare, child derivation, presign, and sign
bind global intent before local runtime configuration. Mixed threshold, party
set, session, source generation, Paillier bits, signer set, context, presign, or
message intent fails at the first plan-bound payload without output or secret
state advancement. Refresh and reshare bind the exact source lifecycle session,
transcript, plan, and group commitments; an equal group public key is not proof
of one generation.

Proofs, commitments, challenges, transcript hashes, presigns, and signature
shares bind every relevant context field:

- protocol and semantic protocol version;
- session, round, sender, and direct-message recipient;
- committee, signer set, and threshold;
- group public key and message digest;
- exact lifecycle epoch plus parent/child derivation binding; and
- presign context.

For each relevant field, create a valid object and substitute one field from a
different context. At minimum cover cross-session, cross-phase,
cross-recipient, cross-signer-set, cross-digest, and cross-epoch or cross-child
use. Signer-set ordering has one canonical interpretation.

Repository-defined SHA-256 transcripts test the fixed labeled-entry encoding,
domain-first rule, field name and order, canonical integer, boolean, uint32-list,
and byte-list encodings, and `Sum`/`Sum32` consistency without finalizing the
builder. Production code uses `internal/transcript`; RFC-defined and direct
content hashes are excluded.

## 4. FROST Ed25519 Profile

The protocol contract is documented in
[`frost-ed25519.md`](frost-ed25519.md).

### Dealerless Keygen

| Area                | Required coverage                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Proof primitive     | Deterministic prove/verify; wrong secret, public value, or domain; every statement-field substitution; point/scalar boundaries; valid zero response; one-use nonce destruction.                                                                                                                                                                                                                                                               |
| Applicability       | Required constant-term proof for 1-of-1, 2-of-2, threshold smaller than committee, full threshold, and trusted-dealer import.                                                                                                                                                                                                                                                                                                                 |
| Protocol placement  | The 2-of-2 rogue-key regression; proof verification before any confidential round-2 effect; bounded early-share buffering without advancement followed by full revalidation.                                                                                                                                                                                                                                                                  |
| Reject and cleanup  | Exact duplicates reject without terminating. Explicitly permitted early shares, partials, and confirmations buffer within limits and are fully revalidated before use. Guard-level cross-session and recipient rejection, and protocol plan-mismatch rejection, are nonterminal and unblamed. Equivocation and authenticated malformed or invalid proofs/shares terminate and clear staged secret state where the phase contract requires it. |
| Evidence            | Public commitment evidence may use public-envelope data. Confidential-share evidence contains neither the share, the original payload, nor a hash of either.                                                                                                                                                                                                                                                                                  |
| Transcript contract | The challenge binds protocol/version, ciphersuite, session, round, dealer, threshold, canonical complete party set, plan hash, every coefficient commitment, chain-code commitment, constant commitment, and proof commitment. The completed transcript binds canonical proof bytes in dealer order.                                                                                                                                          |

Substitute every challenge field and verify party/dealer input permutation
cannot change the canonical result. `frostReshareTranscriptHash` retains its
established label; pin one digest, substitute every field independently, and
verify map insertion order cannot change it.

### Signing

- Default policy accepts every signer-set size from threshold through committee
  size. Explicit exact-threshold policy rejects larger sets, and distinct signer
  sets produce distinct plan digests.
- Deterministically construct an identity aggregate nonce commitment and assert
  an unblamed terminal verification error, no effects, and cleanup of nonce,
  commitment, partial, message, derivation, and signature state.

### Refresh, Reshare, Import, and HD

- Refresh/reshare output remains unavailable until every target key holder
  confirms the same transcript, commitments, public key, and preserved chain
  code. They preserve the group public key, and serialized shares reject
  missing, partial, and stripped confirmation sets.
- Before-persist crashes reload only the source generation and prove it can
  still sign. After-persist and outcome-unknown cutovers re-read the store,
  reload only the target, and prove it can sign. Definite non-commit destroys
  the candidate; unknown outcome retains callback ownership until authoritative
  reconciliation.
- Every trusted-import constant term carries the dealerless-DKG Schnorr proof.
  Snapshot tests distinguish constant-term `Commitments` from deep-copied
  per-party `ChainCodeCommitments` and prove returned-value mutation cannot
  alter the plan.
- Non-hardened HD updates each level as `A_j = A_{j-1} + δ_j·B`; cumulative
  shift is used only for the final root-relative relation
  `A_j = A_root + Δ·B`. Cover empty, single, and multi-level paths, zero
  tweak, invalid-child skip/error, index `2^31-1`, hardened-index rejection, and
  `tss.MaxDerivationDepth = 255`.
- Verify the public-only `[0]`, `[0,1]`, and `[2147483647]` external-oracle
  vectors.

## 5. CGGMP21 secp256k1 Profile

Use the bundled 2024 paper and the repository's
[`CGGMP21 protocol checklist`](cggmp21-protocol-checklist.md). Figure numbers
below refer to that revision.

### Figure 7 and Accountability

- Figure 7 decryption failure may disclose one ephemeral DH exponent only in
  the dedicated authenticated accusation payload. Reject that witness in logs,
  ordinary errors, snapshots, or generic evidence, and validate the embedded
  signed direct envelope.
- Cover missing or mutated `Πprm`, `Πmod`, and receiver-specific `Πfac`; wrong
  prover/verifier and every context field available when each proof is created;
  small or equal `N`/`Nhat`; broadcast/direct reordering and equivocation;
  dynamic-identifier zero/collision; and canonical key-share revalidation.
  Early `Πprm` precedes RID and EpochID, so it binds the auxiliary parameters,
  run/session, committee, prover, and plan available at that point. The final
  transcript and `AuxiliaryDigest` bind the derived RID/EpochID and completed
  auxiliary state.
- Ring-Pedersen generation uses known local factors to prove both bases are
  quadratic residues. Public validation separately covers Jacobi `+1`.

### Figure 8 Presign

| Round/output | Required coverage                                                                                                                                               |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Round 1      | `K_i,G_i,Y_i,A_i,B_i`; verifier-specific `Πenc-elg` for both ciphertexts; canonical public round-1 hash; recipient-specific proof domains.                      |
| Round 2      | `Gamma_i`, `Πelog`, both pairwise `Πaff-g` paths, centered signed affine-mask decoding, and `EllPrime` bounds.                                                  |
| Round 3      | `delta_i,Delta_i,S_i` with `Πelog`; independent `[delta]G=sum(Delta_i)` and `[delta]X=sum(S_i)` checks.                                                         |
| Failure      | Zero `delta` and invalid ECDSA nonce are unattributed terminal failures; no available presign remains.                                                          |
| Output       | Exact normalized `(Gamma,kTilde_i,chiTilde_i,DeltaTilde,STilde)` with raw witnesses destroyed and no API exposing the normalized secret tuple after completion. |

### Figures 9 and 10

- Figure 9 begins only after a Figure 8 aggregate equation fails; while active,
  no available presign exists. Verification reconstructs canonical inbound and
  outbound MtA views and revalidates the previously accepted `Πaff-g` material
  before checking `Πaff-g*` and `Πdec`. The first invalid proof blames only its
  authenticated sender. A complete valid proof set with the original alert
  unresolved returns an unblamed invariant and destroys all witnesses. Early
  Figure 9 payloads, duplicates, and conflicts obey the universal reject
  contract.
- Figure 10 has no additional proof phase. An invalid partial is attributed
  through its authenticated envelope and the normalized commitment equation:

  ```text
  Gamma^sigma_i = DeltaTilde_i^m * STilde_i^r
  ```

- Aggregation accepts only verified partials, emits canonical low-S output,
  rejects high-S public verification, and adjusts recovery-ID parity when `S`
  is normalized.

### Presign Ownership and Durability

One public `PresignID` under one exact `GenerationBinding` has at most one
transition from available to a committed attempt or burn.

- Dealerless keygen and trusted import return in-memory key shares. The caller
  must explicitly commit the initial lifecycle generation with
  `InstallInitialGeneration` before `StartPresign` can load it.
- `StartPresign` loads and canonically validates the exact current generation
  before acquiring a `RunPresign` lease or emitting output.
- Figure 8 success atomically stores one available presign and completes the
  lease before exposing its public descriptor. Known non-commit leaves no
  descriptor, candidate secret, or active lease.
- A `CommitAvailablePresignFromLease` error can be outcome-unknown: the atomic
  rename may already be durable. The session exposes no descriptor and destroys
  its local candidate; the store is authoritative. Reconcile by re-reading the
  exact slot or retrying the exact lease/artifact, never by starting a new
  presign run.
- Artifact copies and encoding round trips cannot create a second slot.
- Concurrent different intents have exactly one winner; exact retries recover
  the same immutable attempt and envelope. Conflict, burn, successful commit,
  or unknown outcome excludes every other claim.
- After attempt commit, the available candidate's secret blob is absent; only
  public recovery metadata and the exact outbox remain.
- `ResumeSign` uses the exact `AttemptQuery`, never a new session or digest.

| Failure point                                                       | Availability result                              |
| ------------------------------------------------------------------- | ------------------------------------------------ |
| Invalid plan, generation, epoch, signer set, or empty-path binding  | Unchanged; no lease or attempt                   |
| Ordinary load failure before atomic mutation                        | Unchanged                                        |
| Figure 8 protocol failure                                           | No available presign                             |
| Figure 8 store known non-commit                                     | No available presign; lease aborted              |
| Figure 8 store outcome unknown                                      | No local descriptor; reconcile exact store state |
| Figure 8 atomic commit                                              | Exactly one available presign                    |
| Figure 10 validation or envelope construction failure before commit | Still available                                  |
| Attempt commit, conflict, burn, or outcome unknown                  | Unavailable to every new intent                  |
| Crash after attempt commit                                          | Recover only the exact attempt and outbox        |

Bad input never makes a partial signature or secret presign artifact
externally visible.

### Refresh, Reshare, and Child Generations

- Refresh and reshare preserve the group public key unless explicitly stated.
- Figure 7/F.1 commits public material before reveal, derives RID from every
  contribution, and derives non-zero collision-free dynamic identifiers.
- Local setup generates Paillier and auxiliary moduli through separate key
  generation, enforces both size floors, and rejects equality. Current
  validation does not explicitly check their GCD or prove independent factor
  generation to peers.
- Every proof and transcript binds the context fields available when it is
  created. Later refresh, reshare, and child-generation transcripts bind epoch,
  SID, RID, plan, source epoch, party set, and threshold; the early Figure 7
  `Πprm` exception is described above.
- Output remains unavailable until every target holder confirms the complete
  new epoch and the lifecycle cutover commits. Serialized shares reject
  missing, partial, and stripped confirmation sets.
- An interrupted transition never leaves two inconsistent usable shares;
  incomplete refresh leaves only the source usable.
- Completed refresh atomically retires the source blob and burns every
  source-epoch available presign. Protocol-level failure installs the durable
  refresh-disabled marker; pre-start and storage failures do not.
- Incomplete reshare never mixes committees; completed reshare rejects removed
  parties and accepts only the target committee. Provisional identifiers and
  transport proofs never enter the final epoch.
- A non-hardened child has a distinct key ID, fresh SID/RID/epoch and auxiliary
  material, installs through the first-generation transaction, and leaves the
  parent current.

## 6. Crash and Restart

Storage-sensitive tests reload serialized state into new objects; an in-memory
round trip is not a restart test.

Use the shared clone-on-read, compare-and-swap `CrashyStore` harness around
persistence and outbound emission. Cover stale-version conflict, before-persist
failure, after-persist unknown outcome, and explicit replacement/rejection with
secret-blob cleanup. Inject before/after persist and before/after outbound where
the phase has those boundaries.

| State at crash                               | Required state after restart                                               |
| -------------------------------------------- | -------------------------------------------------------------------------- |
| Keygen or Figure 7 incomplete/unconfirmed    | No current sign-ready generation                                           |
| Protocol confirmed, before initial install   | No current sign-ready generation                                           |
| Initial generation installation durable      | Exactly one usable current generation                                      |
| Presign lease active, artifact not committed | No available presign; finish or abort the exact lease                      |
| Available-presign commit durable             | Exactly one available public slot and secret candidate                     |
| Attempt committed or outcome unknown         | Resume only the bound attempt and exact envelope while delivery is pending |
| Delivery certificate durable                 | Resume without outbound replay                                             |
| Completion computed but not durable          | Signature unavailable; retry persists the same result                      |
| Burn durable                                 | Presign cannot start or resume an attempt                                  |
| FROST cutover before target persist          | Source is the only recoverable generation                                  |
| FROST target durable or outcome unknown      | Re-read the store; target is the only recoverable generation               |
| FROST target definite non-commit             | Source remains current; candidate is destroyed                             |
| CGGMP21 refresh/reshare before fence         | Source remains current                                                     |
| CGGMP21 fence durable, target not committed  | Reconcile the fenced transition; admit no new source work                  |
| CGGMP21 cutover committed                    | Target current; source retired; source presigns burned                     |
| Child generation not committed               | Parent current; child lineage absent                                       |
| Child first generation committed             | Parent and distinct child lineages current                                 |

`LifecycleStore` is the durability boundary.
`CommitAvailablePresignFromLease` atomically stores availability and finishes
the exact lease. `CommitSignAttempt` is the only online-sign linearization
point: it binds the presign and persists the exact canonical base envelope
before any partial is returned or emitted. Cover `AttemptCreated`,
`AttemptExistingSame`, conflict, burn, and outcome unknown.

External stores run `tssrun/conformance.RunConformance` and add backend tests
for encrypted secret blobs, atomic generation comparison, lease fencing, opaque
identifiers, crash consistency, KMS policy, and database transactions.

Delivery is durable attempt state. Cover ACK idempotency, certificate
persistence, mismatched payload/transcript/recipient rejection, and cessation of
`ResumeSign` outbound replay after delivery. Completion is durable before the
signature is externally visible; timeout or unknown outcome keeps
`Signature()` unavailable until `RetryCompletion` persists the same result.

## 7. Blame, Destruction, Import, and Reconstruction

### Blame Evidence

Blame evidence is deterministic, attributable, verifiable, and public-only.

- Invalid commitments, proofs, and signature shares blame the sender when
  attribution is possible; broadcast equivocation blames its sender.
- Replay, duplicate delivery, transport authentication failure, local misuse,
  storage corruption, and programmer error do not become cryptographic blame.
- Aggregator tampering does not blame the party whose original partial was
  changed by someone else.
- Evidence never contains shares, nonces, witnesses, Paillier private material,
  MtA secrets, reconstructed secrets, or presign secrets.

Distinguish cryptographic verification failure, transport/replay violation,
local misuse, storage failure, and terminal-state misuse by error category and
blame behavior.

### Destruction

`Destroy()` provides API-level safety: destroyed key shares, presigns, and
sessions reject cryptographic use and serialization; repeat destruction is
idempotent; and the public-metadata-after-destruction contract is explicit.

Do not claim memory-forensic zeroization. Go may copy or retain stack, heap,
`big.Int`, and slice storage. Test API inaccessibility after destruction, not
the absence of every byte from process memory.

### Trusted Import and Reconstruction

Trusted import binds target public key, chain code, session, parties, threshold,
ordered constant-term commitments, and security profile. Wrong party, session,
plan, contribution, degree-zero commitment, chain-code commitment, replayed
local claim, and malformed canonical record reject under the universal
contract.

CGGMP21 interactive import proves each party generates and retains only its own
Paillier private material. Centralized import runs the same protocol state
machines and destroys every partial share, contribution, session, and ephemeral
transport key on failure.

Reconstruction requires at least threshold unique shares from one exact
lifecycle generation. Cover insufficient and duplicate shares, mixed lifecycle
sessions, equal-public-key/different-generation metadata, destroyed or malformed
shares, threshold and larger subsets, final public-key verification, redaction,
and non-consumption of inputs. Failures and fuzz artifacts never contain
reconstructed scalars or contribution bytes.

## 8. Specialized Fuzz, Vector, and Opaque-State Contracts

- FROST semantic-decode fuzzing covers keygen commitment/proof and confidential
  shares. Seed with canonical commitment-with-proof and keygen-share records,
  plus the retired proof-less commitment shape as a reject case.
- Independent Ed25519-BIP32 oracle vectors are public-only and verify-only. They
  record the pinned oracle release, tag commit, release-asset digest, and exact
  one-time command. CI neither downloads the oracle nor exposes an update path
  through `tvgen`.
- Reshare-plan wire tests cover deterministic encoding, round trips, total size,
  tag order, exact fields, old-party verification-share order, trailing data,
  and a golden vector.
- Reflection tests prove `KeyShare`, private CGGMP21 presign artifacts,
  `EpochContext`, and CGGMP21 `ResharePlan` have no exported fields. Their byte,
  slice, map, context-path, and nested-record getters return independent
  snapshots.
- Shallow secret-handle copies share destruction state. CGGMP21 presign
  completion returns only a repeatable public descriptor after the store owns
  the normalized secret tuple.
