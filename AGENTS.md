# AGENTS.md

This repository is a security-sensitive Go threshold-signature library under
module `github.com/islishude/tss`. Protocol logic, canonical encodings,
transcripts, proof domains, lifecycle state, key shares, and presigns are
consensus and security boundaries.

## Read Before Changing Code

- Read [`docs/testing-rules.md`](docs/testing-rules.md) and
  [`docs/testing-invariants.md`](docs/testing-invariants.md) before adding,
  moving, or changing tests. They separate test tiers and design rules from
  cross-cutting, protocol, and crash/restart contracts.
- Read [`docs/security.md`](docs/security.md) and the relevant protocol document
  before changing a protocol, lifecycle, storage, transport, or secret-handling
  path.
- For CGGMP21 work, use the bundled 2024 revision of the paper at
  [`docs/cggmp21.pdf`](docs/cggmp21.pdf). Do not search for or download another
  copy of the original paper.
- `Makefile` is the source of truth for development commands, timeouts,
  parallelism, and composed checks. Run `make help` when in doubt.

## Non-Negotiable Security Rules

- Do not read, copy, port, or derive code from public TSS implementations in Go
  or any other language. Papers, RFCs, standards, and public test vectors or test
  scenarios are acceptable references.
- Keep protocol boundaries explicit:
  - `frost/ed25519` is FROST-style EdDSA over Ed25519.
  - `cggmp21/secp256k1` is CGGMP21-style threshold ECDSA over secp256k1.
- Fail closed on the wrong protocol, version, session, round, sender, recipient,
  signer set, party set, threshold, plan digest, transcript, payload type,
  scalar, point, proof, or canonical encoding.
- Reject replay, equivocation, conflicting duplicates, and out-of-order or
  cross-session messages unless a phase explicitly buffers them. Revalidate all
  buffered messages before use.
- Do not preserve retired wire shapes with compatibility shims or fallback
  decoding. There is no legacy production data to preserve. Do not introduce
  `v2`, `v3`, or similar compatibility versions for wire records, proofs, or
  challenge labels before production readiness.
- Use `internal/transcript` for repository-defined labeled SHA-256 transcripts.
  Bind every field that affects the statement, committee, session, round,
  derivation context, or result.
- Never use `math/big.Int.Exp` with a secret exponent. Secret-exponent modular
  exponentiation must go through `internal/paillier/paillierct`.
- Secret scalars must use `internal/secret.Scalar`. Do not expose them through
  `String()`, variable-length `Bytes()`, `BigInt()`, JSON, logs, panics, formatted
  errors, snapshots, or test failure messages.
- Never place private shares, nonces, Paillier private-key material, MtA secrets,
  presign secrets, trusted-dealer contributions, reconstructed secrets, or other
  witness material in `BlameEvidence`, logs, fixtures, metrics, paths, or public
  errors.
- CGGMP21 presigns are one-use objects. Reuse must remain impossible across
  digests, sessions, signer sets, key shares, derivation paths, serialization,
  shallow copies, restarts, failed commits, and concurrent calls. A commit with
  unknown outcome binds the presign to that exact attempt; recovery uses
  `ResumeSign`, never release or reuse.
- Trusted-dealer import and secret reconstruction are explicit exfiltration
  boundaries, not ordinary signing helpers. Contributions require confidential
  transport and storage. Reconstruction must require one exact lifecycle
  generation and must not silently consume, revoke, or weaken the source shares.
- Destroy rejected, superseded, consumed, or no-longer-needed secret state on all
  success and failure paths. Do not claim zeroization guarantees that Go and the
  implementation cannot prove.

## Current Public Surface

- Root package `tss`: party/session identifiers, shared plan/context types, envelopes,
  authenticated inbound opening, policy sets, guards, broadcast certificates,
  replay protection, blame evidence, HD signing context, refresh scheduling, and
  reference passphrase-encryption helpers.
- `tssrun`: transport- and database-neutral run intent, durable lifecycle,
  session registry, dispatch, unknown-session policy, key-share store, presign
  inventory, and cutover contracts. Memory implementations are reference/test
  helpers, not production durability.
- `frost/ed25519`: dealerless DKG, explicitly authorized trusted-dealer import,
  threshold reconstruction, two-round signing, partial verification,
  Ed25519-compatible aggregation, same-party refresh, party/threshold resharing,
  and non-hardened BIP32-style derivation.
- `cggmp21/secp256k1`: dealerless DKG, explicitly authorized trusted-dealer
  import, threshold reconstruction, offline presign, one-round online signing,
  proactive refresh, party/threshold resharing, non-hardened BIP32 derivation,
  and attributable-abort evidence.

The repository is not a production-audited TSS stack. The CGGMP21 Paillier/ZK
layer still requires independent cryptographic review. Do not turn implemented
behavior into claims of production readiness, audit completion, crash safety,
constant-time execution, or secure deletion without matching code and evidence.

## Architecture and Ownership

- Protocol sessions own state-machine validation and transitions. Inbound
  handlers follow:

  ```text
  decode -> policy validate -> cryptographic verify -> prepare transition -> commit -> effects
  ```

  Rejected input must not mutate accepted state or emit effects. Construct
  outbound envelopes before committing the state that makes them visible.

- `internal/wire` owns strict canonical TLV encoding. Production protocol code
  uses the object-level `wire.Marshal`/`wire.Unmarshal` API, not field-level
  codecs.
- `internal/transcript` owns canonical labeled SHA-256 transcript construction.
- `internal/secret` owns fixed-length secret scalar and signed-integer wrappers.
- `internal/paillier` and `internal/paillier/paillierct` own Paillier operations
  and constant-time secret-exponent paths.
- `internal/mta` owns Paillier MtA helpers used by CGGMP21.
- `internal/zk/*` owns the proof systems and their domains.
- `internal/shamir`, `internal/bip32util`, and `internal/curve/*` own sharing,
  derivation, and curve-specific primitives.
- `internal/testharness` and `internal/testutil` own deterministic runners,
  schedules, mutations, snapshots, fixtures, and reduced-parameter test controls.
  Do not create a competing harness inside a protocol package.
- `internal/testvectors` is the only canonical location for committed binary
  golden records, protocol vectors, and generated fixture caches. Follow
  [`internal/testvectors/README.md`](internal/testvectors/README.md).

Keep files focused on one responsibility. Prefer protocol-local helpers; add a
shared abstraction only when it centralizes an invariant used by multiple
packages. Long-lived validated state such as key shares, presigns, and reshare
plans must remain opaque and return defensive copies from accessors.

## Change Workflow

1. Trace the current public entry point, plan digest, wire record, transcript,
   state transition, persistence boundary, and tests before editing.
2. Make the narrowest change that preserves or strengthens the required
   invariant. Remove obsolete paths instead of layering compatibility branches.
3. Add reject-path coverage for malformed, duplicate, replayed, equivocated,
   out-of-order, cross-session, wrong-plan, and conflicting input where relevant.
   Assert both the error category and absence of unsafe state mutation or effects.
4. Keep randomness deterministic or reproducible. Do not mutate package defaults
   in tests; pass explicit test `Limits` and `SecurityParams` through plan options
   or `WithLimits` APIs.
5. Update golden records and protocol vectors only for an intentional contract
   change. Verify canonical decode, validation, and re-encode behavior.
6. Update protocol docs, security notes, examples, deployment guidance, and test
   rules whenever their described behavior or boundary changes.

Every exported identifier requires a Go doc comment beginning with its name.
Comments on internal code should explain equations, domains, invariants,
ownership, failure behavior, or non-obvious security constraints rather than
restate syntax.

## Validation

Prefer the smallest command that exercises the changed area:

```sh
# Fast build, vet, lint, formatting, module, wire-API, and transcript-API checks.
make check

# Fast PR-grade checks, including Tier 0 and reduced-parameter Tier 1 tests.
make ci

# Full lifecycle and adversarial protocol flows.
make test-integration

# Production-parameter Paillier/ZK smoke tests.
make test-slowcrypto

# Integration flows under the race detector.
make test-race

# Short fuzz pass for changed decoder or reject-path targets.
make fuzz-smoke

# Verify all committed wire, protocol, and fixture vectors.
make vectors-verify-all
```

Use `gofmt -w` for changed Go files and Prettier for changed Markdown, JSON, and
YAML. `make fix-all` is source-modifying and should be used deliberately. Do not
run race, slow-crypto, stress, or long fuzz suites by default; select them when
the changed boundary or task justifies the cost.

## Documentation Contract

- Update `docs/*.md` when behavior, API, wire format, proof statement, security
  assumption, lifecycle, storage, transport, recovery, or deployment expectations
  change.
- Update `docs/testing-rules.md` for test tiers or shared testing practices, and
  `docs/testing-invariants.md` for durable invariant classes, protocol phases,
  or lifecycle coverage contracts.
- Add or update executable external-package examples when a public API changes.
- Keep README status and capability claims synchronized with executable code and
  current review status.
