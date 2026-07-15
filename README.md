# tss

Transport- and storage-neutral threshold-signature protocols for Go.

The module provides FROST-style threshold Ed25519 and CGGMP21-style threshold
ECDSA over secp256k1, together with authenticated envelope handling, durable run
integration contracts, strict canonical wire records, refresh/reshare flows, and
non-hardened HD derivation.

> [!WARNING]
> This repository is not a production-audited TSS stack. In particular, the
> CGGMP21 Paillier/ZK layer has not received independent cryptographic review.
> Treat public APIs and wire records as pre-production and review
> [the security model](docs/security.md) before evaluating or integrating the
> library.

## Requirements and Installation

The module currently requires Go 1.26.3 or later.

```sh
go get github.com/islishude/tss
```

## Packages

| Package                                      | Purpose                                                                                                                                                                              |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `github.com/islishude/tss`                   | Shared party/session types, envelopes, authenticated inbound opening, guards, replay protection, broadcast certificates, blame evidence, HD signing context, and refresh scheduling. |
| `github.com/islishude/tss/tssrun`            | Transport- and database-neutral contracts for accepted run intent, unified generation/presign/sign lifecycle, session registration, dispatch, unknown-session policy, and cutover.   |
| `github.com/islishude/tss/frost/ed25519`     | FROST-style threshold Ed25519 with standard Ed25519 verification keys and signatures.                                                                                                |
| `github.com/islishude/tss/cggmp21/secp256k1` | CGGMP21-style threshold ECDSA with Paillier MtA and zero-knowledge proofs.                                                                                                           |

The library does not provide a production network, peer authentication, KMS/HSM,
database, distributed scheduler, or deployment control plane. `tssrun` memory
stores and the built-in passphrase/file helpers are reference implementations,
not production durability or key management.

## Implemented Protocol Surface

| Capability                     | `frost/ed25519`                                                          | `cggmp21/secp256k1`                                                                                |
| ------------------------------ | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| Dealerless key generation      | 3 rounds; proof-gated shares and round-3 confirmation                    | 3 rounds; confirmation is round 3                                                                  |
| Trusted-dealer import          | Interactive contribution flow and centralized provisioning helper        | Interactive contribution flow and centralized provisioning helper                                  |
| Explicit secret reconstruction | Threshold interpolation of the canonical Ed25519 group scalar            | Threshold interpolation of the secp256k1 private scalar                                            |
| Signing                        | 2 online rounds; partial verification and Ed25519-compatible aggregation | 3-round offline presign plus 1-round online sign                                                   |
| Proactive refresh              | Same party set and threshold                                             | Same party set and threshold, with Paillier key rotation                                           |
| Resharing                      | Party-set and threshold change with target-holder confirmation           | Old-dealer/new-receiver party-set and threshold change                                             |
| HD derivation                  | Non-hardened BIP32-style public derivation                               | Explicit non-hardened child generation with a fresh auxiliary epoch                                |
| Failure evidence               | Public blame evidence for attributable protocol failures                 | Signed equivocation, Figure 7 accusations, Figure 9 proofs, and direct invalid-partial attribution |

FROST signatures are standard 64-byte Ed25519 signatures accepted by
`crypto/ed25519.Verify`. The two-round signing protocol follows RFC 9591 signing
equations and domain separation. RFC 9591 does not specify dealerless key
generation: this repository's three-round dealerless DKG follows the original
FROST paper, including a required Schnorr proof of knowledge for every dealer's
constant term before confidential shares are released. Lifecycle confirmation,
refresh, resharing, production nonce binding, and BIP32-style derivation are
repository extensions, so the package should be described as FROST-style rather
than as a wire-compatible implementation of every RFC ciphersuite.

FROST signing accepts any canonical signer set whose size is between the key's
threshold and committee size by default; callers may opt back into an
exact-threshold policy. An identity aggregate nonce commitment is an unblamed
terminal verification failure and clears the session's signing state.

CGGMP21 signing never reconstructs the private key or nonce shares. The current
path implements paper Figures 6-10: Figure 7/F.1 creates each auxiliary epoch,
Figure 8 uses Πenc-elg, Πelog, and Πaff-g, Figure 9 uses setup-less Πaff-g\* and
Πdec, and Figure 10 verifies every normalized partial directly. It combines
those relations with CGGMP24-style Πmod and Ring-Pedersen Πprm semantics. See the
[proof inventory](docs/paillier-zk-proofs.md) and
[audit guide](docs/audit-guide.md) for the current review surface.

Production defaults fail closed. Protocol `DefaultLimits` values are not relaxed
test profiles, and CGGMP21 `DefaultSecurityParams` is the production
cryptographic profile. Explicit non-production profiles are protocol intent and
are bound into plans and persisted state.

## Quick Start

Run the executable 2-of-2 FROST DKG and signing example:

```sh
go test ./frost/ed25519 -run '^ExampleSign$' -count=1
```

Run the CGGMP21 production-policy lifecycle example, which covers DKG,
persistence, offline presign, and online signing:

```sh
go test -tags=integration ./cggmp21/secp256k1 \
  -run '^Example_full_lifecycle$' -count=1
```

The examples simulate multiple parties in one process, but use the public plan,
guard, envelope, and state-machine APIs. They are executable integration
references, not deployment templates. Start with
[`frost/ed25519/examples_test.go`](frost/ed25519/examples_test.go),
[`cggmp21/secp256k1/integration_example_test.go`](cggmp21/secp256k1/integration_example_test.go),
and the [production integration model](docs/integration.md).

Trusted import has separate executable examples; the FROST example also performs
explicit threshold reconstruction:

```sh
go test ./frost/ed25519 -run '^ExampleGenerateTrustedDealerKeyShares$' -count=1
go test ./cggmp21/secp256k1 -run '^ExampleNewTrustedDealerImport$' -count=1
```

## Integration Model

Each participant runs one local protocol state machine. A real deployment must:

1. Authenticate and durably accept one public run intent with a fresh,
   unpredictable session ID.
2. Reconstruct the same protocol plan at every party and accept the same plan
   digest before releasing data-plane messages.
3. Build an `EnvelopeGuard` with the protocol policy set, durable replay cache,
   broadcast-ack verifier, and required envelope signature verifier.
4. Authenticate the transport peer, classify actual channel confidentiality,
   call `tss.OpenEnvelope`, and route the resulting `InboundEnvelope` to the
   registered session. Secret-bearing direct payloads require confidential
   delivery; broadcast payloads require complete consistency certificates.
5. Use one transactional `tssrun.LifecycleStore` boundary for exact key
   generations, run leases, available presigns, online attempts,
   refresh/reshare cutovers, explicit child generations, and completion results.

`tssrun` makes run admission, session registry, unknown-session handling, and
durable cutover interfaces explicit while leaving the transport and database to
the application. See [docs/tssrun.md](docs/tssrun.md) for its contracts and
[docs/deployment.md](docs/deployment.md) for the operational model.

The shared test harness includes a clone-on-read, compare-and-swap `CrashyStore`
for before/after-persist fault injection. Refresh and reshare restart tests use
it to prove that recovery selects only the authoritative durable generation:
the source remains usable before persistence, while a durable or
outcome-unknown target commit requires re-reading and using the target.

### CGGMP21 Presign Safety

CGGMP21 presigns are strictly one-use. `StartSign` requires an atomic durable
`LifecycleStore` transaction that validates the exact current generation,
claims one available public `PresignID`, and persists one immutable intent and
exact outbound envelope before transmission. Figure 8 completion stores the
normalized secret tuple atomically and exposes only a public persisted
descriptor. A timeout or I/O error during the online commit has unknown
outcome: reconcile or call `ResumeSign` for the exact same attempt. Never
release or reuse the presign. Custom stores should pass
`tssrun/conformance.RunConformance` and backend-specific crash tests.

### Trusted Import and Secret Reconstruction

These APIs intentionally cross the normal threshold-confidentiality boundary and
must be authorized as separate key ceremonies:

- A `TrustedDealerContribution` is secret material bound to one plan, session,
  and party. Encrypt it in transit and at rest, never log it, and destroy it after
  use.
- `GenerateTrustedDealerKeyShares` centralizes every generated share in one
  process. For CGGMP21 that also centralizes all Paillier private keys. Prefer the
  interactive contribution flow when participants should generate their own
  auxiliary private material.
- `ReconstructSecretKey` requires a threshold of unique shares from one exact
  lifecycle generation. It neither consumes nor revokes those shares.
- `SecretKey.MarshalBinary` is an explicit exfiltration boundary and returns a
  caller-owned 32-byte secret that must be cleared. FROST reconstructs the group
  scalar, not the original RFC 8032 seed.

See the [secret-material lifecycle](docs/security.md#secret-material-lifecycle)
and [deployment ceremonies](docs/deployment.md#2-trusted-dealer-import-and-export-ceremonies)
before using these APIs.

## Development and Verification

The Makefile keeps ordinary checks separate from deliberately expensive crypto,
race, stress, and fuzz suites:

| Command                   | Scope                                                                     |
| ------------------------- | ------------------------------------------------------------------------- |
| `make help`               | List all supported development targets.                                   |
| `make check`              | Build, vet, lint, format/module hygiene, and API-boundary checks.         |
| `make ci`                 | `make check` plus Tier 0 and reduced-parameter Tier 1 tests.              |
| `make test-integration`   | Tier 2 full lifecycle, adversarial delivery, restart, and recovery flows. |
| `make test-slowcrypto`    | Tier 3 production-parameter Paillier/ZK smoke tests.                      |
| `make test-race`          | Integration flows under the race detector.                                |
| `make fuzz-smoke`         | Short fuzz pass for decoder and reject-path targets.                      |
| `make vectors-verify-all` | Verify committed wire, protocol, and fixture vectors.                     |

Testing policy and invariant requirements live in
[`docs/testing-rules.md`](docs/testing-rules.md). Canonical vector commands and
layout live in
[`internal/testvectors/README.md`](internal/testvectors/README.md).

## Documentation

| Area         | Documents                                                                                                                                                                           |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Integration  | [Production run model](docs/integration.md), [`tssrun` contracts](docs/tssrun.md), [deployment](docs/deployment.md)                                                                 |
| Security     | [Threat model and caller responsibilities](docs/security.md), [wire format](docs/wire.md), [root package](docs/root-package.md)                                                     |
| Protocols    | [FROST Ed25519](docs/frost-ed25519.md), [CGGMP21 secp256k1](docs/cggmp21-secp256k1.md)                                                                                              |
| Review       | [Architecture](docs/architecture.md), [Paillier/ZK proofs](docs/paillier-zk-proofs.md), [audit guide](docs/audit-guide.md), [CGGMP21 checklist](docs/cggmp21-protocol-checklist.md) |
| Verification | [Testing rules](docs/testing-rules.md), [test inventory](docs/test-inventory.md), [test vectors](internal/testvectors/README.md)                                                    |

## License

[MIT](LICENSE)
