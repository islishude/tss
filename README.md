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

| Package                                      | Purpose                                                                                                                                                                                  |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.com/islishude/tss`                   | Shared party/session types, envelopes, authenticated inbound opening, guards, replay protection, broadcast certificates, blame evidence, HD signing context, and refresh scheduling.     |
| `github.com/islishude/tss/tssrun`            | Transport- and database-neutral contracts for accepted run intent, durable lifecycle, session registration, dispatch, unknown-session policy, presign inventory, and generation cutover. |
| `github.com/islishude/tss/frost/ed25519`     | FROST-style threshold Ed25519 with standard Ed25519 verification keys and signatures.                                                                                                    |
| `github.com/islishude/tss/cggmp21/secp256k1` | CGGMP21-style threshold ECDSA with Paillier MtA and zero-knowledge proofs.                                                                                                               |

The library does not provide a production network, peer authentication, KMS/HSM,
database, distributed scheduler, or deployment control plane. `tssrun` memory
stores and the built-in passphrase/file helpers are reference implementations,
not production durability or key management.

## Implemented Protocol Surface

| Capability                     | `frost/ed25519`                                                          | `cggmp21/secp256k1`                                               |
| ------------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| Dealerless key generation      | 2 rounds; confirmation is round 2                                        | 3 rounds; confirmation is round 3                                 |
| Trusted-dealer import          | Interactive contribution flow and centralized provisioning helper        | Interactive contribution flow and centralized provisioning helper |
| Explicit secret reconstruction | Threshold interpolation of the canonical Ed25519 group scalar            | Threshold interpolation of the secp256k1 private scalar           |
| Signing                        | 2 online rounds; partial verification and Ed25519-compatible aggregation | 3-round offline presign plus 1-round online sign                  |
| Proactive refresh              | Same party set and threshold                                             | Same party set and threshold, with Paillier key rotation          |
| Resharing                      | Party-set and threshold change with target-holder confirmation           | Old-dealer/new-receiver party-set and threshold change            |
| HD derivation                  | Non-hardened BIP32-style public derivation                               | Non-hardened BIP32 public derivation and extended public keys     |
| Failure evidence               | Public blame evidence for attributable protocol failures                 | Signed equivocation and conditional identifiable-abort evidence   |

FROST signatures are standard 64-byte Ed25519 signatures accepted by
`crypto/ed25519.Verify`. The implementation follows RFC 9591 signing equations
and domain separation but adds dealerless DKG, lifecycle binding, refresh,
resharing, and BIP32-style derivation; it should be described as FROST-style, not
as a wire-compatible implementation of every RFC ciphersuite.

CGGMP21 signing never reconstructs the private key or nonce shares. Its Paillier
proof layer uses CGGMP-compatible Πenc, Πaff-g, and Πlog\* statements, with CGGMP24
Πmod and Ring-Pedersen Πprm semantics. See the
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
5. Persist key shares, presigns, sign-attempt state, refresh/reshare cutovers, and
   completion results at the documented durable boundary before making them
   visible.

`tssrun` makes run admission, session registry, unknown-session handling, and
durable cutover interfaces explicit while leaving the transport and database to
the application. See [docs/tssrun.md](docs/tssrun.md) for its contracts and
[docs/deployment.md](docs/deployment.md) for the operational model.

### CGGMP21 Presign Safety

CGGMP21 presigns are strictly one-use. `StartSign` requires an atomic durable
`SignAttemptStore` that binds a presign to one immutable intent and exact outbound
envelope before transmission. A timeout or I/O error during commit has unknown
outcome: retry or call `ResumeSign` for the same attempt. Never release or reuse
the presign. Custom stores should pass
`secp256k1test.RunSignAttemptStoreSuite`.

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
