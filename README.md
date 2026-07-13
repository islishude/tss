# tss

Go threshold-signature building blocks.

| Package             | Description                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------- |
| `frost/ed25519`     | FROST-style threshold Ed25519 ([RFC 9591 (FROST)](https://www.rfc-editor.org/rfc/rfc9591)). |
| `cggmp21/secp256k1` | [CGGMP21-style](https://eprint.iacr.org/2021/060) threshold ECDSA with Paillier MtA.        |

## Status

`frost/ed25519` implements a usable FROST flow: dealerless DKG, trusted-dealer key import, explicit threshold reconstruction, two-round signing, partial verification, Ed25519-compatible aggregation, resharing, and BIP32-Ed25519 HD derivation.

`cggmp21/secp256k1` implements dealerless DKG, trusted-dealer key import, explicit threshold reconstruction, offline presigning, single-round online signing, proactive refresh, resharing, BIP32 HD derivation, and blame attribution. Paillier proof layer uses CGGMP24 Πmod and Ring-Pedersen Πprm semantics.

`DefaultLimits` always returns production fail-closed local policy. Tests that
need relaxed bounds pass explicit `Limits` through plan options or `WithLimits`
APIs. CGGMP21 `DefaultSecurityParams` is the production cryptographic profile;
explicit non-production profiles are shared protocol intent, included in plan
digests, and persisted with key shares, presigns, and reshare plans.

## Quick Start

### Ed25519 (FROST)

Run the executable 2-of-2 DKG and signing example:

```sh
go test ./frost/ed25519 -run '^ExampleSign$' -count=1
```

The example constructs guards with `tss.GuardConfig.BuildGuard`, signs broadcast
acknowledgments with Ed25519 identity keys, attaches complete broadcast
certificates, and marks direct share messages confidential. See
[`frost/ed25519/examples_test.go`](frost/ed25519/examples_test.go) and its
[`example_helpers_test.go`](frost/ed25519/example_helpers_test.go) transport
adapter.

### secp256k1 (CGGMP21)

Run the executable DKG, persistence, presign, and online-signing example:

```sh
go test -tags=integration ./cggmp21/secp256k1 \
  -run '^Example_full_lifecycle$' -count=1
```

The integration example uses production policy sets and guards, complete
broadcast certificates, confidential direct delivery, and an atomic
encrypted file-backed `SignAttemptStore`. A deployment must replace the
in-process transport, replay cache, identity keys, and reference file store with
durable database/KMS-backed application infrastructure. Keep CGGMP21 presigns
bound to a durable immutable sign attempt once committed, outcome-unknown, or
possibly sent. Availability is recovered by `ResumeSign`, not by releasing the
presign. Custom `SignAttemptStore` implementations should run
`secp256k1test.RunSignAttemptStoreSuite`. See
[`cggmp21/secp256k1/integration_example_test.go`](cggmp21/secp256k1/integration_example_test.go),
[`example_integration_helpers_test.go`](cggmp21/secp256k1/example_integration_helpers_test.go),
and the lightweight public-vector examples in
[`examples_test.go`](cggmp21/secp256k1/examples_test.go).

Executable examples simulate multiple parties in one process. Production
deployments should follow [docs/integration.md](docs/integration.md): create
one public run intent, distribute one session ID, reconstruct equivalent plans
locally, and route envelopes over authenticated transport.

## Documentation

| Document                                                                 | Content                                                                                       |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| [docs/root-package.md](docs/root-package.md)                             | Root package types, envelopes, errors, blame evidence.                                        |
| [docs/integration.md](docs/integration.md)                               | Production protocol-run model: control plane, session IDs, plan metadata, routing, recovery.  |
| [docs/tssrun.md](docs/tssrun.md)                                         | Public integration API for run stores, session registry, dispatching, and durable boundaries. |
| [docs/frost-ed25519.md](docs/frost-ed25519.md)                           | Full FROST Ed25519 protocol: DKG, signing, resharing, BIP32.                                  |
| [docs/cggmp21-secp256k1.md](docs/cggmp21-secp256k1.md)                   | Full CGGMP21 secp256k1 protocol: keygen, presign, signing, refresh, resharing, HD derivation. |
| [docs/architecture.md](docs/architecture.md)                             | Package boundaries, transport model, state-machine lifecycle.                                 |
| [docs/security.md](docs/security.md)                                     | Threat model, caller responsibilities, constant-time Paillier, secret lifecycle.              |
| [docs/wire.md](docs/wire.md)                                             | Canonical TLV encoding rules and decoder policy.                                              |
| [docs/paillier-zk-proofs.md](docs/paillier-zk-proofs.md)                 | Paillier ZK proof inventory, usage by phase, review blockers.                                 |
| [docs/audit-guide.md](docs/audit-guide.md)                               | Complete proof-to-paper mapping for cryptographic review.                                     |
| [docs/deployment.md](docs/deployment.md)                                 | Production guide: key lifecycle, transport, backups, monitoring.                              |
| [docs/cggmp21-protocol-checklist.md](docs/cggmp21-protocol-checklist.md) | Implementation tracking against the CGGMP21 specification.                                    |
| [docs/testing-rules.md](docs/testing-rules.md)                           | Test tiers, required invariants, fuzzing, golden vectors, crash/restart expectations.         |

## Security

See [docs/security.md](docs/security.md) for the threat model, caller responsibilities, secret-material lifecycle, constant-time Paillier constraints, and production checklist.
