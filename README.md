# tss

Transport- and storage-neutral threshold-signature protocols for Go.

The module provides FROST-style threshold Ed25519 and CGGMP21-style threshold
ECDSA over secp256k1, plus shared envelope validation, durable integration
contracts, refresh and resharing, and non-hardened HD derivation.

> [!WARNING]
> This repository is not a production-audited TSS stack. The CGGMP21
> Paillier/ZK layer has not received independent cryptographic review. Treat
> the APIs and wire records as pre-production, and read the
> [security model](docs/security.md) before evaluating an integration.

## Requirements

Go 1.26.3 or later is required.

```sh
go get github.com/islishude/tss
```

## Packages

| Package                                      | Responsibility                                                                                                          |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `github.com/islishude/tss`                   | Shared identifiers, envelopes, guards, replay and broadcast validation, signing context, HD types, and refresh helpers. |
| `github.com/islishude/tss/tssrun`            | Run acceptance, active-session routing, unknown-session policy, and durable lifecycle interfaces.                       |
| `github.com/islishude/tss/frost/ed25519`     | FROST-style Ed25519 DKG, signing, refresh, resharing, import, reconstruction, and derivation.                           |
| `github.com/islishude/tss/cggmp21/secp256k1` | CGGMP21-style threshold ECDSA, including Paillier MtA and zero-knowledge proofs.                                        |

The library does not provide a production network, peer authentication,
database, KMS/HSM, distributed scheduler, or control plane. In-memory stores,
the passphrase helpers, and `tssrun.FileLifecycleStore` are reference
implementations, not production durability or key management.

## Protocol Surface

| Capability            | `frost/ed25519`                                                | `cggmp21/secp256k1`                                                                     |
| --------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Dealerless keygen     | Three-round proof-gated DKG with final confirmation            | Figure 6 followed by Figure 7/F.1 and final confirmation                                |
| Trusted import        | Interactive contributions or centralized provisioning          | Interactive contributions or centralized provisioning                                   |
| Reconstruction        | Explicit interpolation of the canonical Ed25519 group scalar   | Explicit interpolation of the secp256k1 private scalar                                  |
| Signing               | Two online rounds; standard 64-byte Ed25519 signature          | Three-round Figure 8 presign; one-round Figure 10 signing                               |
| Refresh               | Same party set and threshold; caller-managed compare-and-swap  | Same party set and threshold; lifecycle-managed auxiliary-key rotation and cutover      |
| Resharing             | Party-set and threshold change with target-holder confirmation | Old-dealer/new-receiver handoff, fresh Figure 7/F.1 epoch, and lifecycle-managed commit |
| HD derivation         | Local non-hardened Ed25519-BIP32-style public derivation       | Explicit non-hardened child lineage with a fresh auxiliary epoch                        |
| Attributable failures | Public blame evidence for defined failure classes              | Signed equivocation, Figure 7 accusations, Figure 9 proofs, and invalid partials        |

FROST signing uses RFC 9591 signing equations and produces signatures accepted
by `crypto/ed25519.Verify`. Dealerless DKG, lifecycle confirmation, refresh,
resharing, nonce binding, and Ed25519-BIP32-style derivation are repository
extensions, so the package is described as FROST-style rather than as a
wire-compatible implementation of an RFC ciphersuite.

CGGMP21 follows Figures 6-10 of the bundled 2024 paper revision. The current
proof inventory and implementation mapping live in
[`docs/paillier-zk-proofs.md`](docs/paillier-zk-proofs.md) and
[`docs/cggmp21-paper-mapping.md`](docs/cggmp21-paper-mapping.md).

Default limits and CGGMP21 security parameters are production-policy profiles.
Reduced profiles are explicit non-production intent and are bound into plans
and persisted state where applicable.

## Quick Start

Run the executable 2-of-2 FROST DKG and signing example:

```sh
go test ./frost/ed25519 -run '^ExampleSign$' -count=1
```

Run the integration-tagged CGGMP21 lifecycle example:

```sh
go test -tags=integration ./cggmp21/secp256k1 \
  -run '^Example_full_lifecycle$' -count=1
```

These examples simulate several parties in one process while exercising the
public plans, guards, envelopes, and state machines. They are executable
references, not deployment templates. See
[`frost/ed25519/examples_test.go`](frost/ed25519/examples_test.go),
[`cggmp21/secp256k1/integration_example_test.go`](cggmp21/secp256k1/integration_example_test.go),
and the [integration model](docs/integration.md).

Trusted-import examples are separate:

```sh
go test ./frost/ed25519 -run '^ExampleGenerateTrustedDealerKeyShares$' -count=1
go test ./cggmp21/secp256k1 -run '^ExampleNewTrustedDealerImport$' -count=1
```

## Integration Boundary

Each participant runs one local state machine. A deployment must:

1. Authorize and durably accept one `tssrun.RunIntent` with a fresh shared
   session ID.
2. Reconstruct the same protocol plan at every party and accept the same
   `RunIntent.AcceptanceDigest()` before releasing data-plane messages.
3. Build an `EnvelopeGuard` with the protocol policy set, durable replay cache,
   broadcast-ack verifier, and any required envelope-signature verifier.
4. Derive `ReceiveInfo` from the authenticated transport, call
   `tss.OpenEnvelope`, and dispatch the immutable `InboundEnvelope` to the
   registered local session. Secret direct messages require confidential
   transport; broadcast messages require the configured consistency
   certificate.
5. Persist key generations and protocol results at their documented durable
   boundary. Current CGGMP21 presign, sign, refresh, reshare, and child flows
   use `tssrun.LifecycleStore` directly; FROST keygen, refresh, and reshare
   return caller-owned shares for application-managed persistence.

See [`docs/tssrun.md`](docs/tssrun.md) for API contracts,
[`docs/integration.md`](docs/integration.md) for the end-to-end flow, and
[`docs/deployment.md`](docs/deployment.md) for operational controls.

CGGMP21 presigns are one-use. A commit with unknown outcome remains bound to
the exact attempt; reconcile it or call `ResumeSign`, and never release or
reuse the presign. Trusted import and reconstruction are separate, explicitly
authorized exfiltration ceremonies. See
[`docs/security.md`](docs/security.md) for both boundaries.

## Development

The `Makefile` is the command source of truth:

| Command                   | Scope                                                                 |
| ------------------------- | --------------------------------------------------------------------- |
| `make help`               | List supported targets.                                               |
| `make check`              | Build, vet, lint, formatting/module hygiene, and API-boundary checks. |
| `make ci`                 | `make check` plus Tier 0 and reduced-parameter Tier 1 tests.          |
| `make test-integration`   | Tier 2 lifecycle, adversarial delivery, restart, and recovery flows.  |
| `make test-slowcrypto`    | Tier 3 production-parameter Paillier/ZK smoke tests.                  |
| `make test-race`          | Integration flows under the race detector.                            |
| `make fuzz-smoke`         | Short decoder and reject-path fuzz runs.                              |
| `make vectors-verify-all` | Verify committed wire, protocol, and fixture vectors.                 |

Read [`docs/testing-rules.md`](docs/testing-rules.md) for test selection and
[`docs/testing-invariants.md`](docs/testing-invariants.md) for required
behavioral contracts.

## Documentation

| Area         | Entry points                                                                                                                                                                        |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Integration  | [Integration model](docs/integration.md), [`tssrun` API](docs/tssrun.md), [deployment](docs/deployment.md)                                                                          |
| Security     | [Threat model](docs/security.md), [wire format](docs/wire.md), [root package](docs/root-package.md)                                                                                 |
| Protocols    | [FROST Ed25519](docs/frost-ed25519.md), [CGGMP21 secp256k1](docs/cggmp21-secp256k1.md)                                                                                              |
| Review       | [Architecture](docs/architecture.md), [Paillier/ZK proofs](docs/paillier-zk-proofs.md), [audit guide](docs/audit-guide.md), [CGGMP21 checklist](docs/cggmp21-protocol-checklist.md) |
| Verification | [Testing rules](docs/testing-rules.md), [testing invariants](docs/testing-invariants.md), [test inventory](docs/test-inventory.md), [vectors](internal/testvectors/README.md)       |

## License

[MIT](LICENSE)
