# AGENTS.md

This repository contains a Go TSS library under module `github.com/islishude/tss`.

## Non-Negotiable Constraints

- Do not read, copy, port, or derive code from public TSS implementations in Go or any other language.
- It is acceptable to use papers, RFCs, standards, and public test vectors or test scenarios.
- Keep the protocol boundary honest: CGGMP21 applies to ECDSA/secp256k1; Ed25519 uses FROST-style EdDSA.
- Do not remove the experimental warning from `cggmp21/secp256k1` until the full Paillier MtA/ZK CGGMP21 signing path exists and has been reviewed.

## Useful Commands

```sh
go test -race ./...
golangci-lint run --fix
```

Run both test commands before handing off substantial changes.

## Architecture Map

- Root package `tss`: transport-neutral session ids, envelopes, errors, blame evidence, common interfaces.
- `frost/ed25519`: DKG, two-round signing, partial verification, Ed25519-compatible aggregation.
- `cggmp21/secp256k1`: planned CGGMP21 API shape and experimental threshold ECDSA flow.
- `internal/shamir`: Shamir sharing and interpolation over caller-provided prime-order fields.
- `internal/curve/edwards25519`: Ed25519 scalar/point helpers and commitment verification.
- `internal/curve/secp256k1`: SEC 2 curve constants, point operations, ECDSA helpers.
- `internal/mta`: Paillier MtA product-share helpers for CGGMP21-style signing.
- `internal/paillier`: Paillier primitives used by CGGMP21-style MtA signing.
- `internal/wire`: strict TLV encoding for binary envelopes, key shares, and presign records.
- `internal/zk/paillier`: Paillier encryption, range, modulus, and MtA response proofs.
- `internal/zk/schnorr`: Schnorr proof-of-knowledge primitive over secp256k1.

## Coding Rules

- Prefer small, protocol-local helpers over broad abstractions.
- Keep message decoding fail-closed: wrong session, round, sender, recipient, duplicate message, malformed scalar/point, or transcript mismatch must error.
- Preserve deterministic `MarshalBinary` / `UnmarshalBinary` behavior for key-share types.
- Do not add JSON fallback to binary decoders; use migration helpers separately if legacy data is ever needed.
- Preserve deterministic `BlameEvidence` encoding; never place private shares, nonces, or Paillier private-key material in blame evidence.
- CGGMP21 verification failures that can identify a sender or signer set should populate `ProtocolError.Blame.Evidence` unless the failure is duplicate/replay handling.
- Add Go doc comments for every new exported identifier; comments must start with the identifier name so `doccheck_test.go` can enforce them.
- Add comments around protocol equations, transcript/domain separation, and security-sensitive shortcuts.
- When adding API, wire-format, or protocol behavior, update the relevant `docs/*.md` file and add or refresh an executable example when the public surface changes.
- Avoid comments that restate the line; explain why the check or formula exists.
- Never log or format secret scalar, nonce, or key-share bytes.

## Testing Expectations

When changing protocol behavior, add or update tests for:

- success paths for `1-of-1`, `2-of-3`, and `3-of-5`;
- duplicate/replayed messages;
- malformed scalar/point payloads;
- incorrect session id or signer set;
- signature verification failure and blame attribution when applicable.
