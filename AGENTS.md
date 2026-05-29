# AGENTS.md

This repository contains a Go TSS library under module `github.com/islishude/tss`.

## Non-Negotiable Constraints

- Do not read, copy, port, or derive code from public TSS implementations in Go or any other language.
- It is acceptable to use papers, RFCs, standards, and public test vectors or test scenarios.
- Keep the protocol boundary honest: CGGMP21 applies to ECDSA/secp256k1; Ed25519 uses FROST-style EdDSA.
- Do not preserve prior-format fallback paths while moving toward the production target. Existing conversion code for retired wire shapes must be removed rather than supported.
- Do not remove the experimental warning from `cggmp21/secp256k1` until an independent cryptographic review of the full Paillier MtA/ZK proof layer is complete.
- Never use `math/big.Int.Exp` when the exponent is a secret (`λ`, `μ`, `b` in MtA). All secret-exponent modular exponentiation must go through `internal/paillier/paillierct` (`filippo.io/bigmod`).
- Secret scalars must use `secret.Scalar` (fixed-length bytes). Never expose them via `String()`, variable-length `Bytes()`, `BigInt()`, or JSON.

## Useful Commands

```sh
# Test
go test -race ./...
# Lint and format golang files
golangci-lint run --fix
# Format markdown files
npx -y prettier --write '*.md' 'docs'
```

## Architecture Map

- Root package `tss`: transport-neutral session ids, envelopes, errors, blame evidence, common interfaces, session-id generation, and reference storage-encryption helpers.
- `frost/ed25519`: dealerless FROST-style Ed25519 DKG, two-round signing, partial verification, Ed25519-compatible aggregation, and resharing.
- `cggmp21/secp256k1`: CGGMP21-style threshold ECDSA keygen, presign, online signing, resharing, proactive refresh, BIP32 HD derivation, RefreshScheduler, and evidence verification.
- `internal/shamir`: Shamir sharing and interpolation over caller-provided prime-order fields.
- `internal/curve/edwards25519`: Ed25519 scalar/point helpers and commitment verification.
- `internal/curve/secp256k1`: SEC 2 curve constants, point operations, ECDSA helpers.
- `internal/fiat`: fiat-crypto generated constant-time arithmetic for secp256k1 scalar/field and ed25519 scalar.
- `internal/mta`: Paillier MtA product-share helpers for CGGMP21-style signing (Start/Respond/Finish).
- `internal/paillier`: Paillier public-key primitives (encrypt, decrypt, homomorphic ops, key generation). Secret fields (`Lambda`, `Mu`) use `secret.Scalar`, not `*big.Int`. Decrypt uses constant-time `c^λ mod n²` via `paillierct` with ciphertext blinding.
- `internal/paillier/paillierct`: constant-time modular exponentiation via `filippo.io/bigmod`. Used by `Decrypt` (with ciphertext blinding) and MtA `Respond` (`c^b mod n²`, without blinding — the ZK proof verifies the exact ciphertext relationship).
- `internal/secret`: fixed-length `Scalar` type; no `String()`, `BigInt()`, variable-length `Bytes()`, or JSON.
- `internal/wire`: strict TLV encoding for binary envelopes, key shares, presign records, MtA messages, Paillier keys, and all proof payloads.
- `internal/zk/paillier`: seven ZK proof types — Π^fac (modulus), Π^prm (primality), Π^Enc (unified encryption), Π^Eq (enc-scalar, legacy), EncRangeProof (legacy), Π^mta (MtA response), Π^log (discrete-log equality). Current protocol flows use Π^fac, Π^prm, Π^Enc, and Π^mta.
- `internal/zk/schnorr`: Schnorr proof-of-knowledge primitive over secp256k1.

## Coding Rules

- Keep files small and organized around one responsibility. Split code when a file starts mixing unrelated concerns or becomes difficult to scan.
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
- `math/big.Int.Exp` is acceptable only for public-exponent paths: encryption (`g^m`, `r^n`), public proof verification, test vectors, and key generation. For secret-exponent paths (`c^λ mod n²`, `encA^b mod N²`), always use `internal/paillier/paillierct`.
- All inputs to `paillierct` must be fixed-length big-endian encodings. Never use `lambda.BitLen()`, `lambda.Bytes()` (variable-length), or any `VarTime`-suffixed `bigmod` functions.
- Ciphertext blinding (`c' = c * r^n mod n²`) is required in `Paillier.Decrypt`. Do not apply blinding in MtA `Respond` — the ZK proof verifies the exact ciphertext relationship.

## Testing Expectations

When changing protocol behavior, add or update tests for:

- success paths for `1-of-1`, `2-of-3`, and `3-of-5`;
- duplicate/replayed messages;
- malformed scalar/point payloads;
- incorrect session id or signer set;
- signature verification failure and blame attribution when applicable;
- proof verification failures (wrong domain, wrong public key, malformed commitment/response);
- presign consumption and nonce-reuse guards;
- reshare and refresh flows preserving the group public key.
