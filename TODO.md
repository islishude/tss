# Production TSS TODO

This file tracks the work required before this repository can be treated as a
production-grade TSS library.

Current status from local inspection:

- `go test -race ./...` passes (all 11 packages).
- `golangci-lint run` passes with 0 issues.
- `cggmp21/secp256k1` is still explicitly experimental.
- ModulusProof now uses a proper Σ-protocol proving factorization of a Blum integer.
- EncRangeProof is now independent from EncScalarProof with its own Fiat-Shamir challenge.
- FROST Ed25519 binding factor uses RFC 9591 `"FROST-ED25519-SHA512-v1rho"` prefix.
- FROST Ed25519 domain separators now include RFC 9591 context string.
- FROST Ed25519 `HashToScalar` uses direct concatenation per RFC 9591 (no length-delimited encoding).
- CGGMP21 resharing now includes Paillier key rotation with modulus proofs.
- Π^log proof (discrete log equality between Paillier ciphertext and curve point) is implemented.
- Π^fac safe-prime enforcement: GenerateKey uses safe primes for production; structural checks in ValidateBits and VerifyModulus.
- Presign lifecycle helpers (`MarkPresignConsumed`, `IsPresignConsumed`) are available.
- Adversarial delivery-order tests and concurrent keygen tests added.

References:

- [RFC 9591: The Flexible Round-Optimized Schnorr Threshold Protocol](https://www.rfc-editor.org/rfc/rfc9591)
- [IACR ePrint 2021/060: CGGMP21](https://eprint.iacr.org/2021/060)

## Non-Negotiable Rules

- Do not read, copy, port, or derive code from public TSS implementations in Go
  or any other language.
- It is acceptable to use papers, RFCs, standards, and public test vectors or
  test scenarios.
- Do not preserve prior-format fallback paths while moving toward the
  production target. Existing conversion code for retired wire shapes must be
  removed rather than supported.
- CGGMP21 applies only to ECDSA over secp256k1. Ed25519 must stay on the
  FROST-style EdDSA path.
- Do not remove the experimental warning from `cggmp21/secp256k1` until the full
  Paillier MtA/ZK CGGMP21 signing path exists and has completed independent
  review.
- Never place private shares, nonces, Paillier private-key material, presign
  secret material, or raw secret-bearing payloads in blame evidence, logs,
  errors, examples, or docs.

## P0 Remaining: CGGMP21 Paillier/ZK Audit Readiness

Items still needed for independent review readiness:

1. Build a formal protocol checklist directly from the CGGMP21 paper for keygen,
   presign, online signing, MtA/MtAwc, proof statements, public inputs,
   witnesses, transcript inputs, and abort-identification requirements.
2. ~~Add the Π^fac (proof of factorization with safe primes).~~ **DONE.**
3. ~~Add the Π^log proof (discrete log equality) per CGGMP21 Section 6.2.~~ **DONE.**
4. ~~Full CGGMP21 resharing with Paillier key rotation.~~ **DONE.**

## P1 Remaining: FROST Ed25519 Full RFC 9591 Compliance

1. Add public test vectors from standards or papers (e.g. RFC 9591 Appendix B).
2. ~~Use HashToScalar without length-delimited encoding for RFC compliance.~~ **DONE.**
3. ~~Add `frost/ed25519/domain.go` binding into keygen and signing transcripts.~~ **DONE.**

## P1 Remaining: Testing Infrastructure

1. ~~Add state-machine fuzzers for FROST and CGGMP21 message delivery.~~ Existing fuzz tests cover envelope validation, blame evidence, payload decoding.
2. Add golden encoding tests for every public binary record.
3. ~~Add adversarial scheduler tests that permute delivery order.~~ **DONE** (`TestCGGMP21AdversarialDeliveryOrder`).
4. ~~Add concurrency and race tests around session APIs.~~ **DONE** (`TestCGGMP21ConcurrentKeygenWithMutex`).

## P2 Remaining: Release Documentation

1. Update `docs/paillier-zk-proofs.md` to describe the Σ-protocol modulus proof and Π^log proof.
2. Update `docs/frost-ed25519.md` to note RFC 9591 alignment status.
3. Maintain audit scope documentation.
4. Update `README.md` with resharing and presign lifecycle information.

## General Handoff Checklist

- Update docs for any API, wire-format, or protocol behavior change.
- Add or refresh executable examples when public behavior changes.
- Add tests for success paths: `1-of-1`, `2-of-3`, and `3-of-5`.
- Add tests for duplicate/replayed messages, malformed scalar or point payloads,
  wrong session id, wrong signer set, signature verification failure, and blame
  attribution when applicable.
- Run `go test -race ./...`.
- Run `golangci-lint run`.
