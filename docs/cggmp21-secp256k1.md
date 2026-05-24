# CGGMP21 secp256k1

The `cggmp21/secp256k1` package implements an experimental CGGMP21-style threshold ECDSA flow. CGGMP21 is an ECDSA protocol; Ed25519 support lives in the FROST package.

## Keygen

Each party generates a Shamir polynomial and broadcasts secp256k1 commitments. Private Shamir shares are sent point-to-point in confidential envelopes. Receivers verify shares against commitments before deriving the local aggregated share.

Each party also generates Paillier material and a modulus proof. The proof is
encoded as canonical binary TLV and bound to the keygen transcript. When
`KeygenOptions.EnableHD` is set, parties contribute 32-byte chain-code shares
that are XOR-aggregated into the key share. The group public key is the sum of
degree-zero commitments.

## Presign

Presign is the offline phase. Each signer samples local `k_i` and `gamma_i`,
broadcasts `Gamma_i = gamma_i*G`, and publishes `Enc_i(k_i)` with canonical
binary encrypted-scalar and range proof material.

Pairwise MtA exchanges produce additive shares for:

- `delta = k * gamma`
- `chi = k * x`

Locally:

```text
delta_i = k_i*gamma_i + sum(alpha_ij) + sum(beta_ji)
chi_i   = k_i*x_i     + sum(alphaHat_ij) + sum(betaHat_ji)
```

Round 2 includes a hash of the complete round 1 broadcast view. A mismatch aborts with blame evidence before pairwise MtA output is accepted.

Round 2 MtA response proofs are also canonical binary payloads. They bind the
response ciphertext to the encrypted input scalar, the responder scalar
commitment, and the beta-share commitment under a domain separated by session
id, signer set, initiator, responder, and MtA kind.

After all `delta_i` values are broadcast:

```text
delta = sum(delta_i)
Gamma = sum(Gamma_i)
R     = delta^-1 * Gamma
r     = x(R) mod q
```

The resulting `Presign` record is local-only and one-use. It stores `k_i`, `chi_i`, `R`, `r`, `delta`, and the presign transcript hash. It must not be transported to other parties.

## Online Signing

For a 32-byte digest `m`, each signer sends only:

```text
s_i = m*k_i + r*chi_i mod q
```

The aggregate signature is:

```text
s = sum(s_i) mod q
```

The package applies low-S normalization by default and verifies the final ECDSA signature before returning it.

For HD-style additive shifts, callers pass the already-derived scalar shift in `SignOptions.AdditiveShift`. Each signer adds `k_i*shift` to its local `chi_i`, and verifiers derive the shifted public key with `DerivePublicKey`.

## Blame Evidence

Malformed commitments, Paillier mismatches, invalid MtA responses, malformed online partials, and aggregate verification failure attach `ProtocolError.Blame` when the failure can be attributed. Evidence contains public hashes and public context only.

## Unsupported

The package does not implement network transport, persistent storage encryption, resharing, proactive refresh, BIP32 path derivation, or production-audited proofs. Canonical proof encoding is a wire-safety improvement, not an external cryptographic audit. The experimental security notice remains part of generated artifacts. See [`paillier-zk-proofs.md`](paillier-zk-proofs.md) for the current proof inventory and review blockers.
