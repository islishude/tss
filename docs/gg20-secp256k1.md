# GG20-style secp256k1

The `gg20/secp256k1` package implements an experimental GG20-style threshold ECDSA flow. GG20 is an ECDSA protocol; Ed25519 support lives in the FROST package.

## Keygen

Each party generates a Shamir polynomial and broadcasts secp256k1 commitments. Private Shamir shares are sent point-to-point in confidential envelopes. Receivers verify shares against commitments before deriving the local aggregated share.

Each party also generates Paillier material and a modulus proof. The group public key is the sum of degree-zero commitments.

## Presign

Presign is the offline phase. Each signer samples local `k_i` and `gamma_i`, broadcasts `Gamma_i = gamma_i*G`, and publishes `Enc_i(k_i)` with proof material.

Pairwise MtA exchanges produce additive shares for:

- `delta = k * gamma`
- `sigma = k * x`

Locally:

```text
delta_i = k_i*gamma_i + sum(alpha_ij) + sum(beta_ji)
sigma_i = k_i*x_i     + sum(alphaHat_ij) + sum(betaHat_ji)
```

After all `delta_i` values are broadcast:

```text
delta = sum(delta_i)
Gamma = sum(Gamma_i)
R     = delta^-1 * Gamma
r     = x(R) mod q
```

The resulting `Presign` record is local-only and one-use. It stores `k_i`, `sigma_i`, `R`, `r`, `delta`, and the presign transcript hash. It must not be transported to other parties.

## Online Signing

For a 32-byte digest `m`, each signer sends only:

```text
s_i = m*k_i + r*sigma_i mod q
```

The aggregate signature is:

```text
s = sum(s_i) mod q
```

The package applies low-S normalization by default and verifies the final ECDSA signature before returning it.

## Blame Evidence

Malformed commitments, Paillier mismatches, invalid MtA responses, malformed online partials, and aggregate verification failure attach `ProtocolError.Blame` when the failure can be attributed. Evidence contains public hashes and public context only.

## Unsupported

The package does not implement network transport, persistent storage encryption, resharing, proactive refresh, or production-audited proofs. The experimental security notice remains part of generated artifacts.
