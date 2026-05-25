# FROST Ed25519

The `frost/ed25519` package implements a dealerless FROST-style threshold Ed25519 flow.

## DKG

Each party samples a Shamir polynomial over the Ed25519 prime-order scalar field, broadcasts public commitments, and sends private shares in confidential envelopes. Receivers verify each private share against the sender's commitments.

The group public key is the sum of degree-zero commitments. Each local `KeyShare` stores the aggregated scalar share, group commitments, and verification shares.

## Signing

Signing has two rounds:

1. Each signer broadcasts hiding and binding nonce commitments.
2. After all commitments are known, each signer computes the binding factor, group nonce, Ed25519 challenge, and local partial signature.

Keygen and signing payloads are encoded as exact-field TLV records. Decoders
reject JSON fallback, wrong payload type identifiers, duplicate or unsorted
fields, trailing bytes, malformed points, and non-canonical scalar encodings.

The local partial equation is:

```text
z_i = d_i + rho_i*e_i + lambda_i*c*x_i
```

Aggregation verifies each partial before summing them into the final `S` scalar. The final signature is the standard 64-byte Ed25519 shape:

```text
R || S
```

It verifies with `crypto/ed25519.Verify`.

## Scope

The package signs raw messages only. It does not expose Ed25519ph or Ed25519ctx in v1, and it does not include network transport or storage encryption.
