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

## RFC 9591 Alignment

The package targets RFC 9591 (FROST). Current alignment status:

- **Context string**: Uses `"FROST-ED25519-SHA512-v1"` per RFC 9591 Section 5.4.1.
- **Domain separation**: Keygen, signing binding factor, and signing partial transcripts are domain-separated via `frostProofDomain()`, which binds the RFC 9591 context string, library protocol/version, session ID, threshold, participants, signers, sender, receiver, proof kind, and group public key into a SHA-256 transcript.
- **Binding factor**: The `bindingFactor()` computation prepends `"FROST-ED25519-SHA512-v1rho"` per the RFC 9591 `H1` label, plus the full domain-separation transcript, group public key, message, ordered signer commitments, and participant identifier. This provides stronger binding than the minimal RFC 9591 definition by including session-level context in the hash.
- **HashToScalar**: Uses direct concatenation per RFC 9591 (no length-delimited encoding).
- **Ed25519 challenge**: Uses standard `H(m)` per RFC 8032 compatibility path for Ed25519.

## Resharing

Resharing preserves the group secret through a zero-coefficient polynomial refresh. Each party samples a fresh Shamir polynomial with constant term zero, broadcasts commitments, and delivers private shares point-to-point. Recipients add the received shares to their existing secret share, producing a new share of the same group secret. The group public key and verification shares remain unchanged.

## Scope

The package signs raw messages only. It does not expose Ed25519ph or Ed25519ctx in v1, and it does not include network transport or storage encryption.
