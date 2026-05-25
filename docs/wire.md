# Wire Encoding

Binary records use `internal/wire`, a strict TLV format:

```text
magic      = "TSS1"
type_len   = uint16
type_id    = ASCII/UTF-8 bytes
version    = uint16
field_count = uint16
field      = tag:uint16 || value_len:uint32 || value
```

## Canonical Rules

- `type_id` must be non-empty and match the expected decoder type.
- Fields must be sorted by strictly increasing tag.
- Duplicate tags are rejected.
- Nil field values are rejected by the encoder.
- Decoders reject trailing bytes.
- Higher-level decoders require exact field sets for fixed records.
- Proof integer fields use minimal positive big-endian encoding; leading-zero
  aliases are rejected.
- Proof secp256k1 point fields must pass the curve package's canonical point
  decoder before the proof is accepted.
- Proof transcript and challenge labels are fixed constants in the proof
  package; changing them is a protocol-domain change and must be reviewed with
  the corresponding transcript tests.

These rules ensure one semantic record has one binary representation. This matters for transcript binding, storage integrity, and regression tests.

## Current Records

- `tss.Envelope`
- `cggmp21/secp256k1.KeyShare`
- `cggmp21/secp256k1.Presign`
- `frost/ed25519.KeyShare`
- `frost/ed25519` keygen commitments payload
- `frost/ed25519` keygen share payload
- `frost/ed25519` signing nonce commitment payload
- `frost/ed25519` signing partial payload
- `internal/paillier.PublicKey`
- `internal/paillier.PrivateKey`
- `internal/zk/paillier.ModulusProof`
- `internal/zk/paillier.EncScalarProof`
- `internal/zk/paillier.EncRangeProof`
- `internal/zk/paillier.MTAResponseProof`
- `internal/zk/schnorr.Proof`

Paillier public keys, Paillier private keys, Paillier proof payloads, and
Schnorr share proofs all use the same strict TLV encoding as other binary
records. Keygen and presign proof bytes reject JSON fallback, trailing bytes,
duplicate tags, wrong type identifiers, malformed curve points, and
non-minimal integer encodings where integers appear.

## Decoder Policy

Default `UnmarshalBinary` methods do not auto-detect JSON or any prior wire
shape. CGGMP21 decoders require the expected type identifier and exact field
set. Do not add automatic fallback or proof-conversion helpers to production
decoders.

Paillier proof decoders also reject nested JSON proof payloads, wrong proof type
identifiers, duplicate or unsorted fields, trailing bytes, non-minimal integers,
and malformed curve points. See [`paillier-zk-proofs.md`](paillier-zk-proofs.md)
for the proof inventory and review gaps.
