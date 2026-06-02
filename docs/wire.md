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
- Proof scalar responses use canonical positive big-endian encoding; Paillier
  statement and commitment integers use fixed-width encodings derived from `N`
  or `N²`, with out-of-range values rejected before algebraic checks.
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
- `cggmp21/secp256k1` keygen commitments payload
- `cggmp21/secp256k1` keygen share payload
- `cggmp21/secp256k1` presign round 1 payload
- `cggmp21/secp256k1` presign round 2 payload
- `cggmp21/secp256k1` presign round 3 payload
- `cggmp21/secp256k1` online signing partial payload
- `cggmp21/secp256k1` reshare commitments payload
- `cggmp21/secp256k1` reshare share payload
- `cggmp21/secp256k1` refresh commitments payload
- `cggmp21/secp256k1` refresh share payload
- `frost/ed25519.KeyShare`
- `frost/ed25519` keygen commitments payload
- `frost/ed25519` keygen share payload
- `frost/ed25519` signing nonce commitment payload
- `frost/ed25519` signing partial payload
- `frost/ed25519` reshare commitments payload
- `frost/ed25519` reshare share payload
- `internal/mta.StartMessage`
- `internal/mta.ResponseMessage`
- `internal/paillier.PublicKey`
- `internal/paillier.PrivateKey`
- `internal/zk/paillier.ModulusProof`
- `internal/zk/paillier.RingPedersenParams`
- `internal/zk/paillier.RingPedersenProof`
- `internal/zk/paillier.EncryptionProof`
- `internal/zk/paillier.MTAResponseProof`
- `internal/zk/paillier.LogProof`
- `internal/zk/schnorr.Proof`

Protocol payloads, MtA messages, Paillier public keys, Paillier private keys,
all active Paillier ZK proof types (modulus, Ring-Pedersen parameters/proof,
encryption, MtA response, log), and Schnorr share proofs all use the same strict
TLV encoding as other binary records. Keygen, presign, and signing payloads reject
JSON fallback, trailing bytes, duplicate tags, wrong type identifiers,
malformed curve points, malformed scalars, and non-minimal integer encodings
where integers appear.

## Decoder Policy

Default `UnmarshalBinary` methods do not auto-detect JSON or any prior wire
shape. CGGMP21 decoders require the expected type identifier and exact field
set. Do not add automatic fallback or proof-conversion helpers to production
decoders.

Paillier proof decoders also reject nested JSON proof payloads, wrong proof type
identifiers, duplicate or unsorted fields, trailing bytes, non-minimal integers,
and malformed curve points. See [`paillier-zk-proofs.md`](paillier-zk-proofs.md)
for the proof inventory and review gaps.
