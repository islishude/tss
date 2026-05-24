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

These rules ensure one semantic record has one binary representation. This matters for transcript binding, storage integrity, and regression tests.

## Current Records

- `tss.Envelope`
- `cggmp21/secp256k1.KeyShare`
- `cggmp21/secp256k1.Presign`
- `frost/ed25519.KeyShare`
- `internal/zk/paillier.ModulusProof`
- `internal/zk/paillier.EncScalarProof`
- `internal/zk/paillier.EncRangeProof`
- `internal/zk/paillier.MTAResponseProof`

Paillier public and private keys still use deterministic JSON inside the
canonical top-level records. Paillier proof payloads use the same strict TLV
encoding as other binary records so presign and keygen proof bytes reject JSON
fallback, trailing bytes, duplicate tags, and wrong proof type identifiers.

## Migration Policy

Default `UnmarshalBinary` methods do not auto-detect JSON or legacy encodings. CGGMP21 decoders do not accept old GG20 type identifiers. If legacy data migration is needed later, add explicit migration helpers with names that make the unsafe boundary clear. Do not add automatic fallback to production decoders.

Paillier proof decoders also do not accept the earlier nested JSON proof
payloads. Shares or protocol fixtures carrying those old proof bytes should be
migrated by an explicit offline helper rather than by `StartKeygen`,
`StartPresign`, or `UnmarshalKeyShare`.
