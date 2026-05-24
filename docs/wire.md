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
- `gg20/secp256k1.KeyShare`
- `gg20/secp256k1.Presign`
- `frost/ed25519.KeyShare`

Paillier and proof payloads currently retain their deterministic JSON encodings because they are nested protocol proof payloads, not top-level share/envelope records.

## Migration Policy

Default `UnmarshalBinary` methods do not auto-detect JSON or legacy encodings. If legacy data migration is needed later, add explicit migration helpers with names that make the unsafe boundary clear. Do not add automatic fallback to production decoders.
