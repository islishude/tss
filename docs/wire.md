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

## Object-Level API (Preferred)

All production message types use the object-level `wire.Marshal` / `wire.Unmarshal` API driven by struct tags:

```go
type MyMessage struct {
    Field []byte `wire:"1,bytes"`
    Count uint32 `wire:"2,u32"`
}

func (MyMessage) WireType() string    { return "my.type" }
func (MyMessage) WireVersion() uint16 { return 1 }

// Marshal
raw, err := wire.Marshal(msg)

// Unmarshal
var decoded MyMessage
err := wire.Unmarshal(raw, &decoded)
```

### Struct Tag Grammar

```
wire:"<tag>"                     // infer kind from Go type
wire:"<tag>,<kind>[,<option>...]"
wire:"<tag>,<option>..."         // infer kind, apply options
wire:"-"                         // skip field
```

When the kind is omitted or the second segment is not a recognised kind name, the wire codec infers the kind from the Go field type (see table below). Named primitive types (`type Foo string`) are handled correctly.

#### Supported Kinds

| Kind             | Go Type                                                 | Wire Encoding                                        |
| ---------------- | ------------------------------------------------------- | ---------------------------------------------------- |
| `u8`             | `uint8`                                                 | single byte                                          |
| `u16`            | `uint16`                                                | big-endian uint16                                    |
| `u32`            | `uint32`, `int`, or alias                               | big-endian uint32                                    |
| `bool`           | `bool`                                                  | `wire.Bool`                                          |
| `bytes`          | `[]byte` / `[N]byte`                                    | raw bytes; nil → empty                               |
| `string`         | `string`                                                | UTF-8 bytes                                          |
| `u32list`        | `[]uint32` or alias slice                               | `wire.EncodeUint32List`                              |
| `byteslist`      | `[][]byte`                                              | `wire.EncodeBytesList`                               |
| `partybytes`     | `[]wire.PartyBytes[T]`                                  | `wire.EncodePartyBytes`                              |
| `partybytepairs` | `[]wire.PartyBytePair[T]`                               | `wire.EncodePartyBytePairs`                          |
| `nested`         | struct/pointer implementing `Message`                   | recursive `wire.Marshal`                             |
| `record`         | struct / pointer to struct                              | record body (field count + fields), no envelope      |
| `recordlist`     | `[]struct` / `[]*struct`                                | `uint32 count` + length-prefixed record bodies       |
| `custom`         | type implementing `ValueMarshaler` / `ValueUnmarshaler` | caller-defined canonical bytes                       |
| `bigint`         | `big.Int` / `*big.Int`                                  | signed-magnitude `[sign byte][minimal BE magnitude]` |
| `biguint`        | `big.Int` / `*big.Int`                                  | minimal big-endian magnitude; zero = empty           |
| `bigpos`         | `big.Int` / `*big.Int`                                  | minimal big-endian magnitude; zero rejected          |

`record` and `recordlist` are typically inferred rather than declared
explicitly. A struct field typed as `SomeStruct` infers to `record`; a field
typed as `[]SomeStruct` or `[]*SomeStruct` infers to `recordlist`. Both
enforce the same strict canonical rules as top-level messages: exact field
set, ascending tags, no duplicates, no trailing bytes.

`big.Int` is **not** auto-inferred — callers must declare `bigint`,
`biguint`, or `bigpos` explicitly.

#### Kind Inference Rules

When the kind is omitted, the wire codec selects:

| Go Type              | Inferred Kind |
| -------------------- | ------------- |
| `uint8`              | `u8`          |
| `uint16`             | `u16`         |
| `uint32` / `int`     | `u32`         |
| `bool`               | `bool`        |
| `string`             | `string`      |
| `[]byte` / `[N]byte` | `bytes`       |
| `[]uint32` / `[]int` | `u32list`     |
| `[][]byte`           | `byteslist`   |
| struct               | `record`      |
| pointer to struct    | `record`      |
| `[]struct`           | `recordlist`  |
| `[]*struct`          | `recordlist`  |
| `ValueMarshaler`     | `custom`      |

#### Options

- `len=N` — fixed byte length (validated on decode)
- `max_bytes=name` — semantic byte limit (from `wire.WithFieldLimits`)
- `max_bits=name` — semantic bit-length limit for bigint/biguint/bigpos (validates `BitLen()`) or conservative `len*8` upper bound for bytes (from `wire.WithFieldLimits`)
- `max_items=name` — semantic item count limit
- `allow_empty` — documents that empty is permitted (no-op)

### Interfaces

- **`Message`** — required: `WireType() string`, `WireVersion() uint16`
- **`Validator`** — optional: `Validate() error` (called on marshal and unmarshal)
- **`BeforeMarshaler`** — optional: `BeforeMarshalWire() error`
- **`AfterUnmarshaler`** — optional: `AfterUnmarshalWire() error`
- **`ValueMarshaler`** — used by `custom` kind: `MarshalWireValue() ([]byte, error)`
- **`ValueUnmarshaler`** — used by `custom` kind: `UnmarshalWireValue([]byte) error`

### Field-Level API (Tests Only)

The low-level `MarshalFields` / `UnmarshalFields` / `UnmarshalFieldsWithLimits` and `RequireExactTags` are restricted to test infrastructure (`internal/testutil`, mutation tests, fuzz tests) and the `internal/wire` package itself. Production code must use the object-level API.

### Limits

Frame and semantic limits are **fail-closed**: any struct tag that declares `max_bytes=name`, `max_bits=name`, or `max_items=name` requires the caller to provide a `wire.FieldLimits` containing that name. Missing limits or missing keys produce an error — there is no silent fallback to unlimited.

- **Frame-level** (`wire.FrameLimits`): `MaxTotalBytes`, `MaxFields`, `MaxFieldBytes` — applied during decode via `wire.WithFrameLimits`
- **Semantic-level** (`wire.FieldLimits`): per-field max bytes, bits, or items checked against named limits via `wire.WithFieldLimits` (decode) or `wire.WithFieldLimitsForMarshal` (encode)

Package-level limits (e.g., `frost/ed25519.Limits`, `cggmp21/secp256k1.Limits`) provide `frameLimits(maxTotal int) wire.FrameLimits` and `fieldLimits() wire.FieldLimits` adapter methods to convert their structured limits into wire-layer options.

## DTO Pattern

Types with unexported fields (`secret.Scalar`, `sync.Mutex`) use unexported wire
DTOs. This includes opaque FROST/CGGMP21 key shares, CGGMP21 presigns, and the
CGGMP21 reshare plan. The public domain object is never made mutable merely for
serialization. The `custom` kind eliminates `*secret.Scalar ↔ []byte`
mechanical conversions; the `bigint` / `biguint` / `bigpos` kinds eliminate
`*big.Int ↔ []byte` conversions:

```go
type myMessageWire struct {
    SessionID tss.SessionID `wire:"1,bytes,len=32"`
    Secret    *secret.Scalar `wire:"2,custom,len=32"`
    Modulus   *big.Int       `wire:"3,bigpos,max_bits=paillier_modulus_bits"`
    Response  *big.Int       `wire:"4,bigint,max_bytes=signed_response"`
}
func (myMessageWire) WireType() string    { return "my.type" }
func (myMessageWire) WireVersion() uint16 { return 1 }
```

Conversion functions (`toWire()` / `toDomain()`) handle structural mapping and domain validation; field-level byte encoding is handled by the wire codec.

## Canonical Rules

- `type_id` must be non-empty and match the expected decoder type.
- Fields must be sorted by strictly increasing tag.
- Duplicate tags are rejected.
- Nil field values are rejected by the encoder (nil bytes/list → empty).
- Decoders reject trailing bytes.
- All tagged fields are required. Missing and extra fields are rejected.
- Fields tagged `bigint`, `biguint`, or `bigpos` use canonical integer encodings:
  `bigint` — signed-magnitude (zero = `0x00`, nil = zero); `biguint` — minimal
  big-endian (zero = empty); `bigpos` — minimal big-endian (zero rejected).
  Non-canonical encodings (negative zero, leading zeroes, empty signed) are rejected.
  When `max_bits=name` is declared, `BitLen()` is validated against the limit
  after decoding; for `bytes` fields, `len(raw)*8` is used as a conservative
  upper bound.
- Proof scalar responses use canonical positive big-endian encoding; Paillier
  statement and commitment integers use fixed-width encodings derived from `N`
  or `N²`, with out-of-range values rejected before algebraic checks.
- Proof secp256k1 point fields must pass the curve package's canonical point
  decoder before the proof is accepted.
- Proof transcript and challenge labels are fixed constants in the proof
  package; changing them is a protocol-domain change and must be reviewed with
  the corresponding transcript tests.

These rules ensure one semantic record has one binary representation. This matters for transcript binding, storage integrity, and regression tests.

## Labeled SHA-256 Transcripts

Custom SHA-256 transcript, domain, commitment, challenge, and evidence hashes
use `internal/transcript`. Each entry is encoded as:

```text
u32be(label_length) || label || u32be(value_length) || value
```

The first entry is always `("domain", domain_label)`. Every later entry has a
non-empty stable ASCII `snake_case` label. Integer, boolean, uint32-list, and
byte-list values use the canonical encodings from `internal/wire`; set-valued
inputs are sorted before they enter the transcript.

This encoding is part of the protocol contract. Renaming, reordering, adding,
or removing a field changes the digest and requires transcript binding tests
and vector regeneration. RFC-defined hashes and plain content hashes such as
`SHA-256(payload)` do not use this transcript encoding.

## Current Records

- `tss.BlameEvidence` (direct struct encoding; `PublicInputs` as `[]EvidenceField` record list)
- `tss.Envelope`
- `cggmp21/secp256k1.KeyShare`
- `cggmp21/secp256k1.Presign`
- `cggmp21/secp256k1` keygen commitments payload
- `cggmp21/secp256k1` keygen share payload
- `cggmp21/secp256k1` presign round 1 payload
- `cggmp21/secp256k1` presign round 1 proof payload
- `cggmp21/secp256k1` presign round 2 payload
- `cggmp21/secp256k1` presign round 3 payload
- `cggmp21/secp256k1` online signing partial payload
- `cggmp21/secp256k1` reshare dealer commitments payload
- `cggmp21/secp256k1` reshare share payload (`dealer`, `receiver`, scalar share, dealer-commitment hash)
- `cggmp21/secp256k1` reshare receiver material payload
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
- `internal/zk/paillier.EncProof` (Πenc)
- `internal/zk/paillier.AffGProof` (Πaff-g)
- `internal/zk/paillier.LogStarProof` (Πlog\*)
- `internal/zk/paillier.KeygenConfirmation`
- `internal/zk/schnorr.Proof`
- `internal/zk/signprep.Proof` (Schnorr + DLEQ, 8 fields: MPoint, KCommitment, MCommitment, DLEQA1, DLEQA2, KResponse, MResponse, DLEQResponse)

Protocol payloads, MtA messages, Paillier public keys, Paillier private keys,
all active Paillier ZK proof types (modulus, Ring-Pedersen parameters/proof,
encryption, MtA response, log), and Schnorr share proofs all use the same strict
TLV encoding as other binary records. Keygen, presign, and signing payloads reject
JSON fallback, trailing bytes, duplicate tags, wrong type identifiers,
malformed curve points, malformed scalars, and non-minimal integer encodings
where integers appear.

Current presign wire shapes are:

- `mta.start-message`: field 1 is the Paillier ciphertext only.
- `cggmp21.secp256k1.payload.presign.round1`: fields are `Gamma`, `EncK`, and prover Paillier public key.
- `cggmp21.secp256k1.payload.presign.round1-proof`: fields are public Round1 hash and verifier-specific `EncProof`.
- `cggmp21.secp256k1.payload.presign.round3`: fields are `Delta` (scalar), `KPoint` (compressed point), `ChiPoint` (compressed point), and `Proof` (signprep proof bytes).
- `cggmp21.secp256k1.payload.sign.partial`: fields are `S` (scalar), `PresignTranscript` (32 bytes), `PresignContext`/context hash (32 bytes), `DigestHash` (32 bytes), `SignPlanHash` (32 bytes), and `PartialEquationHash` (32 bytes).

Legacy `EncryptionProof` bytes are not accepted by production presign decoders.

The canonical `cggmp21.secp256k1.presign` record contains the local fixed-length
secret scalars `k_i`, `χ_i`, and `δ`, public `(R, r)`, transcript/context
hashes, additive HD shift, consumed flag, key binding fields for the group
public key, keygen transcript hash, and participant-set hash, and per-party
`VerifyShares` (tag 17, one `SignVerifyShare` per signer: party ID + KPoint +
ChiPoint + signprep proof bytes). Decoders require this complete 17-field set;
prior presign records without the VerifyShares field are rejected.

## Decoder Policy

Default `UnmarshalBinary` methods do not auto-detect JSON or any prior wire
shape. CGGMP21 decoders require the expected type identifier and exact field
set. Do not add automatic fallback or proof-conversion helpers to production
decoders.

Paillier proof decoders also reject nested JSON proof payloads, wrong proof type
identifiers, duplicate or unsorted fields, trailing bytes, non-minimal integers,
and malformed curve points. See [`paillier-zk-proofs.md`](paillier-zk-proofs.md)
for the proof inventory and review gaps.
