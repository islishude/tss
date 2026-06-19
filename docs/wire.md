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

## Public Binary API

Exported types that callers persist, transmit, or restore implement the standard
`encoding.BinaryMarshaler` and `encoding.BinaryUnmarshaler` contracts:

```go
raw, err := value.MarshalBinary()

var restored SomeType
err = restored.UnmarshalBinary(raw)
```

Types with caller-provided resource policy also expose
`MarshalBinaryWithLimits` and `UnmarshalBinaryWithLimits`. Existing
`UnmarshalFoo` and `UnmarshalFooWithLimits` functions remain convenience
wrappers around those methods; they do not contain separate decoding logic.

External callers must not depend on `internal/wire`. That package remains the
single canonical TLV implementation used behind the standard binary methods.

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

| Kind             | Go Type                                                 | Wire Encoding                                                         |
| ---------------- | ------------------------------------------------------- | --------------------------------------------------------------------- |
| `u8`             | `uint8`                                                 | single byte                                                           |
| `u16`            | `uint16`                                                | big-endian uint16                                                     |
| `u32`            | `uint32`, `int`, or alias                               | big-endian uint32                                                     |
| `bool`           | `bool`                                                  | `wire.Bool`                                                           |
| `bytes`          | `[]byte` / `[N]byte`                                    | raw bytes; nil → empty                                                |
| `string`         | `string`                                                | UTF-8 bytes                                                           |
| `u32list`        | `[]uint32` or alias slice                               | `wire.EncodeUint32List`                                               |
| `byteslist`      | `[][]byte`                                              | `wire.EncodeBytesList`                                                |
| `partybytes`     | `[]wire.PartyBytes[T]`                                  | `wire.EncodePartyBytes`                                               |
| `partybytepairs` | `[]wire.PartyBytePair[T]`                               | `wire.EncodePartyBytePairs`                                           |
| `nested`         | struct/pointer implementing `Message`                   | recursive `wire.Marshal`                                              |
| `record`         | struct / pointer to struct                              | record body (field count + fields), no envelope                       |
| `recordlist`     | `[]struct` / `[]*struct`                                | `uint32 count` + length-prefixed record bodies                        |
| `custom`         | type implementing `ValueMarshaler` / `ValueUnmarshaler` | caller-defined canonical bytes                                        |
| `bigint`         | `big.Int` / `*big.Int`                                  | signed-magnitude `[sign byte][minimal BE magnitude]`                  |
| `biguint`        | `big.Int` / `*big.Int`                                  | minimal big-endian magnitude; zero = empty                            |
| `bigpos`         | `big.Int` / `*big.Int`                                  | minimal big-endian magnitude; zero rejected                           |
| `map`            | `map[K]V` where `K` is `uint32` or alias                | `uint32 count` + sorted entries of `(key_len, key, value_len, value)` |

`record` and `recordlist` are typically inferred rather than declared
explicitly. A struct field typed as `SomeStruct` infers to `record`; a field
typed as `[]SomeStruct` or `[]*SomeStruct` infers to `recordlist`. Both
enforce the same strict canonical rules as top-level messages: exact field
set, ascending tags, no duplicates, no trailing bytes, except for fields
explicitly tagged `optional`.

`big.Int` and `map[K]V` are **not** auto-inferred — callers must declare `bigint`,
`biguint`, or `bigpos` explicitly, and map fields must declare `map` explicitly.
This prevents existing or future fields from silently changing wire format if their
Go type changes to a map.

#### Kind Inference Rules

When the kind is omitted, the wire codec selects:

| Go Type              | Inferred Kind      |
| -------------------- | ------------------ |
| `uint8`              | `u8`               |
| `uint16`             | `u16`              |
| `uint32` / `int`     | `u32`              |
| `bool`               | `bool`             |
| `string`             | `string`           |
| `[]byte` / `[N]byte` | `bytes`            |
| `[]uint32` / `[]int` | `u32list`          |
| `[][]byte`           | `byteslist`        |
| struct               | `record`           |
| pointer to struct    | `record`           |
| `[]struct`           | `recordlist`       |
| `[]*struct`          | `recordlist`       |
| `ValueMarshaler`     | `custom`           |
| `map[K]V`            | _must be declared_ |

`map` is never inferred. A `map[K]V` field without `,map` in its tag produces a
schema-parse error. This is intentional: auto-inferring maps would silently change
the wire format of existing fields if their Go type were refactored to a map.

#### Options

- `len=N` — fixed byte length (validated on decode)
- `max_bytes=name` — semantic byte limit (from `wire.WithFieldLimits`)
- `max_bits=name` — semantic bit-length limit for bigint/biguint/bigpos (validates `BitLen()`) or conservative `len*8` upper bound for bytes (from `wire.WithFieldLimits`)
- `max_items=name` — semantic item count limit
- `optional` — only valid on pointer fields; nil is omitted on marshal and an
  absent tag decodes as nil. Without `optional`, pointer fields remain
  required, and nil record/nested pointers are rejected.
- `allow_empty` — documents that empty is permitted (no-op)

### Interfaces

- **`Message`** — required: `WireType() string`, `WireVersion() uint16`
- **`Validator`** — optional: `Validate() error` (called on marshal and unmarshal)
- **`BeforeMarshaler`** — optional: `BeforeMarshalWire() error`
- **`AfterUnmarshaler`** — optional: `AfterUnmarshalWire() error`
- **`ValueMarshaler`** — used by `custom` kind: `MarshalWireValue() ([]byte, error)`
- **`ValueUnmarshaler`** — used by `custom` kind: `UnmarshalWireValue([]byte) error`
- **`MessageMarshaler`** — optional: `MarshalWireMessage(opts ...MarshalOption) ([]byte, error)`. Types implementing this interface provide their own complete canonical TLV message encoding, bypassing struct-tag reflection. The returned bytes must be a full TLV envelope (`magic || type_id || version || field_body`). BeforeMarshalWire and Validate hooks still run before the custom marshaler.
- **`MessageUnmarshaler`** — optional: `UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error`. Types implementing this interface provide their own complete canonical TLV message decoding, bypassing struct-tag reflection. AfterUnmarshalWire and Validate hooks still run after the custom unmarshaler. Decoding is fail-atomic: the original destination is never modified on error.

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
`*big.Int ↔ []byte` conversions.

FROST and CGGMP21 KeyShare DTOs encode participant-owned public material as
canonical `PartyID` maps. The map key is the sole owner identity; nested values
do not duplicate it. Decoders require the map key set to match `Parties`
exactly, reject the broadcast ID and unknown/missing parties, and validate any
confirmation sender against its map key. FROST per-party keygen confirmations
use `wire:"...,record,optional"` so missing confirmations are represented by an
absent tag rather than a zero-length or one-element record list. Protocol
ordering is still derived from `Parties`, not map iteration.

When a type must completely control its TLV envelope (type ID, version, field
order) without exposing wire-tagged exported fields, implement `MessageMarshaler`
and `MessageUnmarshaler`. These object-level hooks delegate to an internal DTO
while keeping the DTO and its wire tags private:

```go
type KeyShare struct {
    state *keyShareState // unexported, no wire tags
}

func (KeyShare) WireType() string    { return "cggmp21.secp256k1.keyshare" }
func (KeyShare) WireVersion() uint16 { return 1 }

func (k KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
    w := keyShareDTOFromState(k.state)
    return wire.Marshal(w, opts...)
}

func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
    var w keyShareDTO
    if err := wire.Unmarshal(in, &w, opts...); err != nil {
        return err
    }
    k.state = stateFromKeyShareDTO(&w)
    return nil
}
```

This approach keeps the DTO pattern but moves the object-to-DTO ceremony inside
the type, making the public API cleaner. The wire codec still enforces all
canonical rules through the inner `Marshal`/`Unmarshal` call on the DTO.

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

Conversion helpers (`encodeFooWire` / `decodeFooWire`) handle structural mapping
and domain validation; field-level byte encoding is handled by the wire codec.

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

### Map Canonical Rules

Map fields (`wire:"N,map"`) encode `map[K]V` where `K` must be `uint32` or a
named `uint32` type (e.g., `tss.PartyID`). The wire format is:

```text
uint32 entry_count
repeat entry_count:
    uint32 key_len     (always 4)
    key_bytes          (big-endian uint32)
    uint32 value_len
    value_bytes
```

Map entries are sorted by `key_bytes` in ascending big-endian order. Both
encoding and decoding enforce:

- **Deterministic output**: Go map iteration order does not affect encoding.
  Entries are always sorted before emitting bytes.
- **Strict sort order**: Decoders reject entries that are not in strictly
  ascending key order (`key[i-1] < key[i]`).
- **Duplicate keys rejected**: Encoded entries with identical key bytes produce
  an error on both encode and decode.
- **Key constraints**: Keys must be exactly 4 bytes (big-endian uint32).
  `map[string]`, `map[int]`, `map[uint64]`, and other key types are rejected at
  schema-parse time.
- **Nil map → count 0**: A nil map encodes as `uint32(0)` with no entries.
  An empty non-nil map encodes identically.
- **Value types**: First-version map supports `uint8`, `uint16`, `uint32`,
  `bool`, `string`, `[]byte`, `[N]byte`, `ValueMarshaler` (custom), and
  struct (record) values. Slice-of-non-byte, nested map, and nested message
  values are rejected at schema-parse time.
- **Limits**: `max_items=name` constrains the entry count. `max_bytes=name`
  constrains each value's byte length. Both are fail-closed — the caller must
  provide the corresponding `FieldLimits` key.

`map` is not a replacement for `partybytes` / `partybytepairs`. Those legacy
kinds remain for existing per-party encodings. New code may use `map` when the
wire format is being designed for the first time; converting existing
per-party encodings is a separate refactoring decision.

FROST Ed25519 and CGGMP21 secp256k1 `KeyShare` records use this map encoding
for per-party public material. The map key is the sole party identity source and
must exactly match the share's canonical `Parties` set. The value does not
repeat a party field. Transcript, hash, confirmation, and public getter paths
iterate `Parties`; they never depend on Go map iteration order. The retired
record-list key-share layout is not decoded.

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
- `tss.BroadcastAck`
- `tss.BroadcastCertificate` (`Acks` as a canonical `BroadcastAck` record list)
- `tss.SigningContext`
- `tss.Envelope`
- `cggmp21/secp256k1.KeyShare`
- `cggmp21/secp256k1.Presign`
- `cggmp21/secp256k1.VerificationShare`
- `cggmp21/secp256k1.PaillierPublicShare`

`Envelope` and `BlameEvidence` carry their schema version only in the TLV frame
header. Their field tags are contiguous and do not include a duplicate body
version field. Semantic protocol-version binding uses `tss.ProtocolVersion`
inside transcripts instead.

- `cggmp21/secp256k1.RingPedersenPublicShare`
- `cggmp21/secp256k1.SignVerifyShare`
- `cggmp21/secp256k1.SignAttemptRecord`
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
- `frost/ed25519.VerificationShare`
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
all active Paillier ZK proof types (Πmod, Πprm, Πenc, Πaff-g, Πlog\*), and
Schnorr share proofs all use the same strict TLV encoding as other binary
records. CGGMP21 keygen, refresh, reshare, and presign payloads carry
Paillier public keys, Ring-Pedersen parameters, and Paillier/MtA proofs as
nested typed TLV records, not pre-serialized opaque byte strings. Nested fields
still enforce the enclosing field's named `max_bytes` limit before decoding.
Keygen, presign, and signing payloads reject
JSON fallback, trailing bytes, duplicate tags, wrong type identifiers,
malformed curve points, malformed scalars, and non-minimal integer encodings
where integers appear.

Current presign wire shapes are:

- `mta.start-message`: field 1 is the Paillier ciphertext only.
- `cggmp21.secp256k1.payload.presign.round1`: fields are `Gamma`, `EncK`, and prover Paillier public key.
- `cggmp21.secp256k1.payload.presign.round1-proof`: fields are public Round1 hash and verifier-specific `EncProof`.
- `cggmp21.secp256k1.payload.presign.round2`: fields are typed MtA `ResponseMessage` records for `Delta` and `Sigma`, plus the round-1 echo hash. Each response carries a typed `AffGProof`.
- `cggmp21.secp256k1.payload.presign.round3`: fields are `Delta` (scalar), `KPoint` (compressed point), `ChiPoint` (compressed point), and `Proof` (signprep proof bytes).
- `cggmp21.secp256k1.payload.sign.partial`: fields are `S` (scalar), `PresignTranscript` (32 bytes), `PresignContext`/context hash (32 bytes), `DigestHash` (32 bytes), `SignPlanHash` (32 bytes), and `PartialEquationHash` (32 bytes).

Retired `EncryptionProof`, `MTAResponseProof`, and `LogProof` wire types have no
decoder or compatibility path.

`SignVerifyShare` implements the standard binary marshal/unmarshal interfaces
with wire type `cggmp21.secp256k1.sign-verify-share`. Its fields are party ID,
`KPoint`, `ChiPoint`, and signprep proof bytes.

The public verification, Paillier, and Ring-Pedersen share records also expose
standalone standard binary codecs. Their record bodies remain the same bodies
embedded in KeyShare record lists.

The canonical `cggmp21.secp256k1.presign` record contains the local fixed-length
secret scalars `k_i`, `χ_i`, and `δ`, public `(R, r)`, transcript/context
hashes, additive HD shift, consumed flag, key binding fields for the group
public key, keygen transcript hash, and participant-set hash, and per-party
`VerifyShares` (tag 16, a canonical `SignVerifyShare` record list with one entry
per signer). Decoders require the complete 19-field presign set. The former
opaque party-triple byte field is intentionally not accepted.

`SignAttemptRecord` stores delivery acknowledgments directly as a canonical
`tss.BroadcastAck` record list. Its optional certificate field contains the
complete canonical `tss.BroadcastCertificate` TLV encoding, so nil remains an
empty field while non-nil certificates use the public standard codec. The
record has 28 contiguous fields. Low-S is mandatory protocol behavior and is
not encoded as an attempt option; the retired 29-field layout containing a
`LowS` field is rejected.

## Decoder Policy

Default `UnmarshalBinary` methods do not auto-detect JSON or any prior wire
shape. CGGMP21 decoders require the expected type identifier and exact field
set. Do not add automatic fallback or proof-conversion helpers to production
decoders.

Paillier proof decoders also reject nested JSON proof payloads, wrong proof type
identifiers, duplicate or unsorted fields, trailing bytes, non-minimal integers,
and malformed curve points. See [`paillier-zk-proofs.md`](paillier-zk-proofs.md)
for the proof inventory and review gaps.
