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
| `customlist`     | `[]T` / `[]*T` where `T` implements value codecs        | `uint32 count` + repeated length-prefixed canonical custom value      |
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

- `len=N` — fixed byte length (validated on encode and decode)
- `max_bytes=name` — semantic byte limit (from `wire.WithFieldLimits`)
- `max_bits=name` — semantic bit-length limit for bigint/biguint/bigpos (validates `BitLen()`) or conservative `len*8` upper bound for bytes (from `wire.WithFieldLimits`)
- `max_items=name` — semantic item count limit
- `optional` — valid only on pointer `record`, `nested`, `custom`, `bigint`,
  `biguint`, and `bigpos` fields; nil is omitted on marshal and an absent tag
  decodes as nil. Without `optional`, pointer fields remain required.

Each option is validated against the field kind at schema parse time. Unsupported
options, duplicate options, and malformed limit names are rejected before
marshal/unmarshal. Named semantic limits must match `[a-z][a-z0-9_]*`.

| Option      | Supported Kinds                                                                                                                                                               |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `len`       | `bytes`, `string`, `custom`, `customlist` items, `bigint`, `biguint`, `bigpos`, supported map values                                                                          |
| `max_bytes` | `bytes`, `string`, `byteslist` items, `partybytes` items, `partybytepairs` items, `nested`, `custom`, `customlist` items, `bigint`, `biguint`, `bigpos`, supported map values |
| `max_bits`  | `bytes`, `bigint`, `biguint`, `bigpos`, byte-valued map values                                                                                                                |
| `max_items` | `u32list`, `byteslist`, `partybytes`, `partybytepairs`, count-prefixed `custom`, `customlist`, `recordlist`, `map`                                                            |
| `optional`  | pointer `record`, `nested`, `custom`, `bigint`, `biguint`, `bigpos`                                                                                                           |

For custom fields, `max_items` is supported only for count-prefixed custom
values. A field tagged `wire:"N,custom,max_items=name"` must encode its raw
value with a leading big-endian `uint32 item_count`. The codec checks that count
against the global repeated-field limit and the named field limit after
`MarshalWireValue` and before `UnmarshalWireValue`. The wire package does not
parse the custom payload body or validate individual items; those remain the
custom type's responsibility. `max_items` is an upper bound, not an exact-count
protocol invariant.

For `customlist`, `len=N` and `max_bytes=name` apply to each item, not to the
whole list. `max_items=name` applies to the list count. Nil items are rejected;
a nil slice encodes as an empty list.

### Interfaces

- **`Message`** — required: `WireType() string`, `WireVersion() uint16`
- **`Validator`** — optional: `Validate() error` (called on marshal and unmarshal)
- **`BeforeMarshaler`** — optional: `BeforeMarshalWire() error`
- **`AfterUnmarshaler`** — optional: `AfterUnmarshalWire() error`
- **`ValueMarshaler`** — used by `custom` kind: `MarshalWireValue() ([]byte, error)`
- **`ValueUnmarshaler`** — used by `custom` kind: `UnmarshalWireValue([]byte) error`
- **`MessageMarshaler`** — optional: `MarshalWireMessage(opts ...MarshalOption) ([]byte, error)`. Types implementing this interface provide their own complete TLV message encoding, bypassing struct-tag reflection. `wire.Marshal` reparses the returned full envelope to enforce type, version, tag ordering, duplicate/tag-zero rejection, canonical framing, and no trailing bytes. BeforeMarshalWire and Validate hooks still run before the custom marshaler.
- **`MessageUnmarshaler`** — optional: `UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error`. Types implementing this interface provide their own field-schema decoding, bypassing struct-tag reflection. `wire.Unmarshal` performs canonical frame/type/version and configured frame-limit preflight before invoking the hook. AfterUnmarshalWire and Validate hooks still run afterward. Decoding is fail-atomic: the original destination is never modified on error.

### Field-Level API (Tests Only)

The low-level `MarshalFields` / `UnmarshalFields` / `UnmarshalFieldsWithLimits` and `RequireExactTags` are restricted to test infrastructure (`internal/testutil`, mutation tests, fuzz tests) and the `internal/wire` package itself. Production code must use the object-level API.

### Limits

Frame and semantic limits are **fail-closed**: any struct tag that declares `max_bytes=name`, `max_bits=name`, or `max_items=name` requires the caller to provide a `wire.FieldLimits` containing that name. Missing limits or missing keys produce an error — there is no silent fallback to unlimited.

- **Frame-level** (`wire.FrameLimits`): `MaxTotalBytes`, `MaxFields`, `MaxFieldBytes` — applied during decode via `wire.WithFrameLimits`. Zero-valued members inherit their individual defaults, so partial overrides are safe.
- **Semantic-level** (`wire.FieldLimits`): per-field max bytes, bits, or items checked against named limits via `wire.WithFieldLimits` (decode) or `wire.WithFieldLimitsForMarshal` (encode)

Package-level limits (e.g., `frost/ed25519.Limits`, `cggmp21/secp256k1.Limits`) provide `frameLimits(maxTotal int) wire.FrameLimits` and `fieldLimits() wire.FieldLimits` adapter methods to convert their structured limits into wire-layer options.

## Opaque State Codecs

Opaque public objects may keep their mutable and secret-bearing state behind an
unexported pointer while the unexported state type exposes wire-tagged fields to
the reflection codec. FROST and CGGMP21 key shares, CGGMP21 presigns, and
CGGMP21 reshare plans use this pattern. The public domain object is never made
mutable merely for serialization. The `custom` kind eliminates
`*secret.Scalar ↔ []byte` mechanical conversions; the `bigint` / `biguint` /
`bigpos` kinds eliminate `*big.Int ↔ []byte` conversions.

FROST Ed25519 and CGGMP21 secp256k1 `keyShareState` codecs encode
participant-owned public material as canonical `PartyID` maps. The map key is
the sole owner identity; nested values do not duplicate it. Decoders require
the map key set to match `Parties` exactly, reject the broadcast ID and
unknown/missing parties, and validate any confirmation sender against its map
key. FROST per-party keygen confirmations use optional record tag 2, so a
missing confirmation is represented by an absent tag rather than a zero-length
or one-element record list. Protocol ordering is still derived from `Parties`,
not map iteration.

The public wrapper implements `MessageMarshaler` and `MessageUnmarshaler` to
apply domain validation, caller-provided semantic limits, fail-atomic receiver
assignment, and secret cleanup. The internal state implements only `Message`;
`wire.Marshal` and `wire.Unmarshal` encode its tagged fields directly:

```go
type KeyShare struct {
    state *keyShareState
}

type keyShareState struct {
    Party   tss.PartyID    `wire:"1,u32"`
    Parties tss.PartySet   `wire:"2,u32list,max_items=parties"`
    Secret  *secret.Scalar `wire:"3,custom,len=32,max_bytes=scalar"`
}

func (*keyShareState) WireType() string    { return "example.keyshare" }
func (*keyShareState) WireVersion() uint16 { return 1 }

func (k *KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
    // Resolve limits, apply defaults, and validate first.
    return wire.Marshal(k.state, opts...)
}

func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
    var state keyShareState
    if err := wire.Unmarshal(in, &state, opts...); err != nil {
        return err
    }
    // Validate the temporary state and destroy it on failure.
    k.state = &state
    return nil
}
```

Wrapper codecs call `wire.ResolveMarshalOptions` or
`wire.ResolveUnmarshalOptions` before invoking the reflection codec. This
ensures the same caller-provided semantic and frame limits are applied to
top-level fields, canonical map values, and nested records. Defaults are used
only when the caller supplied no corresponding options.

This approach keeps wire ownership inside the type while allowing long-lived
runtime state to store typed values such as `*secp.Point`, `*schnorr.Proof`,
`*big.Int`, and `*zkpai.LogStarProof`. Bytes are produced only at wire,
transcript, hash, and public snapshot boundaries.

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
- Tag zero is invalid in object, message-body, and record-body encodings.
- Duplicate tags are rejected.
- Nil field values are rejected by the encoder (nil bytes/list → empty).
- Decoders reject trailing bytes.
- All tagged fields are required. Missing and extra fields are rejected.
- `[N]byte` fields and map values always decode from exactly `N` bytes, even
  when the tag omits an explicit `len=N`.
- Fields tagged `bigint`, `biguint`, or `bigpos` use canonical integer encodings:
  `bigint` — signed-magnitude (zero = `0x00`); `biguint` — minimal
  big-endian (zero = empty); `bigpos` — minimal big-endian (zero rejected).
  Required `*big.Int` fields reject nil; only explicitly optional fields may
  omit a nil pointer.
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

### Trusted-dealer import records

Both protocol packages define independent v1 records for
`TrustedDealerImportPlan` and `TrustedDealerContribution`. Plans contain only
public intent and ordered contribution commitments. Contributions contain a
fixed 32-byte secret scalar, a 32-byte chain-code contribution, the bound party
and session, and the plan hash. JSON encoding is forbidden for contributions.

Plan and contribution decoders enforce total-size limits, exact field sets,
canonical tag order, canonical sorted parties, record ordering, point/scalar
validity, and no trailing bytes. Their addition does not change existing
keygen payload or `KeyShare` wire layouts.

- `tss.BlameEvidence` (direct struct encoding; `PublicInputs` as `[]EvidenceField` record list)
- `tss.BroadcastAck`
- `tss.BroadcastCertificate` (`Acks` as a canonical `BroadcastAck` record list)
- `tss.SigningContext`
- `tss.Envelope`
- `cggmp21/secp256k1.KeyShare`
- `cggmp21/secp256k1.Presign`
- `cggmp21/secp256k1.VerificationShare`
- `cggmp21/secp256k1.PaillierPublicShare`

The CGGMP21 private `Presign` record contains only the normalized Figure 8
artifact and its complete public binding. Availability is runtime/store state,
not a wire field. Decoding is structural and restores an available artifact
only for the lifecycle store or explicit import path; callers use
`VerifyCryptographicMaterialWithLimits` before use.

`Envelope` and `BlameEvidence` carry their schema version only in the TLV frame
header. Their field tags are contiguous and do not include a duplicate body
version field. Semantic protocol-version binding uses `tss.ProtocolVersion`
inside transcripts instead.

- `cggmp21/secp256k1.RingPedersenPublicShare`
- `cggmp21/secp256k1.EpochContext`
- `cggmp21/secp256k1.ChildDerivationPlan`
- `tssrun.GenerationRecord`, `PresignCandidate`, and `SignAttemptRecord`
- `cggmp21/secp256k1` Figure 6 commitment, reveal, and proof payloads
- `cggmp21/secp256k1` Figure 7 commitment, reveal, proof, direct-share, and
  decryption-error payloads
- `cggmp21/secp256k1` presign round 1 payload
- `cggmp21/secp256k1` presign round 1 proof payload
- `cggmp21/secp256k1` presign round 2 payload
- `cggmp21/secp256k1` presign round 3 payload
- `cggmp21/secp256k1` Figure 9 red-alert payload
- `cggmp21/secp256k1` online signing partial payload
- `cggmp21/secp256k1` reshare dealer commitments payload
- `cggmp21/secp256k1` reshare share payload (`dealer`, `receiver`, scalar share, dealer-commitment hash)
- `cggmp21/secp256k1` reshare receiver material payload
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
- `internal/zk/paillier.FactorProof`
- `internal/zk/paillier.RingPedersenParams`
- `internal/zk/paillier.RingPedersenProof`
- `internal/zk/paillier.EncProof` (Πenc)
- `internal/zk/paillier.AffGProof` (Πaff-g)
- `internal/zk/paillier.LogStarProof` (Πlog\*)
- `internal/zk/paillier.EncElgProof` (Πenc-elg)
- `internal/zk/paillier.ElogProof` (Πelog)
- `internal/zk/paillier.AffGStarProof` (Πaff-g\*)
- `internal/zk/paillier.MulProof` (Πmul)
- `internal/zk/paillier.MulStarProof` (Πmul\*)
- `internal/zk/paillier.DecProof` (Πdec)
- `internal/zk/schnorr.Proof`

Protocol payloads, MtA messages, Paillier keys, active Paillier proof types, and
Schnorr proofs all use the same strict TLV encoding. CGGMP21 Figure 6,
Figure 7/F.1, reshare handoff, and Figure 8 payloads carry
Paillier public keys, Ring-Pedersen parameters, and Paillier/MtA proofs as
nested typed TLV records, not pre-serialized opaque byte strings. Nested fields
still enforce the enclosing field's named `max_bytes` limit before decoding.
Keygen, auxiliary, presign, and signing payloads reject
JSON fallback, trailing bytes, duplicate tags, wrong type identifiers,
malformed curve points, malformed scalars, and non-minimal integer encodings
where integers appear.

`FactorProof` is a canonical receiver-specific Πfac record. Keygen and refresh
direct-share payloads require it as tag 2, followed by the DH-masked share, RID,
`EpochID`, and plan hash. Reshare round 2 also has the direct
`cggmp21.secp256k1.reshare.factor-proof` payload, containing prover, verifier,
the canonical prover Paillier key, Πfac, and the reshare plan hash.
The corresponding receiver-material broadcast may arrive later, but its
Paillier key must then match byte-for-byte. Key-share party data stores Πfac
only for remote parties; the local entry is checked directly against its
private factors. Records made before Πfac became mandatory are rejected.

Ring-Pedersen wire shape is `(Nhat,S,T)`. `Nhat` is independently generated and
must differ from every Paillier modulus used in the statement. Parameters use
`T=τ² mod Nhat` and `S=T^λ mod Nhat`; public decoding additionally requires
`Jacobi(S,Nhat)=Jacobi(T,Nhat)=+1`. This public check does not prove QR
membership without the factors; that guarantee comes from local generation by
the verifier.

Figure 7 and Figure 9 use dedicated, bounded accountability records:

- `cggmp21.secp256k1.payload.auxinfo.decryption-error` contains the accused
  party, one ephemeral DH exponent, the exact signed direct envelope, SID, RID,
  epoch, and plan hash. It is the only wire type allowed to disclose that
  witness.
- `cggmp21.secp256k1.payload.presign.red-alert` contains the alert kind and
  digest, one canonical public inbound/outbound MtA pair and `Πaff-g*` per peer,
  one `Πdec`, and exact plan/epoch/presign bindings. It is bounded before nested
  decode. Figure 10 has no proof payload beyond the ordinary partial.

Current Figure 8 and Figure 10 payload shapes are:

- `cggmp21.secp256k1.payload.presign.round1`: `EncK`, `EncGamma`, `Y`, `A1`,
  `A2`, `B1`, `B2`, prover Paillier key, plan hash, epoch ID, and protocol
  presign ID.
- `cggmp21.secp256k1.payload.presign.round1-proof`: the canonical public
  round-1 hash, verifier-specific `EncElgProof` records for `EncK` and
  `EncGamma`, plan hash, epoch ID, and presign ID.
- `cggmp21.secp256k1.payload.presign.round2`: `Gamma`, `ElogProof`, typed MtA
  responses for delta and chi, round-1 echo, plan hash, epoch ID, and presign
  ID. Each response carries a typed `AffGProof`.
- `cggmp21.secp256k1.payload.presign.round3`: `delta_i`, `S_i`, `Delta_i`,
  `ElogProof`, plan hash, epoch ID, and presign ID.
- `cggmp21.secp256k1.payload.sign.partial`: `sigma_i`, presign ID, epoch ID,
  presign transcript, context hash, digest hash, partial-equation hash, and sign
  plan hash.

The canonical `cggmp21.secp256k1.presign` record has 20 fields. It stores the
owner, threshold, signer set, protocol presign ID, epoch ID, `Gamma`, scalar
`r`, normalized local secret scalars `kTilde_i` and `chiTilde_i`, a
signer-ordered list of `(party,DeltaTilde,STilde)`, transcript and context
bindings, public key bindings, plan/security profile, empty-path derivation
binding, and the complete `EpochContext`. Raw Figure 8 witnesses and lifecycle
availability are not encoded.

`tssrun.SignAttemptRecord` is a durable store value rather than a protocol
payload. It contains the exact `GenerationBinding`, public presign slot,
immutable attempt identity, public Figure 10 recovery context, exact canonical
outbox, digests, delivery record, completion record, and terminal flags. A
committed attempt never contains the available presign's secret blob or
normalized secret tuple.

The nested `cggmp21.secp256k1.sign-outbox`, `sign-delivery`,
`sign-completion`, and `sign-public-context` records validate their own exact
generation, epoch, presign, attempt, signer, digest, envelope, delivery, and
verification-key bindings. Low-S is mandatory final-signature behavior, not a
wire option.

The public verification, Paillier, Ring-Pedersen, epoch, and child-plan records
also expose standard binary codecs. Unsupported historical layouts have no
decoder or compatibility path.

## Decoder Policy

Default `UnmarshalBinary` methods do not auto-detect JSON or any prior wire
shape. CGGMP21 decoders require the expected type identifier and exact field
set. Do not add automatic fallback or proof-conversion helpers to production
decoders.

Paillier proof decoders also reject nested JSON proof payloads, wrong proof type
identifiers, duplicate or unsorted fields, trailing bytes, non-minimal integers,
and malformed curve points. See [`paillier-zk-proofs.md`](paillier-zk-proofs.md)
for the proof inventory and review gaps.
