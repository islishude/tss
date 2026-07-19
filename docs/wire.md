# Wire Encoding

`internal/wire` is the repository's single canonical binary codec. Production
protocol code uses its object-level API; external callers use the binary methods
exposed by public types and must not import an `internal` package.

## Frame Format

Every top-level message uses this strict TLV frame:

```text
magic       = "TSS1"
type_len    = uint16
type_id     = type_len bytes of non-empty UTF-8
version     = uint16
field_count = uint16
field       = tag:uint16 || value_len:uint32 || value
```

Fields are ordered by strictly increasing, non-zero tag. The decoder requires
the expected type identifier and version, applies size limits before allocating,
and rejects duplicate or unsorted tags, truncation, and trailing data.

## Public Binary API

Public records that callers persist, transmit, or restore expose canonical
`MarshalBinary` / `UnmarshalBinary` methods compatible with the standard
`encoding` interfaces:

```go
raw, err := value.MarshalBinary()

var restored SomeType
err = restored.UnmarshalBinary(raw)
```

Records with caller-controlled resource policy also expose limit-aware methods.
Package convenience functions, where present, delegate to the same codec rather
than maintaining a second decoder.

## Object-Level API

Production message types use `wire.Marshal` and `wire.Unmarshal` with struct
tags or the object-level hooks described below:

```go
type myMessage struct {
    SessionID [32]byte `wire:"1"`
    Count     uint32   `wire:"2"`
}

func (myMessage) WireType() string    { return "example.message" }
func (myMessage) WireVersion() uint16 { return 1 }

raw, err := wire.Marshal(myMessageValue)

var decoded myMessage
err = wire.Unmarshal(raw, &decoded)
```

Production code must not assemble message frames with `MarshalFields`,
`UnmarshalFields`, or `RequireExactTags`. Those low-level helpers are reserved
for `internal/wire`, fuzzing, mutation tests, and shared test infrastructure.

### Struct Tags and Kinds

```text
wire:"<tag>"                     infer the kind from the Go type
wire:"<tag>,<kind>"              declare the kind
wire:"<tag>,<option>..."         infer the kind and apply options
wire:"<tag>,<kind>,<option>..."  declare both
wire:"-"                         ignore the field
```

Tagged fields must be exported. Untagged fields and fields tagged `-` are not
encoded. Named primitive types are supported.

| Kind             | Go shape                                     | Canonical value encoding                  |
| ---------------- | -------------------------------------------- | ----------------------------------------- |
| `u8`             | `uint8`                                      | one byte                                  |
| `u16`            | `uint16`                                     | big-endian uint16                         |
| `u32`            | `uint32`, `int`, or aliases                  | big-endian uint32                         |
| `bool`           | `bool`                                       | `wire.Bool`                               |
| `bytes`          | `[]byte` or `[N]byte`                        | raw bytes                                 |
| `string`         | `string`                                     | UTF-8 bytes                               |
| `u32list`        | `[]uint32`, `[]int`, or aliases              | count plus canonical integers             |
| `byteslist`      | `[][]byte`                                   | count plus length-prefixed items          |
| `partybytes`     | `[]wire.PartyBytes[T]`                       | canonical party/value tuples              |
| `partybytepairs` | `[]wire.PartyBytePair[T]`                    | canonical party/value-pair tuples         |
| `nested`         | a type implementing `Message`                | complete nested TLV frame                 |
| `record`         | struct or pointer to struct                  | field body without a TLV frame            |
| `recordlist`     | slice of structs or struct pointers          | count plus length-prefixed record bodies  |
| `custom`         | value-codec type                             | bytes owned by the domain type            |
| `customlist`     | slice of value-codec types                   | count plus length-prefixed custom values  |
| `bigint`         | `big.Int` or `*big.Int`                      | signed magnitude                          |
| `biguint`        | `big.Int` or `*big.Int`                      | minimal unsigned magnitude; zero is empty |
| `bigpos`         | `big.Int` or `*big.Int`                      | minimal positive magnitude; zero rejects  |
| `map`            | `map[K]V`, where `K` is `uint32` or an alias | sorted length-prefixed key/value entries  |

Inference covers primitive values, byte/integer lists, records, record lists,
and types implementing `ValueMarshaler`. Declare `partybytes`,
`partybytepairs`, `nested`, `customlist`, all `big.Int` kinds, and `map`
explicitly. Requiring explicit integer signedness and map encoding prevents a Go
type refactor from silently changing the wire contract.

`record` and `recordlist` enforce the same exact-field, tag-order, duplicate,
and trailing-data rules as a top-level message. They have no nested magic,
type, or version header.

### Options

- `len=N` sets an exact byte length. `[N]byte` also has an intrinsic exact
  length.
- `max_bytes=name` applies a named per-value byte cap.
- `max_bits=name` applies a named integer bit cap, or the conservative
  `len(value) * 8` bound for byte values.
- `max_items=name` applies a named count cap.
- `optional` omits a nil pointer and accepts an absent field. It is valid only
  for pointer `record`, `nested`, `custom`, `bigint`, `biguint`, and `bigpos`
  fields.

Unsupported option/kind combinations, duplicate options, non-positive fixed
lengths, and limit names outside `[a-z][a-z0-9_]*` fail when the schema is
parsed.

For `customlist`, `len` and `max_bytes` apply to each item while `max_items`
applies to the list. A `custom` field may use `max_items` only when its canonical
bytes begin with a big-endian uint32 count; the domain codec still owns item
validation.

### Interfaces and Hooks

- `Message` supplies `WireType` and `WireVersion`.
- `Validator` runs before marshal and after unmarshal.
- `BeforeMarshaler` runs before encoding.
- `AfterUnmarshaler` runs after field decoding and before validation.
- `ValueMarshaler` / `ValueUnmarshaler` own one `custom` field value.
- `MessageMarshaler` / `MessageUnmarshaler` own a complete TLV message while
  remaining behind `wire.Marshal` / `wire.Unmarshal`.

`wire.Marshal` reparses a custom message result to enforce its type, version,
canonical frame, and field ordering. `wire.Unmarshal` performs frame preflight
before invoking a custom decoder and decodes into temporary state, so the
original destination is unchanged on error. A custom decoder still owns its
exact field schema, semantic validation, input copying, and secret cleanup.

## Limits

`FrameLimits` caps total input bytes, field count, and bytes per field. A
zero-valued member inherits that member from `DefaultFrameLimits`; negative or
otherwise invalid limits reject.

`FieldLimits` maps the names referenced by `max_bytes`, `max_bits`, and
`max_items` to values. A tag that names a missing limit fails closed; it never
silently becomes unlimited. Use `WithFrameLimits` and `WithFieldLimits` for
decode, and `WithFieldLimitsForMarshal` for encode.

Protocol packages adapt their public `Limits` values to these wire options.
Object-level message hooks use `ResolveMarshalOptions` and
`ResolveUnmarshalOptions` so nested records and map values receive the same
caller policy.

## Canonical Value Rules

- Nil byte slices, lists, and maps encode as empty values. Other required nil
  pointers reject; only `optional` fields may be absent.
- Every non-optional tagged field is required. Missing required and extra fields
  reject.
- `[N]byte` fields and `[N]byte` map values require exactly `N` bytes even
  without `len=N`.
- Strings must be valid UTF-8.
- `bigint` uses one sign byte followed by a minimal magnitude. Zero is `00`;
  empty input, negative zero, invalid sign bytes, and leading zeroes reject.
- `biguint` uses a minimal magnitude with empty encoding for zero. Negative and
  leading-zero values reject.
- `bigpos` requires a non-empty, minimal, strictly positive magnitude.
- Curve scalars, points, proof integers, and proof points receive their
  domain-specific canonical and range checks after structural decoding.

One semantic record must have one binary representation. That property is part
of transcript binding, storage integrity, and vector compatibility.

### Map Rules

Map fields encode:

```text
uint32 entry_count
repeat entry_count:
    uint32 key_len     // exactly 4
    key_bytes          // big-endian uint32
    uint32 value_len
    value_bytes
```

Entries are sorted by canonical key bytes. Decoders reject non-increasing order,
duplicate keys, non-four-byte keys, unsupported value types, excess counts or
value sizes, and trailing bytes. Nil and empty maps both encode as count zero.

Supported values are `uint8`, `uint16`, `uint32`, `bool`, `string`, `[]byte`,
`[N]byte`, a value-codec type, or a record struct. Nested maps, nested messages,
and non-byte slices are not supported. Map keys identify ownership when used for
per-party state; protocol code must compare the key set with the canonical party
set and iterate that ordered set rather than Go map order.

## Opaque State

Long-lived public objects may keep mutable or secret-bearing fields behind an
unexported state pointer. Their message hooks encode an internal tagged record,
apply caller limits and domain validation, decode into temporary state, and
replace the receiver only after every check succeeds. Temporary secret state is
destroyed on failure.

This keeps key shares, presigns, plans, scalars, points, proofs, and large
integers typed and opaque until a wire, transcript, hash, or public-snapshot
boundary.

## Labeled SHA-256 Transcripts

Repository-defined SHA-256 transcripts, commitments, challenges, domains, and
evidence hashes use `internal/transcript`. Each entry is encoded as:

```text
u32be(label_length) || label || u32be(value_length) || value
```

The first entry is `("domain", domain_label)`. Later labels are non-empty,
stable ASCII `snake_case`. Integers, booleans, lists, and sets use canonical
wire encodings; set-valued inputs are sorted first.

Renaming, reordering, adding, or removing a transcript field changes the digest
and requires binding tests and vector review. RFC-defined hashes and plain
content hashes such as `SHA-256(payload)` do not use this repository-defined
transcript format.

## Record Ownership and Decoder Policy

Root-package envelopes and evidence, `tssrun` durable records, FROST and
CGGMP21 payloads, MtA messages, Paillier keys, and proof objects all use the
strict codec. Their owning Go structs or custom message codecs define exact
field schemas; protocol documents define semantics. This document deliberately
does not duplicate a field-by-field record inventory.

Default decoders require the expected type, version, and exact current schema.
They do not auto-detect JSON or retired layouts. Do not add fallback decoders,
proof conversion, or compatibility versions before the repository adopts a
production compatibility policy.

Committed encodings and verification commands are cataloged in
[`internal/testvectors/README.md`](../internal/testvectors/README.md). See
[`frost-ed25519.md`](frost-ed25519.md),
[`cggmp21-secp256k1.md`](cggmp21-secp256k1.md), and
[`tssrun.md`](tssrun.md) for protocol and lifecycle semantics, and
[`paillier-zk-proofs.md`](paillier-zk-proofs.md) for proof inventory and review
status.

Trusted-dealer contributions and some persisted protocol records contain secret
material. They use canonical binary encoding only and must not appear in JSON,
logs, blame evidence, or public vectors.
