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
wire:"<tag>,<kind>[,<option>...]"
wire:"-"   // skip field
```

#### Supported Kinds

| Kind             | Go Type                               | Wire Encoding               |
| ---------------- | ------------------------------------- | --------------------------- |
| `u8`             | `uint8`                               | single byte                 |
| `u16`            | `uint16`                              | big-endian uint16           |
| `u32`            | `uint32`, `int`, or alias             | big-endian uint32           |
| `bool`           | `bool`                                | `wire.Bool`                 |
| `bytes`          | `[]byte`                              | raw bytes; nil → empty      |
| `string`         | `string`                              | UTF-8 bytes                 |
| `u32list`        | `[]uint32` or alias slice             | `wire.EncodeUint32List`     |
| `byteslist`      | `[][]byte`                            | `wire.EncodeBytesList`      |
| `partybytes`     | `[]wire.PartyBytes[T]`                | `wire.EncodePartyBytes`     |
| `partybytepairs` | `[]wire.PartyBytePair[T]`             | `wire.EncodePartyBytePairs` |
| `nested`         | struct/pointer implementing `Message` | recursive `wire.Marshal`    |

#### Options

- `len=N` — fixed byte length (validated on decode)
- `max_bytes=name` — semantic byte limit (from `wire.WithLimitSet`)
- `max_items=name` — semantic item count limit
- `allow_empty` — documents that empty is permitted (no-op)

### Interfaces

- **`Message`** — required: `WireType() string`, `WireVersion() uint16`
- **`Validator`** — optional: `Validate() error` (called on marshal and unmarshal)
- **`BeforeMarshaler`** — optional: `BeforeMarshalWire() error`
- **`AfterUnmarshaler`** — optional: `AfterUnmarshalWire() error`

### Field-Level API (Tests Only)

The low-level `MarshalFields` / `UnmarshalFields` / `UnmarshalFieldsWithLimits` and `RequireExactTags` are restricted to test infrastructure (`internal/testutil`, mutation tests, fuzz tests) and the `internal/wire` package itself. Production code must use the object-level API.

### Limits

- **TLV-level** (`wire.Limits`): `MaxTotalBytes`, `MaxFields`, `MaxFieldBytes` — applied during envelope decode via `wire.WithLimits`
- **Semantic-level** (`wire.LimitSet`): per-field max bytes/items checked against named limits via `wire.WithLimitSet`

## DTO Pattern

Types with unexported fields (`secret.Scalar`, `*big.Int`, `sync.Mutex`) or array types (`[32]byte`) use unexported wire DTOs:

```go
type myMessageWire struct {
    SessionID []byte `wire:"1,bytes,len=32"`
    Secret    []byte `wire:"2,bytes"`
}
func (myMessageWire) WireType() string    { return "my.type" }
func (myMessageWire) WireVersion() uint16 { return 1 }
```

Conversion functions (`toWire()` / `toDomain()`) handle `[32]byte` ↔ `[]byte`, `*big.Int` ↔ `[]byte`, and custom type mapping.

## Canonical Rules

- `type_id` must be non-empty and match the expected decoder type.
- Fields must be sorted by strictly increasing tag.
- Duplicate tags are rejected.
- Nil field values are rejected by the encoder (nil bytes/list → empty).
- Decoders reject trailing bytes.
- All tagged fields are required. Missing and extra fields are rejected.
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
- `cggmp21.secp256k1.payload.sign.partial`: fields are `S` (scalar), `PresignTranscript` (32 bytes), `PresignContext` (32 bytes), `DigestHash` (32 bytes), and `PartialEquationHash` (32 bytes).

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
