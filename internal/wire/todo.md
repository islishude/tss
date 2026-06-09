# internal/wire — remaining work

## Completed

- `custom` kind + `ValueMarshaler`/`ValueUnmarshaler`
- `bigint`/`biguint`/`bigpos` native kinds
- Exported helpers: `wire.EncodeBigInt`/`DecodeBigInt`/`EncodeBigUint`/`DecodeBigUint`/`EncodeBigPos`/`DecodeBigPos`
- `transcript.go` migrated to `wire.EncodeBigInt` (replaces `EncodeSigned`)
- Schema validation: `len=N` vs `[N]byte` array length
- `secret.Scalar.MarshalWireValue`/`UnmarshalWireValue`
- `WirePoint` adapter (`internal/curve/secp256k1`)
- ZK proof DTO migration (affg/enc/logstar)
- Payload scalar DTO migration
- signprep proof scalar migration

## Unfinished — Point field migration

**`presignRound3Payload.KPoint`/`ChiPoint`** (priority: medium)
- Currently: `[]byte` + `wire:"2,bytes"`, manual `secp.PointBytes`/`PointFromBytes`
- Target: `secp.WirePoint` + `wire:"2,custom,max_bytes=point"`
- Blocker: `SignVerifyShare.KPoint`/`ChiPoint` are also `[]byte`, need coordinated migration
- Files: `sign.go`, `payload_encoding.go`, `presign_round3.go`, `types.go`

**signprep point fields** (priority: low)
- `Proof.MPoint`, `KCommitment`, `MCommitment`, `DLEQA1`, `DLEQA2`
- Files: `internal/zk/signprep/types.go`, `prove.go`, `verify.go`, `encoding.go`

**edwards25519 WirePoint** (priority: low)
- frost/ed25519 point fields need corresponding adapter
- Location: `internal/curve/edwards25519`

## Unfinished — Other

**ring_pedersen DTO** (priority: low)
- Uses `fixedModNBytes` (fixed modulus width), incompatible with `bigpos` minimal encoding
- File: `internal/zk/paillier/ring_pedersen.go`

**`presignWire.LittleR`/`AdditiveShift`** (priority: low)
- Exported fields `Presign.LittleR`/`AdditiveShift` are `[]byte`, changing would affect API

**`integer.go` old helpers** (priority: low)
- `EncodeSigned`/`DecodeSigned`/`DecodePositive` still defined in `internal/zk/paillier/integer.go`
- No callers remain except utility functions (random sampling, range checks)

## Documentation

- Phase 5: DTO as domain wire boundary conceptual documentation
