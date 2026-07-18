package ed25519

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testvectors"
	"github.com/islishude/tss/internal/wire"
)

const (
	fuzzKeyShare uint8 = iota
	fuzzKeygenCommitments
	fuzzKeygenShare
	fuzzNonceCommitment
	fuzzSignPartial
	fuzzKeygenConfirmation
	fuzzReshareCommitments
	fuzzReshareShare
)

// FuzzFROSTSemanticDecoders exercises the protocol-level semantic decoders,
// beyond the generic TLV frame parser. Accepted inputs must already be
// canonical and survive a deterministic re-encode.
func FuzzFROSTSemanticDecoders(f *testing.F) {
	seeds := []struct {
		kind uint8
		name string
	}{
		{kind: fuzzKeyShare, name: "wire/v1/frost/KeyShare.golden"},
		{kind: fuzzKeygenCommitments, name: "wire/v1/frost/KeygenCommitmentsPayload.golden"},
		{kind: fuzzKeygenShare, name: "wire/v1/frost/KeygenSharePayload.golden"},
		{kind: fuzzNonceCommitment, name: "wire/v1/frost/NonceCommitmentPayload.golden"},
		{kind: fuzzSignPartial, name: "wire/v1/frost/SignPartialPayload.golden"},
		{kind: fuzzKeygenConfirmation, name: "wire/v1/frost/KeygenConfirmation.golden"},
		{kind: fuzzReshareCommitments, name: "wire/v1/frost/ReshareCommitmentsPayload.golden"},
		{kind: fuzzReshareShare, name: "wire/v1/frost/ReshareSharePayload.golden"},
	}
	for _, seed := range seeds {
		encoded := bytes.TrimSpace(testvectors.Read(f, seed.name))
		raw := make([]byte, hex.DecodedLen(len(encoded)))
		n, err := hex.Decode(raw, encoded)
		if err != nil {
			f.Fatalf("decode seed %s: %v", seed.name, err)
		}
		f.Add(seed.kind, raw[:n])
		if seed.kind == fuzzKeygenCommitments {
			version, fields, err := wire.UnmarshalFields(raw[:n], keygenCommitmentsPayloadWireType)
			if err != nil {
				f.Fatalf("decode keygen commitment seed fields: %v", err)
			}
			if len(fields) != 4 || fields[len(fields)-1].Tag != 4 {
				f.Fatalf("keygen commitment seed does not end in required proof tag 4")
			}
			proofless, err := wire.MarshalFields(version, keygenCommitmentsPayloadWireType, fields[:len(fields)-1])
			if err != nil {
				f.Fatalf("build retired proof-less keygen commitment seed: %v", err)
			}
			f.Add(seed.kind, proofless)
		}
	}

	f.Fuzz(func(t *testing.T, kind uint8, raw []byte) {
		limits := testLimits()
		var (
			canonical []byte
			err       error
		)
		switch kind % 8 {
		case fuzzKeyShare:
			var share *KeyShare
			share, err = tss.DecodeBinaryWithLimits[KeyShare](raw, limits)
			if err != nil {
				return
			}
			defer share.Destroy()
			canonical, err = share.MarshalBinaryWithLimits(limits)
		case fuzzKeygenCommitments:
			var value keygenCommitmentsPayload
			value, err = unmarshalKeygenCommitmentsPayload(raw)
			if err != nil {
				return
			}
			canonical, err = value.MarshalBinaryWithLimits(limits)
		case fuzzKeygenShare:
			var value keygenSharePayload
			value, err = unmarshalKeygenSharePayload(raw)
			if err != nil {
				return
			}
			defer value.Share.Destroy()
			canonical, err = value.MarshalBinaryWithLimits(limits)
		case fuzzNonceCommitment:
			var value nonceCommitment
			value, err = unmarshalNonceCommitmentPayload(raw)
			if err != nil {
				return
			}
			canonical, err = value.MarshalBinaryWithLimits(limits)
		case fuzzSignPartial:
			var value signPartialPayload
			value, err = unmarshalSignPartialPayload(raw)
			if err != nil {
				return
			}
			canonical, err = value.MarshalBinaryWithLimits(limits)
		case fuzzKeygenConfirmation:
			var value KeygenConfirmation
			err = value.UnmarshalBinaryWithLimits(raw, limits)
			if err != nil {
				return
			}
			canonical, err = value.MarshalBinary()
		case fuzzReshareCommitments:
			var value reshareCommitmentsPayload
			value, err = unmarshalReshareCommitmentsPayload(raw)
			if err != nil {
				return
			}
			canonical, err = value.MarshalBinaryWithLimits(limits)
		case fuzzReshareShare:
			var value reshareSharePayload
			value, err = unmarshalReshareSharePayload(raw)
			if err != nil {
				return
			}
			defer value.Share.Destroy()
			canonical, err = value.MarshalBinaryWithLimits(limits)
		}
		if err != nil {
			t.Fatalf("accepted value failed canonical re-encode: %v", err)
		}
		if !bytes.Equal(raw, canonical) {
			t.Fatal("semantic decoder accepted a non-canonical encoding")
		}
	})
}
