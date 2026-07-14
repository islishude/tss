package ed25519

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/islishude/tss/internal/testvectors"
)

const (
	fuzzKeyShare uint8 = iota
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
	}

	f.Fuzz(func(t *testing.T, kind uint8, raw []byte) {
		limits := testLimits()
		var (
			canonical []byte
			err       error
		)
		switch kind % 6 {
		case fuzzKeyShare:
			var share *KeyShare
			share, err = UnmarshalKeyShareWithLimits(raw, limits)
			if err != nil {
				return
			}
			defer share.Destroy()
			canonical, err = share.MarshalBinaryWithLimits(limits)
		case fuzzNonceCommitment:
			var value nonceCommitment
			value, err = unmarshalNonceCommitmentPayload(raw)
			if err != nil {
				return
			}
			canonical, err = marshalNonceCommitmentPayloadWithLimits(value, limits)
		case fuzzSignPartial:
			var value signPartialPayload
			value, err = unmarshalSignPartialPayload(raw)
			if err != nil {
				return
			}
			canonical, err = marshalSignPartialPayloadWithLimits(value, limits)
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
			canonical, err = marshalReshareCommitmentsPayloadWithLimits(value, limits)
		case fuzzReshareShare:
			var value reshareSharePayload
			value, err = unmarshalReshareSharePayload(raw)
			if err != nil {
				return
			}
			defer value.Share.Destroy()
			canonical, err = marshalReshareSharePayloadWithLimits(value, limits)
		}
		if err != nil {
			t.Fatalf("accepted value failed canonical re-encode: %v", err)
		}
		if !bytes.Equal(raw, canonical) {
			t.Fatal("semantic decoder accepted a non-canonical encoding")
		}
	})
}
