package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

func TestCGGMP21KeyShareCanonicalEncoding(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("key share encoding is not deterministic")
	}
	decoded, err := UnmarshalKeyShare(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PublicKey, shares[1].PublicKey) {
		t.Fatal("public key mismatch after canonical round trip")
	}
	if _, err := UnmarshalKeyShare([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON key share encoding accepted")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := UnmarshalKeyShare(trailing); err == nil {
		t.Fatal("key share with trailing bytes accepted")
	}
}

func TestCGGMP21RejectsWrongWireTypes(t *testing.T) {
	wrongKeyShare, err := wire.Marshal(tss.Version, "wrong.secp256k1.keyshare", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(wrongKeyShare); err == nil {
		t.Fatal("wrong key share wire type accepted")
	}
	wrongPresign, err := wire.Marshal(tss.Version, "wrong.secp256k1.presign", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPresign(wrongPresign); err == nil {
		t.Fatal("wrong presign wire type accepted")
	}
}

func TestCGGMP21KeyShareRejectsNonCanonicalFields(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	unsorted := cloneKeyShare(shares[1])
	unsorted.Parties[0], unsorted.Parties[1] = unsorted.Parties[1], unsorted.Parties[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted party set encoded")
	}
	nonCanonicalPaillier := cloneKeyShare(shares[1])
	nonCanonicalPaillier.PaillierPublicKey = append(nonCanonicalPaillier.PaillierPublicKey, ' ')
	if _, err := nonCanonicalPaillier.MarshalBinary(); err == nil {
		t.Fatal("non-canonical Paillier public key encoded")
	}
}

func TestCGGMP21KeyShareRejectsMalformedKeygenConfirmed(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := rewriteKeyShareField(raw, keyShareFieldKeygenConfirmed, []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(mutated); err == nil {
		t.Fatal("key share accepted malformed KeygenConfirmed flag")
	}
}

func TestCGGMP21KeyShareRejectsIncompleteProductionMaterial(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		tag   uint16
		value []byte
	}{
		{name: "paillier public key", tag: keyShareFieldPaillierPublicKey, value: []byte{}},
		{name: "paillier private key", tag: keyShareFieldPaillierPrivateKey, value: []byte{}},
		{name: "paillier proof", tag: keyShareFieldPaillierProof, value: []byte{}},
		{name: "Ring-Pedersen parameters", tag: keyShareFieldRingPedersenParams, value: []byte{}},
		{name: "Ring-Pedersen proof", tag: keyShareFieldRingPedersenProof, value: []byte{}},
		{name: "Ring-Pedersen public parameters", tag: keyShareFieldRingPedersenPublic, value: wire.Uint32(0)},
		{name: "paillier public key set", tag: keyShareFieldPaillierPublicKeys, value: wire.Uint32(0)},
		{name: "share proof", tag: keyShareFieldShareProof, value: []byte{}},
		{name: "keygen transcript hash", tag: keyShareFieldKeygenTranscriptHash, value: []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated, err := rewriteKeyShareField(raw, tc.tag, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalKeyShare(mutated); err == nil {
				t.Fatalf("key share missing %s decoded", tc.name)
			}
		})
	}
}

func TestCGGMP21KeyShareValidatesStoredPeerPaillierProofs(t *testing.T) {
	shares := secpKeygen(t, 2, 3)

	badModulusProof := cloneKeyShare(shares[1])
	badModulusProof.PaillierPublicKeys[0].Proof = append([]byte(nil), badModulusProof.PaillierPublicKeys[1].Proof...)
	if err := badModulusProof.Validate(); err == nil {
		t.Fatal("key share accepted swapped peer Paillier modulus proof")
	}

	badRingPedersenProof := cloneKeyShare(shares[1])
	badRingPedersenProof.RingPedersenPublic[0].Proof = append([]byte(nil), badRingPedersenProof.RingPedersenPublic[1].Proof...)
	if err := badRingPedersenProof.Validate(); err == nil {
		t.Fatal("key share accepted swapped peer Ring-Pedersen proof")
	}
}

func TestCGGMP21PresignCanonicalEncoding(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	raw1, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("presign encoding is not deterministic")
	}
	decoded, err := UnmarshalPresign(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.TranscriptHash, presigns[1].TranscriptHash) {
		t.Fatal("presign transcript mismatch after round trip")
	}
	if _, err := UnmarshalPresign([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON presign encoding accepted")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := UnmarshalPresign(trailing); err == nil {
		t.Fatal("presign with trailing bytes accepted")
	}
}

func TestCGGMP21PresignRejectsUnsortedSigners(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	unsorted := clonePresign(presigns[1])
	unsorted.Signers[0], unsorted.Signers[1] = unsorted.Signers[1], unsorted.Signers[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted signer set encoded")
	}
	if _, _, err := StartSignDigest(shares[1], unsorted, tss.SessionID{}, make([]byte, 32)); err == nil {
		t.Fatal("unsorted signer set entered signing")
	}
}

func FuzzCGGMP21KeyShareUnmarshal(f *testing.F) {
	share := secpKeygen(f, 1, 1)[1]
	raw, err := share.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		share, err := UnmarshalKeyShare(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, share, (*KeyShare).MarshalBinary, UnmarshalKeyShare)
	})
}

func FuzzCGGMP21PresignUnmarshal(f *testing.F) {
	presign := minimalCGGMP21Presign(f)
	raw, err := presign.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		presign, err := UnmarshalPresign(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, presign, (*Presign).MarshalBinary, UnmarshalPresign)
	})
}

func FuzzCGGMP21KeygenCommitmentsPayloadUnmarshal(f *testing.F) {
	shares := secpKeygen(f, 1, 1)
	payload := keygenCommitmentsPayload{
		Commitments:        shares[1].GroupCommitments,
		PaillierPublicKey:  shares[1].PaillierPublicKey,
		PaillierProof:      shares[1].PaillierProof,
		RingPedersenParams: shares[1].RingPedersenParams,
		RingPedersenProof:  shares[1].RingPedersenProof,
	}
	raw, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalKeygenCommitmentsPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalKeygenCommitmentsPayload, unmarshalKeygenCommitmentsPayload)
	})
}

func FuzzCGGMP21KeygenSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalKeygenSharePayload(keygenSharePayload{Share: scalarBytes(big.NewInt(1))})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalKeygenSharePayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalKeygenSharePayload, unmarshalKeygenSharePayload)
	})
}

func FuzzCGGMP21PresignRound3PayloadUnmarshal(f *testing.F) {
	raw, err := marshalPresignRound3Payload(presignRound3Payload{Delta: scalarBytes(big.NewInt(1))})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"delta":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalPresignRound3Payload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalPresignRound3Payload, unmarshalPresignRound3Payload)
	})
}

func FuzzCGGMP21PresignRound2PayloadUnmarshal(f *testing.F) {
	shares := secpKeygen(f, 2, 2)
	sessionID := fuzzSessionID()
	_, out1, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		f.Fatal(err)
	}
	s2, _, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		f.Fatal(err)
	}
	round2, err := s2.HandlePresignMessage(out1[0])
	if err != nil {
		f.Fatal(err)
	}
	f.Add(round2[0].Payload)
	f.Add([]byte(`{"delta":{},"sigma":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalPresignRound2Payload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalPresignRound2Payload, unmarshalPresignRound2Payload)
	})
}

func FuzzCGGMP21ReshareCommitmentsPayloadUnmarshal(f *testing.F) {
	shares := secpKeygen(f, 1, 1)
	payload := reshareCommitmentsPayload{
		Commitments:        shares[1].GroupCommitments,
		PaillierPublicKey:  shares[1].PaillierPublicKey,
		PaillierProof:      shares[1].PaillierProof,
		RingPedersenParams: shares[1].RingPedersenParams,
		RingPedersenProof:  shares[1].RingPedersenProof,
	}
	raw, err := marshalReshareCommitmentsPayload(payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareCommitmentsPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalReshareCommitmentsPayload, unmarshalReshareCommitmentsPayload)
	})
}

func FuzzCGGMP21ReshareSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalReshareSharePayload(reshareSharePayload{Share: scalarBytes(big.NewInt(1))})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareSharePayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalReshareSharePayload, unmarshalReshareSharePayload)
	})
}

func FuzzCGGMP21RefreshCommitmentsPayloadUnmarshal(f *testing.F) {
	shares := secpKeygen(f, 1, 1)
	payload := refreshCommitmentsPayload{
		Commitments:        shares[1].GroupCommitments,
		PaillierPublicKey:  shares[1].PaillierPublicKey,
		PaillierProof:      shares[1].PaillierProof,
		RingPedersenParams: shares[1].RingPedersenParams,
		RingPedersenProof:  shares[1].RingPedersenProof,
	}
	raw, err := marshalRefreshCommitmentsPayload(payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalRefreshCommitmentsPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalRefreshCommitmentsPayload, unmarshalRefreshCommitmentsPayload)
	})
}

func FuzzCGGMP21RefreshSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalRefreshSharePayload(refreshSharePayload{Share: scalarBytes(big.NewInt(1))})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalRefreshSharePayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalRefreshSharePayload, unmarshalRefreshSharePayload)
	})
}

func minimalCGGMP21Presign(tb testing.TB) *Presign {
	tb.Helper()
	one := big.NewInt(1)
	RPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(one))
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		tb.Fatal(err)
	}
	littleR := new(big.Int).Mod(RPoint.X.BigInt(), secp.Order())
	transcript := sha256.Sum256([]byte("minimal presign"))
	ctx := testPresignContext()
	contextHash := presignContextHash(ctx)
	return &Presign{
		Version:        tss.Version,
		Party:          1,
		Threshold:      1,
		Signers:        []tss.PartyID{1},
		R:              R,
		LittleR:        scalarBytes(littleR),
		KShare:         scalarBytes(one),
		ChiShare:       scalarBytes(one),
		Delta:          scalarBytes(one),
		TranscriptHash: transcript[:],
		Context:        ctx,
		ContextHash:    contextHash,
	}
}

func cloneKeyShare(in *KeyShare) *KeyShare {
	if in == nil {
		return nil
	}
	out := *in
	out.Parties = append([]tss.PartyID(nil), in.Parties...)
	out.PublicKey = append([]byte(nil), in.PublicKey...)
	out.ChainCode = append([]byte(nil), in.ChainCode...)
	out.secret = append([]byte(nil), in.secret...)
	out.GroupCommitments = cloneByteSlices(in.GroupCommitments)
	out.VerificationShares = append([]VerificationShare(nil), in.VerificationShares...)
	for i := range out.VerificationShares {
		out.VerificationShares[i].PublicKey = append([]byte(nil), in.VerificationShares[i].PublicKey...)
	}
	out.PaillierPublicKey = append([]byte(nil), in.PaillierPublicKey...)
	out.paillierPrivateKey = append([]byte(nil), in.paillierPrivateKey...)
	out.PaillierProof = append([]byte(nil), in.PaillierProof...)
	out.PaillierPublicKeys = append([]PaillierPublicShare(nil), in.PaillierPublicKeys...)
	for i := range out.PaillierPublicKeys {
		out.PaillierPublicKeys[i].PublicKey = append([]byte(nil), in.PaillierPublicKeys[i].PublicKey...)
		out.PaillierPublicKeys[i].Proof = append([]byte(nil), in.PaillierPublicKeys[i].Proof...)
	}
	out.RingPedersenParams = append([]byte(nil), in.RingPedersenParams...)
	out.RingPedersenProof = append([]byte(nil), in.RingPedersenProof...)
	out.RingPedersenPublic = append([]RingPedersenPublicShare(nil), in.RingPedersenPublic...)
	for i := range out.RingPedersenPublic {
		out.RingPedersenPublic[i].Params = append([]byte(nil), in.RingPedersenPublic[i].Params...)
		out.RingPedersenPublic[i].Proof = append([]byte(nil), in.RingPedersenPublic[i].Proof...)
	}
	out.PaillierProofSessionID = in.PaillierProofSessionID
	out.PaillierProofDomain = in.PaillierProofDomain
	out.ShareProof = append([]byte(nil), in.ShareProof...)
	out.KeygenTranscriptHash = append([]byte(nil), in.KeygenTranscriptHash...)
	return &out
}

func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func rewriteKeyShareField(raw []byte, tag uint16, value []byte) ([]byte, error) {
	return rewriteWireField(raw, keyShareWireType, tag, value)
}

func rewriteWireField(raw []byte, wireType string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.Unmarshal(raw, wireType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = make([]byte, len(value))
			copy(fields[i].Value, value)
			return wire.Marshal(version, wireType, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %d", tag)
}

func rewriteNestedWireField(raw []byte, outerType string, outerTag uint16, innerType string, innerTag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.Unmarshal(raw, outerType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag != outerTag {
			continue
		}
		inner, err := rewriteWireField(fields[i].Value, innerType, innerTag, value)
		if err != nil {
			return nil, err
		}
		fields[i].Value = inner
		return wire.Marshal(version, outerType, fields)
	}
	return nil, fmt.Errorf("missing outer wire field %d", outerTag)
}

func mutatePresignRound1Payload(raw []byte, mutate func(*presignRound1Payload)) ([]byte, error) {
	original, err := unmarshalPresignRound1Payload(raw)
	if err != nil {
		return nil, err
	}
	payload, err := unmarshalPresignRound1Payload(raw)
	if err != nil {
		return nil, err
	}
	mutate(&payload)
	if !bytes.Equal(original.Gamma, payload.Gamma) {
		return rewriteWireField(raw, presignRound1PayloadWireType, presignRound1PayloadFieldGamma, payload.Gamma)
	}
	if !bytes.Equal(original.EncK, payload.EncK) {
		return rewriteWireField(raw, presignRound1PayloadWireType, presignRound1PayloadFieldEncK, payload.EncK)
	}
	if !bytes.Equal(original.EncKProof, payload.EncKProof) {
		return rewriteWireField(raw, presignRound1PayloadWireType, presignRound1PayloadFieldEncKProof, payload.EncKProof)
	}
	if !bytes.Equal(original.PaillierPublicKey, payload.PaillierPublicKey) {
		return rewriteWireField(raw, presignRound1PayloadWireType, presignRound1PayloadFieldPaillierPublicKey, payload.PaillierPublicKey)
	}
	return marshalPresignRound1Payload(payload)
}

func mutatePresignRound2Payload(raw []byte, mutate func(*presignRound2Payload)) ([]byte, error) {
	original, err := unmarshalPresignRound2Payload(raw)
	if err != nil {
		return nil, err
	}
	payload, err := unmarshalPresignRound2Payload(raw)
	if err != nil {
		return nil, err
	}
	mutate(&payload)
	const mtaResponseWireType = "mta.response-message"
	const (
		mtaResponseFieldCiphertext uint16 = 1
		mtaResponseFieldProof      uint16 = 2
	)
	if !bytes.Equal(original.Delta.Ciphertext, payload.Delta.Ciphertext) {
		return rewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldDelta, mtaResponseWireType, mtaResponseFieldCiphertext, payload.Delta.Ciphertext)
	}
	if !bytes.Equal(original.Delta.Proof, payload.Delta.Proof) {
		return rewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldDelta, mtaResponseWireType, mtaResponseFieldProof, payload.Delta.Proof)
	}
	if !bytes.Equal(original.Sigma.Ciphertext, payload.Sigma.Ciphertext) {
		return rewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldSigma, mtaResponseWireType, mtaResponseFieldCiphertext, payload.Sigma.Ciphertext)
	}
	if !bytes.Equal(original.Sigma.Proof, payload.Sigma.Proof) {
		return rewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldSigma, mtaResponseWireType, mtaResponseFieldProof, payload.Sigma.Proof)
	}
	if !bytes.Equal(original.Round1Echo, payload.Round1Echo) {
		return rewriteWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldRound1Echo, payload.Round1Echo)
	}
	return marshalPresignRound2Payload(payload)
}

func assertPayloadRemarshals[P any](t *testing.T, p P, marshal func(P) ([]byte, error), unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("payload did not remarshal deterministically")
	}
}
