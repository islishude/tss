//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"math"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
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
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := UnmarshalKeyShare(trailing); err == nil {
		t.Fatal("key share with trailing bytes accepted")
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

func TestCGGMP21KeyShareRejectsMalformedKeygenConfirmations(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := testutil.RewriteWireField(raw, keyShareWireType, keyShareFieldKeygenConfirmations, []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(mutated); err == nil {
		t.Fatal("key share accepted malformed keygen confirmations")
	}
}

func TestCGGMP21KeyShareRejectsEmptyKeygenConfirmations(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := testutil.RewriteWireField(raw, keyShareWireType, keyShareFieldKeygenConfirmations, wire.EncodeBytesList(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(mutated); err == nil {
		t.Fatal("key share accepted empty keygen confirmations")
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
			mutated, err := testutil.RewriteWireField(raw, keyShareWireType, tc.tag, tc.value)
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

func TestCGGMP21KeyShareRejectsOverflowThreshold(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, overflow := range []uint32{math.MaxInt32 + 1, math.MaxUint32} {
		mutated, err := testutil.RewriteWireField(raw, keyShareWireType, keyShareFieldThreshold, wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalKeyShare(mutated); err == nil {
			t.Fatalf("key share threshold %d accepted", overflow)
		}
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
		testutil.AssertDeterministicRoundTrip(t, share, (*KeyShare).MarshalBinary, UnmarshalKeyShare)
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
		testutil.AssertDeterministicRoundTrip(t, p, marshalKeygenCommitmentsPayload, unmarshalKeygenCommitmentsPayload)
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
	round2 := deliverPresignMessagesTo(f, s2, 2, out1)
	f.Add(round2[0].Payload)
	f.Add([]byte(`{"delta":{},"sigma":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalPresignRound2Payload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, p, marshalPresignRound2Payload, unmarshalPresignRound2Payload)
	})
}

func FuzzCGGMP21ReshareDealerCommitmentsPayloadUnmarshal(f *testing.F) {
	shares := secpKeygen(f, 1, 1)
	payload := reshareDealerCommitmentsPayload{Commitments: shares[1].GroupCommitments}
	raw, err := marshalReshareDealerCommitmentsPayload(payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareDealerCommitmentsPayload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, p, marshalReshareDealerCommitmentsPayload, unmarshalReshareDealerCommitmentsPayload)
	})
}

func FuzzCGGMP21ReshareReceiverMaterialPayloadUnmarshal(f *testing.F) {
	shares := secpKeygen(f, 1, 1)
	payload := reshareReceiverMaterialPayload{
		PaillierPublicKey:  shares[1].PaillierPublicKey,
		PaillierProof:      shares[1].PaillierProof,
		RingPedersenParams: shares[1].RingPedersenParams,
		RingPedersenProof:  shares[1].RingPedersenProof,
	}
	raw, err := marshalReshareReceiverMaterialPayload(payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"paillier_public_key":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareReceiverMaterialPayload(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, p, marshalReshareReceiverMaterialPayload, unmarshalReshareReceiverMaterialPayload)
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
		testutil.AssertDeterministicRoundTrip(t, p, marshalRefreshCommitmentsPayload, unmarshalRefreshCommitmentsPayload)
	})
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
		return testutil.RewriteWireField(raw, presignRound1PayloadWireType, presignRound1PayloadFieldGamma, payload.Gamma)
	}
	if !bytes.Equal(original.EncK, payload.EncK) {
		return testutil.RewriteWireField(raw, presignRound1PayloadWireType, presignRound1PayloadFieldEncK, payload.EncK)
	}
	if !bytes.Equal(original.PaillierPublicKey, payload.PaillierPublicKey) {
		return testutil.RewriteWireField(raw, presignRound1PayloadWireType, presignRound1PayloadFieldPaillierPublicKey, payload.PaillierPublicKey)
	}
	return marshalPresignRound1Payload(payload)
}

func mutatePresignRound1ProofPayload(raw []byte, mutate func(*presignRound1ProofPayload)) ([]byte, error) {
	original, err := unmarshalPresignRound1ProofPayload(raw)
	if err != nil {
		return nil, err
	}
	payload, err := unmarshalPresignRound1ProofPayload(raw)
	if err != nil {
		return nil, err
	}
	mutate(&payload)
	if !bytes.Equal(original.PublicRound1Hash, payload.PublicRound1Hash) {
		return testutil.RewriteWireField(raw, presignRound1ProofPayloadWireType, presignRound1ProofPayloadFieldPublicHash, payload.PublicRound1Hash)
	}
	if !bytes.Equal(original.EncKProof, payload.EncKProof) {
		return testutil.RewriteWireField(raw, presignRound1ProofPayloadWireType, presignRound1ProofPayloadFieldEncKProof, payload.EncKProof)
	}
	return marshalPresignRound1ProofPayload(payload)
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
		return testutil.RewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldDelta, mtaResponseWireType, mtaResponseFieldCiphertext, payload.Delta.Ciphertext)
	}
	if !bytes.Equal(original.Delta.Proof, payload.Delta.Proof) {
		return testutil.RewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldDelta, mtaResponseWireType, mtaResponseFieldProof, payload.Delta.Proof)
	}
	if !bytes.Equal(original.Sigma.Ciphertext, payload.Sigma.Ciphertext) {
		return testutil.RewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldSigma, mtaResponseWireType, mtaResponseFieldCiphertext, payload.Sigma.Ciphertext)
	}
	if !bytes.Equal(original.Sigma.Proof, payload.Sigma.Proof) {
		return testutil.RewriteNestedWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldSigma, mtaResponseWireType, mtaResponseFieldProof, payload.Sigma.Proof)
	}
	if !bytes.Equal(original.Round1Echo, payload.Round1Echo) {
		return testutil.RewriteWireField(raw, presignRound2PayloadWireType, presignRound2PayloadFieldRound1Echo, payload.Round1Echo)
	}
	return marshalPresignRound2Payload(payload)
}
