//go:build integration

package secp256k1

import (
	"bytes"
	"math"
	"slices"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestCGGMP21KeyShareCanonicalEncoding(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
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
	reordered := cloneKeyShareValue(shares[1])
	reordered.state.PartyData = make(map[tss.PartyID]keySharePartyData, len(reordered.state.Parties))
	for i := len(reordered.state.Parties) - 1; i >= 0; i-- {
		id := reordered.state.Parties[i]
		reordered.state.PartyData[id] = shares[1].state.PartyData[id].Clone()
	}
	raw3, err := reordered.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw3) {
		t.Fatal("key share map insertion order changed canonical encoding")
	}
	decoded, err := tss.DecodeBinary[KeyShare](raw1)
	if err != nil {
		t.Fatal(err)
	}
	decodedMeta := mustKeyShareMetadata(t, decoded)
	shareMeta := mustKeyShareMetadata(t, shares[1])
	if !bytes.Equal(decodedMeta.PublicKey, shareMeta.PublicKey) {
		t.Fatal("public key mismatch after canonical round trip")
	}
	if !slices.Equal(decodedMeta.Parties, shareMeta.Parties) {
		t.Fatal("party order changed after canonical round trip")
	}
	if decoded.state.PaillierPrivateKey == nil {
		t.Fatal("decoded key share lost typed Paillier private key")
	}
	if decoded.state.PaillierProofSessionID != shares[1].state.PaillierProofSessionID {
		t.Fatal("Paillier proof session ID mismatch after canonical round trip")
	}
	for i, id := range decodedMeta.Parties {
		verificationShare, ok := decoded.VerificationShare(id)
		if !ok {
			t.Fatalf("missing verification share for party %d", id)
		}
		paillierShare, ok := decoded.PaillierPublicShare(id)
		if !ok {
			t.Fatalf("missing Paillier public share for party %d", id)
		}
		ringPedersenShare, ok := decoded.RingPedersenPublicShare(id)
		if !ok {
			t.Fatalf("missing Ring-Pedersen public share for party %d", id)
		}
		confirmation, ok := decoded.KeygenConfirmation(id)
		if !ok {
			t.Fatalf("missing keygen confirmation for party %d", id)
		}
		if verificationShare.Party != id ||
			paillierShare.Party != id ||
			ringPedersenShare.Party != id ||
			confirmation.Sender != id {
			t.Fatalf("party getter does not match Parties at index %d", i)
		}
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := tss.DecodeBinary[KeyShare](trailing); err == nil {
		t.Fatal("key share with trailing bytes accepted")
	}
}

func TestCGGMP21KeyShareStateCodecAppliesCallerLimits(t *testing.T) {
	t.Parallel()

	share := CachedKeygenShares(t, 2, 3)[1]
	limits := testLimits()
	raw, err := share.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}

	smallFields := limits.fieldLimits()
	smallFields["point"] = len(share.state.PublicKey) - 1
	if _, err := wire.Marshal(share.state, wire.WithFieldLimitsForMarshal(smallFields)); err == nil {
		t.Fatal("key share state marshal ignored caller field limits")
	}

	var decoded keyShareState
	if err := wire.Unmarshal(
		raw,
		&decoded,
		wire.WithFrameLimits(limits.frameLimits(len(raw)-1)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err == nil {
		t.Fatal("key share state unmarshal ignored caller frame limits")
	}
	if err := wire.Unmarshal(
		raw,
		&decoded,
		wire.WithFrameLimits(limits.frameLimits(len(raw))),
		wire.WithFieldLimits(smallFields),
	); err == nil {
		t.Fatal("key share state unmarshal ignored caller field limits")
	}

	missingFields := limits.fieldLimits()
	delete(missingFields, "point")
	if _, err := wire.Marshal(share.state, wire.WithFieldLimitsForMarshal(missingFields)); err == nil {
		t.Fatal("key share state marshal accepted missing field limit")
	}
}

func TestCGGMP21KeyShareRejectsNonCanonicalFields(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	unsorted := cloneKeyShareValue(shares[1])
	unsorted.state.Parties[0], unsorted.state.Parties[1] = unsorted.state.Parties[1], unsorted.state.Parties[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted party set encoded")
	}
	nonCanonicalPaillier := cloneKeyShareValue(shares[1])
	data := nonCanonicalPaillier.state.PartyData[nonCanonicalPaillier.state.Party]
	data.PaillierPublicKey.G = nil
	nonCanonicalPaillier.state.PartyData[nonCanonicalPaillier.state.Party] = data
	if _, err := nonCanonicalPaillier.MarshalBinary(); err == nil {
		t.Fatal("malformed Paillier public key encoded")
	}
}

func TestCGGMP21KeyShareRejectsMalformedKeygenConfirmations(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	malformed := cloneKeyShareValue(shares[1])
	data := malformed.state.PartyData[1]
	data.KeygenConfirmation.Sender = 2
	malformed.state.PartyData[1] = data
	if _, err := malformed.MarshalBinary(); err == nil {
		t.Fatal("key share accepted confirmation sender that did not match the party-data key")
	}
}

func TestCGGMP21KeyShareRejectsEmptyKeygenConfirmations(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	missing := cloneKeyShareValue(shares[1])
	data := missing.state.PartyData[1]
	data.KeygenConfirmation = nil
	missing.state.PartyData[1] = data
	if _, err := missing.MarshalBinary(); err == nil {
		t.Fatal("key share accepted missing keygen confirmation")
	}
}

func TestCGGMP21KeyShareRejectsIncompleteProductionMaterial(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)

	for _, tc := range []struct {
		name   string
		mutate func(*KeyShare)
	}{
		{name: "verification share", mutate: func(k *KeyShare) {
			data := k.state.PartyData[1]
			data.VerificationShare = nil
			k.state.PartyData[1] = data
		}},
		{name: "paillier public key", mutate: func(k *KeyShare) {
			data := k.state.PartyData[1]
			data.PaillierPublicKey = nil
			k.state.PartyData[1] = data
		}},
		{name: "paillier proof", mutate: func(k *KeyShare) {
			data := k.state.PartyData[1]
			data.PaillierProof = nil
			k.state.PartyData[1] = data
		}},
		{name: "Ring-Pedersen parameters", mutate: func(k *KeyShare) {
			data := k.state.PartyData[1]
			data.RingPedersenParams = nil
			k.state.PartyData[1] = data
		}},
		{name: "Ring-Pedersen proof", mutate: func(k *KeyShare) {
			data := k.state.PartyData[1]
			data.RingPedersenProof = nil
			k.state.PartyData[1] = data
		}},
		{name: "share proof", mutate: func(k *KeyShare) { k.state.ShareProof = nil }},
		{name: "keygen transcript hash", mutate: func(k *KeyShare) { k.state.KeygenTranscriptHash = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated := cloneKeyShareValue(shares[1])
			tc.mutate(mutated)
			raw, err := mutated.MarshalWireMessage(wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()))
			if err == nil {
				_, err = tss.DecodeBinary[KeyShare](raw)
			}
			if err == nil {
				t.Fatalf("key share missing %s decoded", tc.name)
			}
		})
	}
}

func TestCGGMP21KeyShareRejectsInvalidTypedWireFields(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	missingPrivate := cloneKeyShareValue(shares[1])
	missingPrivate.state.PaillierPrivateKey = nil
	if _, err := missingPrivate.MarshalWireMessage(wire.WithFieldLimitsForMarshal(testLimits().fieldLimits())); err == nil {
		t.Fatal("key share state codec accepted nil Paillier private key")
	}

	raw, err := shares[1].MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		tag   uint16
		value []byte
	}{
		{name: "empty Paillier private key", tag: 9, value: []byte{}},
		{name: "malformed Paillier private key", tag: 9, value: []byte{1}},
		{name: "short Paillier proof session ID", tag: 12, value: make([]byte, 31)},
		{name: "long Paillier proof session ID", tag: 12, value: make([]byte, 33)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated, err := testutil.RewriteWireField(raw, keyShareWireType, tc.tag, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tss.DecodeBinaryWithLimits[KeyShare](mutated, testLimits()); err == nil {
				t.Fatalf("key share accepted %s", tc.name)
			}
		})
	}
}

func TestCGGMP21KeyShareRejectsPartyDataKeySetMismatch(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*keyShareState)
	}{
		{name: "missing", mutate: func(s *keyShareState) { delete(s.PartyData, 3) }},
		{name: "extra", mutate: func(s *keyShareState) { s.PartyData[4] = s.PartyData[3] }},
		{name: "broadcast", mutate: func(s *keyShareState) { s.PartyData[tss.BroadcastPartyId] = s.PartyData[3] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated := cloneKeyShareValue(shares[1])
			tc.mutate(mutated.state)
			raw, err := wire.Marshal(mutated.state, wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()))
			if err != nil {
				return
			}
			if _, err := tss.DecodeBinary[KeyShare](raw); err == nil {
				t.Fatalf("key share accepted %s party data", tc.name)
			}
		})
	}
}

func TestCGGMP21KeyShareRejectsLocalPaillierKeyMismatch(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	mismatched := cloneKeyShareValue(shares[1])
	mismatched.state.PaillierPrivateKey = shares[2].state.PaillierPrivateKey.Clone()
	if err := mismatched.ValidateWithLimits(testLimits()); err == nil {
		t.Fatal("key share accepted local Paillier private key from another party")
	}
}

func TestCGGMP21KeyShareValidatesStoredPeerPaillierProofs(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)

	badModulusProof := cloneKeyShareValue(shares[1])
	modulusData := badModulusProof.state.PartyData[1]
	modulusData.PaillierProof = badModulusProof.state.PartyData[2].PaillierProof.Clone()
	badModulusProof.state.PartyData[1] = modulusData
	if err := badModulusProof.Validate(); err == nil {
		t.Fatal("key share accepted swapped peer Paillier modulus proof")
	}

	badRingPedersenProof := cloneKeyShareValue(shares[1])
	ringData := badRingPedersenProof.state.PartyData[1]
	ringData.RingPedersenProof = badRingPedersenProof.state.PartyData[2].RingPedersenProof.Clone()
	badRingPedersenProof.state.PartyData[1] = ringData
	if err := badRingPedersenProof.Validate(); err == nil {
		t.Fatal("key share accepted swapped peer Ring-Pedersen proof")
	}
}

func TestCGGMP21PresignCanonicalEncoding(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
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
	decoded, err := tss.DecodeBinary[Presign](raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustPresignMetadata(t, decoded).TranscriptHash, mustPresignMetadata(t, presigns[1]).TranscriptHash) {
		t.Fatal("presign transcript mismatch after round trip")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := tss.DecodeBinary[Presign](trailing); err == nil {
		t.Fatal("presign with trailing bytes accepted")
	}
}

func TestCGGMP21PresignRejectsUnsortedSigners(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	unsorted := clonePresignForTest(presigns[1])
	unsorted.state.Signers[0], unsorted.state.Signers[1] = unsorted.state.Signers[1], unsorted.state.Signers[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted signer set encoded")
	}
	if _, _, err := StartSignDigest(shares[1], unsorted, tss.SessionID{}, make([]byte, 32)); err == nil {
		t.Fatal("unsorted signer set entered signing")
	}
}

func TestCGGMP21KeyShareRejectsOverflowThreshold(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, overflow := range []uint32{math.MaxInt32 + 1, math.MaxUint32} {
		mutated, err := testutil.RewriteWireField(raw, keyShareWireType, 2, wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tss.DecodeBinary[KeyShare](mutated); err == nil {
			t.Fatalf("key share threshold %d accepted", overflow)
		}
	}
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
		return testutil.RewriteWireFieldByName(raw, presignRound1PayloadWireType, presignRound1Payload{}, "Gamma", payload.Gamma)
	}
	if !bytes.Equal(original.EncK, payload.EncK) {
		return testutil.RewriteWireFieldByName(raw, presignRound1PayloadWireType, presignRound1Payload{}, "EncK", payload.EncK)
	}
	return payload.MarshalBinaryWithLimits(testLimits())
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
		return testutil.RewriteWireFieldByName(raw, presignRound1ProofPayloadWireType, presignRound1ProofPayload{}, "PublicRound1Hash", payload.PublicRound1Hash)
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
	if !bytes.Equal(original.Delta.Ciphertext, payload.Delta.Ciphertext) {
		return testutil.RewriteNestedWireFieldByName(raw, presignRound2PayloadWireType, presignRound2Payload{}, "Delta", mtaResponseWireType, mta.ResponseMessage{}, "Ciphertext", payload.Delta.Ciphertext)
	}
	if !bytes.Equal(original.Sigma.Ciphertext, payload.Sigma.Ciphertext) {
		return testutil.RewriteNestedWireFieldByName(raw, presignRound2PayloadWireType, presignRound2Payload{}, "Sigma", mtaResponseWireType, mta.ResponseMessage{}, "Ciphertext", payload.Sigma.Ciphertext)
	}
	if !bytes.Equal(original.Round1Echo, payload.Round1Echo) {
		return testutil.RewriteWireFieldByName(raw, presignRound2PayloadWireType, presignRound2Payload{}, "Round1Echo", payload.Round1Echo)
	}
	return marshalPresignRound2Payload(payload)
}
