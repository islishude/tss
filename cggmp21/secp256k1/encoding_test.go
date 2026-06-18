//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"math"
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
	decoded, err := UnmarshalKeyShare(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PublicKeyBytes(), shares[1].PublicKeyBytes()) {
		t.Fatal("public key mismatch after canonical round trip")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := UnmarshalKeyShare(trailing); err == nil {
		t.Fatal("key share with trailing bytes accepted")
	}
}

func TestCGGMP21KeyShareRejectsNonCanonicalFields(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	unsorted := cloneKeyShareValue(shares[1])
	unsorted.state.parties[0], unsorted.state.parties[1] = unsorted.state.parties[1], unsorted.state.parties[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted party set encoded")
	}
	nonCanonicalPaillier := cloneKeyShareValue(shares[1])
	nonCanonicalPaillier.state.paillierPublicKey = append(nonCanonicalPaillier.state.paillierPublicKey, ' ')
	if _, err := nonCanonicalPaillier.MarshalBinary(); err == nil {
		t.Fatal("non-canonical Paillier public key encoded")
	}
}

func TestCGGMP21KeyShareRejectsMalformedKeygenConfirmations(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := testutil.RewriteWireFieldByName(raw, keyShareWireType, keyShareWire{}, "KeygenConfirmations", []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(mutated); err == nil {
		t.Fatal("key share accepted malformed keygen confirmations")
	}
}

func TestCGGMP21KeyShareRejectsEmptyKeygenConfirmations(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := testutil.RewriteWireFieldByName(raw, keyShareWireType, keyShareWire{}, "KeygenConfirmations", wire.EncodeBytesList(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(mutated); err == nil {
		t.Fatal("key share accepted empty keygen confirmations")
	}
}

func TestCGGMP21KeyShareRejectsIncompleteProductionMaterial(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		field string
		value []byte
	}{
		{name: "paillier public key", field: "PaillierPublicKey", value: []byte{}},
		{name: "paillier private key", field: "PaillierPrivateKey", value: []byte{}},
		{name: "paillier proof", field: "PaillierProof", value: []byte{}},
		{name: "Ring-Pedersen parameters", field: "RingPedersenParams", value: []byte{}},
		{name: "Ring-Pedersen proof", field: "RingPedersenProof", value: []byte{}},
		{name: "Ring-Pedersen public parameters", field: "RingPedersenPublic", value: wire.Uint32(0)},
		{name: "paillier public key set", field: "PaillierPublicKeys", value: wire.Uint32(0)},
		{name: "share proof", field: "ShareProof", value: []byte{}},
		{name: "keygen transcript hash", field: "KeygenTranscriptHash", value: []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated, err := testutil.RewriteWireFieldByName(raw, keyShareWireType, keyShareWire{}, tc.field, tc.value)
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
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)

	badModulusProof := cloneKeyShareValue(shares[1])
	badModulusProof.state.paillierPublicKeys[0].Proof = append([]byte(nil), badModulusProof.state.paillierPublicKeys[1].Proof...)
	if err := badModulusProof.Validate(); err == nil {
		t.Fatal("key share accepted swapped peer Paillier modulus proof")
	}

	badRingPedersenProof := cloneKeyShareValue(shares[1])
	badRingPedersenProof.state.ringPedersenPublic[0].Proof = append([]byte(nil), badRingPedersenProof.state.ringPedersenPublic[1].Proof...)
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
	decoded, err := UnmarshalPresign(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.TranscriptHashBytes(), presigns[1].TranscriptHashBytes()) {
		t.Fatal("presign transcript mismatch after round trip")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := UnmarshalPresign(trailing); err == nil {
		t.Fatal("presign with trailing bytes accepted")
	}
}

func TestCGGMP21PresignRejectsUnsortedSigners(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	unsorted := clonePresignForTest(presigns[1])
	unsorted.state.signers[0], unsorted.state.signers[1] = unsorted.state.signers[1], unsorted.state.signers[0]
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
		mutated, err := testutil.RewriteWireFieldByName(raw, keyShareWireType, keyShareWire{}, "Threshold", wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalKeyShare(mutated); err == nil {
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
	if !bytes.Equal(original.PaillierPublicKey, payload.PaillierPublicKey) {
		return testutil.RewriteWireFieldByName(raw, presignRound1PayloadWireType, presignRound1Payload{}, "PaillierPublicKey", payload.PaillierPublicKey)
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
		return testutil.RewriteWireFieldByName(raw, presignRound1ProofPayloadWireType, presignRound1ProofPayload{}, "PublicRound1Hash", payload.PublicRound1Hash)
	}
	if !bytes.Equal(original.EncKProof, payload.EncKProof) {
		return testutil.RewriteWireFieldByName(raw, presignRound1ProofPayloadWireType, presignRound1ProofPayload{}, "EncKProof", payload.EncKProof)
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
	if !bytes.Equal(original.Delta.Proof, payload.Delta.Proof) {
		return testutil.RewriteNestedWireFieldByName(raw, presignRound2PayloadWireType, presignRound2Payload{}, "Delta", mtaResponseWireType, mta.ResponseMessage{}, "Proof", payload.Delta.Proof)
	}
	if !bytes.Equal(original.Sigma.Ciphertext, payload.Sigma.Ciphertext) {
		return testutil.RewriteNestedWireFieldByName(raw, presignRound2PayloadWireType, presignRound2Payload{}, "Sigma", mtaResponseWireType, mta.ResponseMessage{}, "Ciphertext", payload.Sigma.Ciphertext)
	}
	if !bytes.Equal(original.Sigma.Proof, payload.Sigma.Proof) {
		return testutil.RewriteNestedWireFieldByName(raw, presignRound2PayloadWireType, presignRound2Payload{}, "Sigma", mtaResponseWireType, mta.ResponseMessage{}, "Proof", payload.Sigma.Proof)
	}
	if !bytes.Equal(original.Round1Echo, payload.Round1Echo) {
		return testutil.RewriteWireFieldByName(raw, presignRound2PayloadWireType, presignRound2Payload{}, "Round1Echo", payload.Round1Echo)
	}
	return marshalPresignRound2Payload(payload)
}
