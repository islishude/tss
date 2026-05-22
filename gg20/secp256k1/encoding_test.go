package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestGG20KeyShareCanonicalEncoding(t *testing.T) {
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

func TestGG20KeyShareRejectsNonCanonicalFields(t *testing.T) {
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

func TestGG20OldStyleKeyShareCannotPresign(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	old := cloneKeyShare(shares[1])
	old.PaillierPublicKey = nil
	old.PaillierPrivateKey = nil
	old.PaillierProof = nil
	old.PaillierPublicKeys = nil
	old.ShareProof = nil
	old.KeygenTranscriptHash = nil
	raw, err := old.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartPresign(decoded, sessionID, []tss.PartyID{1, 2}); err == nil {
		t.Fatal("old-style key share entered presign")
	}
}

func TestGG20PresignCanonicalEncoding(t *testing.T) {
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

func TestGG20PresignRejectsUnsortedSigners(t *testing.T) {
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

func FuzzGG20KeyShareUnmarshal(f *testing.F) {
	share := minimalGG20KeyShare(f)
	raw, err := share.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalKeyShare(data)
	})
}

func FuzzGG20PresignUnmarshal(f *testing.F) {
	presign := minimalGG20Presign(f)
	raw, err := presign.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalPresign(data)
	})
}

func minimalGG20KeyShare(tb testing.TB) *KeyShare {
	tb.Helper()
	secret := big.NewInt(1)
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(secret))
	if err != nil {
		tb.Fatal(err)
	}
	return &KeyShare{
		Version:            tss.Version,
		Party:              1,
		Threshold:          1,
		Parties:            []tss.PartyID{1},
		PublicKey:          publicKey,
		Secret:             scalarBytes(secret),
		GroupCommitments:   [][]byte{publicKey},
		VerificationShares: []VerificationShare{{Party: 1, PublicKey: publicKey}},
		SecurityNotice:     ExperimentalSecurityNotice,
	}
}

func minimalGG20Presign(tb testing.TB) *Presign {
	tb.Helper()
	one := big.NewInt(1)
	RPoint := secp.ScalarBaseMult(one)
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		tb.Fatal(err)
	}
	littleR := new(big.Int).Mod(RPoint.X, secp.Order())
	transcript := sha256.Sum256([]byte("minimal presign"))
	return &Presign{
		Version:        tss.Version,
		Party:          1,
		Threshold:      1,
		Signers:        []tss.PartyID{1},
		R:              R,
		LittleR:        scalarBytes(littleR),
		KShare:         scalarBytes(one),
		SigmaShare:     scalarBytes(one),
		Delta:          scalarBytes(one),
		TranscriptHash: transcript[:],
		SecurityNotice: ExperimentalSecurityNotice,
	}
}

func cloneKeyShare(in *KeyShare) *KeyShare {
	if in == nil {
		return nil
	}
	out := *in
	out.Parties = append([]tss.PartyID(nil), in.Parties...)
	out.PublicKey = append([]byte(nil), in.PublicKey...)
	out.Secret = append([]byte(nil), in.Secret...)
	out.GroupCommitments = cloneByteSlices(in.GroupCommitments)
	out.VerificationShares = append([]VerificationShare(nil), in.VerificationShares...)
	for i := range out.VerificationShares {
		out.VerificationShares[i].PublicKey = append([]byte(nil), in.VerificationShares[i].PublicKey...)
	}
	out.PaillierPublicKey = append([]byte(nil), in.PaillierPublicKey...)
	out.PaillierPrivateKey = append([]byte(nil), in.PaillierPrivateKey...)
	out.PaillierProof = append([]byte(nil), in.PaillierProof...)
	out.PaillierPublicKeys = append([]PaillierPublicShare(nil), in.PaillierPublicKeys...)
	for i := range out.PaillierPublicKeys {
		out.PaillierPublicKeys[i].PublicKey = append([]byte(nil), in.PaillierPublicKeys[i].PublicKey...)
		out.PaillierPublicKeys[i].Proof = append([]byte(nil), in.PaillierPublicKeys[i].Proof...)
	}
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
