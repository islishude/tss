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
		{name: "paillier public key set", tag: keyShareFieldPaillierPublicKeys, value: encodeUint32(0)},
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
		_, _ = UnmarshalKeyShare(data)
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
		_, _ = UnmarshalPresign(data)
	})
}

func minimalCGGMP21Presign(tb testing.TB) *Presign {
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
		ChiShare:       scalarBytes(one),
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
	out.ChainCode = append([]byte(nil), in.ChainCode...)
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

func rewriteKeyShareField(raw []byte, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.Unmarshal(raw, keyShareWireType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = make([]byte, len(value))
			copy(fields[i].Value, value)
			return wire.Marshal(version, keyShareWireType, fields)
		}
	}
	return nil, fmt.Errorf("missing key share field %d", tag)
}
