package paillier

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pubRaw2, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubRaw, pubRaw2) {
		t.Fatal("public key encoding is not deterministic")
	}
	pub, err := UnmarshalPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	if pub.N.Cmp(sk.N) != 0 || pub.G.Cmp(sk.G) != 0 {
		t.Fatal("public key mismatch after round trip")
	}
	privRaw, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	privRaw2, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privRaw, privRaw2) {
		t.Fatal("private key encoding is not deterministic")
	}
	priv, err := UnmarshalPrivateKey(privRaw)
	if err != nil {
		t.Fatal(err)
	}
	if priv.N.Cmp(sk.N) != 0 || !priv.Lambda.Equal(sk.Lambda) || !priv.Mu.Equal(sk.Mu) {
		t.Fatal("private key mismatch after round trip")
	}
}

func TestRejectsNonCanonicalPublicKey(t *testing.T) {
	t.Parallel()

	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := append([]byte(" "), raw...)
	if _, err := UnmarshalPublicKey(nonCanonical); err == nil {
		t.Fatal("expected non-canonical public key rejection")
	}
	if _, err := UnmarshalPublicKey([]byte(`{"n":"01","g":"02"}`)); err == nil {
		t.Fatal("expected JSON public key rejection")
	}
	if _, err := UnmarshalPrivateKey([]byte(`{"public_key":{"n":"01","g":"02"}}`)); err == nil {
		t.Fatal("expected JSON private key rejection")
	}
	withLeadingZero, err := rewritePaillierField(raw, publicKeyWireType, publicKeyFieldN, append([]byte{0}, sk.N.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPublicKey(withLeadingZero); err == nil {
		t.Fatal("expected non-minimal public modulus rejection")
	}
	privRaw, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	badPrivate, err := rewritePaillierField(privRaw, privateKeyWireType, privateKeyFieldP, append([]byte{0}, sk.P.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPrivateKey(badPrivate); err == nil {
		t.Fatal("expected non-minimal private factor rejection")
	}
	wrongType, err := wire.MarshalFields(paillierWireVersion, "wrong.paillier.public-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPublicKey(wrongType); err == nil {
		t.Fatal("expected wrong public key type rejection")
	}
}

func FuzzPublicKeyUnmarshal(f *testing.F) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"n":"01","g":"02"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := UnmarshalPublicKey(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, pk, (*PublicKey).MarshalBinary, UnmarshalPublicKey)
	})
}

func FuzzPrivateKeyUnmarshal(f *testing.F) {
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := sk.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"public_key":{"n":"01","g":"02"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		sk, err := UnmarshalPrivateKey(data)
		if err != nil {
			return
		}
		testutil.AssertDeterministicRoundTrip(t, sk, (*PrivateKey).MarshalBinary, UnmarshalPrivateKey)
	})
}

func rewritePaillierField(raw []byte, typeID string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, typeID)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = make([]byte, len(value))
			copy(fields[i].Value, value)
			return wire.MarshalFields(version, typeID, fields)
		}
	}
	return nil, fmt.Errorf("missing Paillier field %d", tag)
}

func TestValidateBitsPassesAtOrAboveMin(t *testing.T) {
	t.Parallel()
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := sk.ValidateBits(512); err != nil {
		t.Fatalf("512-bit modulus failed at min=512: %v", err)
	}
	if err := sk.ValidateBits(256); err != nil {
		t.Fatalf("512-bit modulus failed at min=256: %v", err)
	}
	if err := sk.ValidateBits(0); err != nil {
		t.Fatalf("512-bit modulus failed at min=0: %v", err)
	}
}

func TestValidateBitsRejectsBelowMin(t *testing.T) {
	t.Parallel()
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := sk.ValidateBits(1024); err == nil {
		t.Fatal("512-bit modulus accepted with min=1024")
	}
	if err := sk.ValidateBits(768); err == nil {
		t.Fatal("512-bit modulus accepted with min=768")
	}
}

func TestValidateBitsRejectsInvalidPublicKey(t *testing.T) {
	t.Parallel()
	// Zero-valued N.
	pk := PublicKey{N: big.NewInt(0)}
	if err := pk.ValidateBits(0); err == nil {
		t.Fatal("zero-modulus public key accepted by ValidateBits")
	}
	// Even N.
	pk = PublicKey{N: big.NewInt(100)}
	if err := pk.ValidateBits(0); err == nil {
		t.Fatal("even-modulus accepted by ValidateBits")
	}
}

func TestAfterUnmarshalWireReconstructsNSquared(t *testing.T) {
	t.Parallel()
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey
	if pk.NSquared == nil {
		t.Fatal("NSquared not populated after keygen")
	}
	expected := new(big.Int).Mul(pk.N, pk.N)
	if pk.NSquared.Cmp(expected) != 0 {
		t.Fatal("NSquared != N^2 after keygen")
	}

	// Simulate AfterUnmarshalWire: nil out NSquared, call AfterUnmarshalWire, verify.
	pk2 := PublicKey{N: pk.N, G: pk.G}
	if pk2.NSquared != nil {
		t.Fatal("NSquared should be nil before AfterUnmarshalWire")
	}
	if err := pk2.AfterUnmarshalWire(); err != nil {
		t.Fatal(err)
	}
	if pk2.NSquared.Cmp(expected) != 0 {
		t.Fatal("AfterUnmarshalWire did not reconstruct NSquared correctly")
	}
}

func TestAfterUnmarshalWireNilN(t *testing.T) {
	t.Parallel()
	pk := PublicKey{}
	if err := pk.AfterUnmarshalWire(); err != nil {
		t.Fatal("AfterUnmarshalWire with nil N should succeed (no-op)")
	}
}

func TestPaillierMarshalJSONRejects(t *testing.T) {
	t.Parallel()
	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sk.MarshalJSON(); err == nil {
		t.Fatal("MarshalJSON should reject private key")
	}
}
