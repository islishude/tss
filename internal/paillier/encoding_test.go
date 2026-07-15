package paillier

import (
	"bytes"
	"context"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

type privateKeyCustomFieldMessage struct {
	PrivateKey *PrivateKey `wire:"1,custom,max_bytes=paillier_private_key"`
}

func (privateKeyCustomFieldMessage) WireType() string {
	return "test.paillier.private-key-custom-field"
}

func (privateKeyCustomFieldMessage) WireVersion() uint16 {
	return 1
}

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
	pub, err := tss.DecodeBinary[PublicKey](pubRaw)
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
	priv, err := tss.DecodeBinary[PrivateKey](privRaw)
	if err != nil {
		t.Fatal(err)
	}
	if priv.N.Cmp(sk.N) != 0 || !priv.Lambda.Equal(sk.Lambda) || !priv.Mu.Equal(sk.Mu) {
		t.Fatal("private key mismatch after round trip")
	}
}

func TestPrivateKeyCustomWireValueRoundTrip(t *testing.T) {
	t.Parallel()

	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	want, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	custom, err := sk.MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(custom, want) {
		t.Fatal("custom private-key field encoding differs from MarshalBinary")
	}

	limits := wire.FieldLimits{"paillier_private_key": len(want)}
	raw, err := wire.Marshal(
		privateKeyCustomFieldMessage{PrivateKey: sk},
		wire.WithFieldLimitsForMarshal(limits),
	)
	if err != nil {
		t.Fatal(err)
	}
	var decoded privateKeyCustomFieldMessage
	if err := wire.Unmarshal(raw, &decoded, wire.WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}
	if decoded.PrivateKey == nil {
		t.Fatal("custom private-key field was not allocated")
	}
	if decoded.PrivateKey.N.Cmp(sk.N) != 0 ||
		!decoded.PrivateKey.Lambda.Equal(sk.Lambda) ||
		!decoded.PrivateKey.Mu.Equal(sk.Mu) ||
		!decoded.PrivateKey.P.Equal(sk.P) ||
		!decoded.PrivateKey.Q.Equal(sk.Q) {
		t.Fatal("custom private-key field mismatch after round trip")
	}
}

func TestPrivateKeyCustomWireValueRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	var nilKey *PrivateKey
	if _, err := nilKey.MarshalWireValue(); err == nil {
		t.Fatal("nil private key custom marshal succeeded")
	}
	if err := nilKey.UnmarshalWireValue([]byte{1}); err == nil {
		t.Fatal("nil private key custom unmarshal succeeded")
	}

	var decoded PrivateKey
	if err := decoded.UnmarshalWireValue([]byte(`{"private_key":true}`)); err == nil {
		t.Fatal("custom private-key field accepted non-wire input")
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
	nonCanonical := slices.Concat([]byte(" "), raw)
	if _, err := tss.DecodeBinary[PublicKey](nonCanonical); err == nil {
		t.Fatal("expected non-canonical public key rejection")
	}
	if _, err := tss.DecodeBinary[PublicKey]([]byte(`{"n":"01","g":"02"}`)); err == nil {
		t.Fatal("expected JSON public key rejection")
	}
	if _, err := tss.DecodeBinary[PrivateKey]([]byte(`{"public_key":{"n":"01","g":"02"}}`)); err == nil {
		t.Fatal("expected JSON private key rejection")
	}
	withLeadingZero, err := testutil.RewriteWireFieldByName(raw, publicKeyWireType, PublicKey{}, "N", slices.Concat([]byte{0}, sk.N.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[PublicKey](withLeadingZero); err == nil {
		t.Fatal("expected non-minimal public modulus rejection")
	}
	privRaw, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pBytes := sk.P.FixedBytes()
	badPrivate, err := testutil.RewriteWireFieldByName(
		privRaw,
		privateKeyType,
		PrivateKey{},
		"P",
		slices.Concat([]byte{0}, pBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[PrivateKey](badPrivate); err == nil {
		t.Fatal("expected wrong-width private factor rejection")
	}
	wrongType, err := wire.MarshalFields(publicKeyWireVersion, "wrong.paillier.public-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[PublicKey](wrongType); err == nil {
		t.Fatal("expected wrong public key type rejection")
	}
}

func TestPrivateKeyWireRejectsRetiredFlatLayout(t *testing.T) {
	t.Parallel()

	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := wire.MarshalFields(privateKeyVersion, privateKeyType, []wire.Field{
		{Tag: 1, Value: sk.N.Bytes()},
		{Tag: 2, Value: sk.G.Bytes()},
		{Tag: 3, Value: sk.Lambda.FixedBytes()},
		{Tag: 4, Value: sk.Mu.FixedBytes()},
		{Tag: 5, Value: sk.P.FixedBytes()},
		{Tag: 6, Value: sk.Q.FixedBytes()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[PrivateKey](retired); err == nil {
		t.Fatal("retired flat private-key layout was accepted")
	}
}

func TestPrivateKeyWireDecodeIsFailAtomic(t *testing.T) {
	t.Parallel()

	original, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := GenerateKeyForTest(context.Background(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := replacement.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	bad, err := testutil.RewriteWireFieldByName(
		raw,
		privateKeyType,
		PrivateKey{},
		"Q",
		[]byte{1},
	)
	if err != nil {
		t.Fatal(err)
	}

	before := original.Clone()
	if err := original.UnmarshalBinary(bad); err == nil {
		t.Fatal("invalid private key was accepted")
	}
	if original.N.Cmp(before.N) != 0 ||
		!original.Lambda.Equal(before.Lambda) ||
		!original.Mu.Equal(before.Mu) ||
		!original.P.Equal(before.P) ||
		!original.Q.Equal(before.Q) {
		t.Fatal("failed private-key decode mutated receiver")
	}
}

func TestStandaloneKeyDecodersEnforceObjectByteCaps(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		maxBytes int
		decode   func([]byte) error
	}{
		"public": {
			maxBytes: tss.DefaultMaxPaillierPublicKeyBytes,
			decode: func(in []byte) error {
				var key PublicKey
				return key.UnmarshalBinary(in)
			},
		},
		"private": {
			maxBytes: tss.DefaultMaxPaillierPrivateKeyBytes,
			decode: func(in []byte) error {
				var key PrivateKey
				return key.UnmarshalBinary(in)
			},
		},
	} {
		err := tc.decode(make([]byte, tc.maxBytes+1))
		if err == nil || !strings.Contains(err.Error(), "wire input too large") {
			t.Errorf("%s key oversized decode got %v, want wire frame rejection", name, err)
		}
	}
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
