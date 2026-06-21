package paillier

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
)

func TestIntegerEncodingCanonical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		x    *big.Int
		want []byte
	}{
		{name: "nil as zero", x: nil, want: []byte{0x00}},
		{name: "zero", x: big.NewInt(0), want: []byte{0x00}},
		{name: "positive", x: big.NewInt(258), want: []byte{0x00, 0x01, 0x02}},
		{name: "negative", x: big.NewInt(-258), want: []byte{0x01, 0x01, 0x02}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EncodeSigned(tc.x)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("EncodeSigned() = %x, want %x", got, tc.want)
			}
			decoded, err := DecodeSigned(got)
			if err != nil {
				t.Fatal(err)
			}
			want := new(big.Int)
			if tc.x != nil {
				want.Set(tc.x)
			}
			if decoded.Cmp(want) != 0 {
				t.Fatalf("DecodeSigned() = %s, want %s", decoded, want)
			}
		})
	}

	t.Run("non-canonical signed", func(t *testing.T) {
		t.Parallel()
		for _, in := range [][]byte{
			nil,
			{},
			{0x02},
			{0x01},
			{0x01, 0x00},
			{0x00, 0x00},
			{0x00, 0x00, 0x01},
		} {
			t.Run(fmt.Sprintf("%x", in), func(t *testing.T) {
				t.Parallel()
				if _, err := DecodeSigned(in); err == nil {
					t.Fatalf("DecodeSigned(%x) accepted non-canonical input", in)
				}
			})
		}
	})

	t.Run("positive round-trip", func(t *testing.T) {
		t.Parallel()
		if got, err := DecodePositive([]byte{0x01, 0x02}); err != nil || got.Cmp(big.NewInt(258)) != 0 {
			t.Fatalf("DecodePositive() = %v, %v; want 258, nil", got, err)
		}
	})

	t.Run("non-canonical positive", func(t *testing.T) {
		t.Parallel()
		for _, in := range [][]byte{
			nil,
			{},
			{0x00},
			{0x00, 0x01},
		} {
			t.Run(fmt.Sprintf("%x", in), func(t *testing.T) {
				t.Parallel()
				if _, err := DecodePositive(in); err == nil {
					t.Fatalf("DecodePositive(%x) accepted non-canonical input", in)
				}
			})
		}
	})
}

func TestIntegerRangeChecks(t *testing.T) {
	t.Parallel()
	if !InSignedPowerOfTwo(big.NewInt(-8), 3) || !InSignedPowerOfTwo(big.NewInt(8), 3) {
		t.Fatal("signed power-of-two range rejected inclusive endpoint")
	}
	if InSignedPowerOfTwo(big.NewInt(-9), 3) || InSignedPowerOfTwo(big.NewInt(9), 3) {
		t.Fatal("signed power-of-two range accepted out-of-range value")
	}
	if !InUnsignedPowerOfTwo(big.NewInt(0), 3) || !InUnsignedPowerOfTwo(big.NewInt(7), 3) {
		t.Fatal("unsigned power-of-two range rejected valid value")
	}
	if InUnsignedPowerOfTwo(big.NewInt(-1), 3) || InUnsignedPowerOfTwo(big.NewInt(8), 3) {
		t.Fatal("unsigned power-of-two range accepted invalid value")
	}
	if BoundSignedPowerOfTwo(5).Cmp(big.NewInt(32)) != 0 || BoundUnsignedPowerOfTwo(5).Cmp(big.NewInt(32)) != 0 {
		t.Fatal("power-of-two bound helper returned wrong bound")
	}
	if !inMultRange(big.NewInt(45), big.NewInt(15), 2) || inMultRange(big.NewInt(61), big.NewInt(15), 2) {
		t.Fatal("multi-range helper returned wrong result")
	}
}

func TestGroupMembershipChecks(t *testing.T) {
	t.Parallel()
	n := big.NewInt(15)
	if !IsZNStar(big.NewInt(2), n) {
		t.Fatal("valid Z*_N element rejected")
	}
	for _, x := range []*big.Int{nil, big.NewInt(0), big.NewInt(3), big.NewInt(15), big.NewInt(16)} {
		if IsZNStar(x, n) {
			t.Fatalf("invalid Z*_N element accepted: %v", x)
		}
	}
	if !IsZN2Star(big.NewInt(2), n) {
		t.Fatal("valid Z*_{N^2} element rejected")
	}
	for _, x := range []*big.Int{nil, big.NewInt(0), big.NewInt(3), big.NewInt(225), big.NewInt(226)} {
		if IsZN2Star(x, n) {
			t.Fatalf("invalid Z*_{N^2} element accepted: %v", x)
		}
	}
	if _, err := RequireZNStar(big.NewInt(3), n); err == nil {
		t.Fatal("RequireZNStar accepted non-unit")
	}
	if _, err := RequireZN2Star(big.NewInt(225), n); err == nil {
		t.Fatal("RequireZN2Star accepted out-of-range value")
	}
}

func TestRingPedersenParamsValidation(t *testing.T) {
	t.Parallel()

	valid := seedRingPedersenParams()
	if err := ValidateRingPedersenParams(valid); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalRingPedersenParams(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := tss.DecodeBinary[RingPedersenParams](raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.N.Cmp(valid.N) != 0 || decoded.S.Cmp(valid.S) != 0 || decoded.T.Cmp(valid.T) != 0 {
		t.Fatal("Ring-Pedersen params did not round-trip")
	}

	tests := []struct {
		name   string
		params *RingPedersenParams
	}{
		{name: "nil", params: nil},
		{name: "even modulus", params: &RingPedersenParams{N: big.NewInt(14), S: big.NewInt(3), T: big.NewInt(5)}},
		{name: "prime modulus", params: &RingPedersenParams{N: big.NewInt(17), S: big.NewInt(2), T: big.NewInt(3)}},
		{name: "s one", params: &RingPedersenParams{N: big.NewInt(15), S: big.NewInt(1), T: big.NewInt(4)}},
		{name: "t non-unit", params: &RingPedersenParams{N: big.NewInt(15), S: big.NewInt(2), T: big.NewInt(3)}},
		{name: "s out of range", params: &RingPedersenParams{N: big.NewInt(15), S: big.NewInt(15), T: big.NewInt(4)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateRingPedersenParams(tc.params); err == nil {
				t.Fatal("invalid Ring-Pedersen params validated")
			}
			if _, err := MarshalRingPedersenParams(tc.params); err == nil {
				t.Fatal("invalid Ring-Pedersen params marshaled")
			}
		})
	}
}

func TestSecurityParamsValidationAndBindingValues(t *testing.T) {
	t.Parallel()

	valid := SecurityParams{Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 512}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if valid.EncRange() != 384 || valid.AffGRange() != 640 {
		t.Fatal("security parameter range helpers returned wrong values")
	}
	if err := valid.CheckPaillierModulus(&pai.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 510)}); err == nil {
		t.Fatal("short Paillier modulus accepted")
	}
	if err := valid.CheckPaillierModulus(&pai.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 512)}); err != nil {
		t.Fatal(err)
	}

	for _, params := range []SecurityParams{
		{EllPrime: 1, Epsilon: 1, ChallengeBits: 1},
		{Ell: 1, Epsilon: 1, ChallengeBits: 1},
		{Ell: 1, EllPrime: 1, ChallengeBits: 1},
		{Ell: 1, EllPrime: 1, Epsilon: 1},
		{Ell: 1, EllPrime: 1, Epsilon: 1, ChallengeBits: 257},
	} {
		if err := params.Validate(); err == nil {
			t.Fatalf("invalid SecurityParams validated: %+v", params)
		}
	}
}

func TestTranscriptDomainSeparation(t *testing.T) {
	t.Parallel()

	build := func(domain, label string, payload []byte) []byte {
		transcript := NewTranscript(domain)
		transcript.AppendBytes(label, payload)
		if err := transcript.AppendBigInt("n", big.NewInt(42)); err != nil {
			t.Fatal(err)
		}
		if err := transcript.AppendSigned("z", big.NewInt(-7)); err != nil {
			t.Fatal(err)
		}
		transcript.AppendUint16("u16", 16)
		transcript.AppendUint32("u32", 32)
		// AppendPoint with the generator is infallible.
		_ = transcript.AppendPoint("G", secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
		return transcript.Sum()
	}
	base := build("domain", "field", []byte("payload"))
	for _, changed := range [][]byte{
		build("other", "field", []byte("payload")),
		build("domain", "other", []byte("payload")),
		build("domain", "field", []byte("other")),
	} {
		if bytes.Equal(base, changed) {
			t.Fatal("transcript failed to bind domain, label, or payload")
		}
	}

	t1 := NewTranscript("domain")
	t1.AppendBytes("a", []byte("1"))
	t1.AppendBytes("b", []byte("2"))
	t2 := NewTranscript("domain")
	t2.AppendBytes("b", []byte("2"))
	t2.AppendBytes("a", []byte("1"))
	if bytes.Equal(t1.Sum(), t2.Sum()) {
		t.Fatal("transcript failed to bind field order")
	}
	if err := t1.AppendPointBytes("bad", []byte{0x02}); err == nil {
		t.Fatal("AppendPointBytes accepted malformed point")
	}
	if err := t1.AppendBigInt("nil_bigint", nil); err == nil {
		t.Fatal("AppendBigInt accepted nil integer")
	}
	if err := t1.AppendSigned("nil_signed", nil); err == nil {
		t.Fatal("AppendSigned accepted nil integer")
	}
	challenge, err := t1.ChallengeSigned(128)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Sign() <= 0 || !InUnsignedPowerOfTwo(challenge, 128) {
		t.Fatal("challenge outside requested bit range")
	}
	for _, bits := range []uint32{0, 257} {
		if _, err := t1.ChallengeSigned(bits); err == nil {
			t.Fatalf("ChallengeSigned accepted invalid bit length %d", bits)
		}
	}
}
