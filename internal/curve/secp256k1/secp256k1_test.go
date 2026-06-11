package secp256k1

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/testutil"
)

func TestBasePointEncoding(t *testing.T) {
	t.Parallel()

	enc, err := PointBytes(G)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PointFromBytes(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(got, G) {
		t.Fatal("base point round trip mismatch")
	}
}

func TestECDSASignVerify(t *testing.T) {
	t.Parallel()

	secret := deterministicScalar(t, 1)
	pub := ScalarBaseMult(secret)
	digest := sha256.Sum256([]byte("test"))
	r, s, err := SignECDSA(testutil.DeterministicReader(2), digest[:], secret, true)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyECDSA(pub, digest[:], r, s) {
		t.Fatal("signature did not verify")
	}
}

func TestFiatScalarArithmeticMatchesBigInt(t *testing.T) {
	t.Parallel()

	a := ScalarFromBigInt(big.NewInt(7))
	b := ScalarFromBigInt(big.NewInt(11))
	got := ScalarMul(ScalarAdd(a, b), b).BigInt()
	want := new(big.Int).Mul(big.NewInt(18), big.NewInt(11))
	want.Mod(want, Order())
	if got.Cmp(want) != 0 {
		t.Fatalf("fiat scalar arithmetic mismatch: got %s want %s", got, want)
	}
	inv, err := ScalarInvert(b)
	if err != nil {
		t.Fatal(err)
	}
	if ScalarMul(b, inv).BigInt().Cmp(big.NewInt(1)) != 0 {
		t.Fatal("fiat scalar inversion failed")
	}
}

func TestScalarMultCorrectness(t *testing.T) {
	t.Parallel()

	// 0 * G = infinity
	if p := ScalarMult(G, ScalarZero()); p.Inf == 0 {
		t.Fatal("0*G should be infinity")
	}

	// 1 * G = G
	one := ScalarOne()
	if p := ScalarMult(G, one); !Equal(p, G) {
		t.Fatal("1*G should equal G")
	}

	// 2 * G = G + G = Double(G)
	two := ScalarAdd(ScalarOne(), ScalarOne())
	twoGsm := ScalarMult(G, two)
	twoGadd := Add(G, G)
	twoGdbl := Double(G)
	if !Equal(twoGsm, twoGadd) {
		t.Fatalf("ScalarMult(G,2) != Add(G,G): Sm=(%x,%x,%d) Add=(%x,%x,%d)",
			twoGsm.X.Bytes(), twoGsm.Y.Bytes(), twoGsm.Inf,
			twoGadd.X.Bytes(), twoGadd.Y.Bytes(), twoGadd.Inf)
	}
	if !Equal(twoGsm, twoGdbl) {
		t.Fatal("ScalarMult(G,2) != Double(G)")
	}

	// 3 * G = 2*G + G
	three := ScalarAdd(two, ScalarOne())
	threeGsm := ScalarMult(G, three)
	threeGadd := Add(twoGdbl, G)
	if !Equal(threeGsm, threeGadd) {
		t.Fatalf("ScalarMult(G,3) != 2*G + G")
	}

	// Edge cases: infinity
	inf := NewInfinity()
	if d := Double(inf); d.Inf == 0 {
		t.Fatal("Double(infinity) should be infinity")
	}
	if a := Add(inf, G); !Equal(a, G) {
		t.Fatal("Add(infinity, G) should be G")
	}
	if a := Add(G, inf); !Equal(a, G) {
		t.Fatal("Add(G, infinity) should be G")
	}

	// G + (-G) = infinity
	negG := &Point{X: G.X, Y: FieldNeg(G.Y)}
	if sum := Add(G, negG); sum.Inf == 0 {
		t.Fatalf("G + (-G) should be infinity, got Inf=%d", sum.Inf)
	}

	// (N-1) * G = -G
	order := Order()
	nMinus1Big := new(big.Int).Sub(order, big.NewInt(1))
	nMinus1 := ScalarFromBigInt(nMinus1Big)
	nMinus1G := ScalarMult(G, nMinus1)
	if !Equal(nMinus1G, negG) {
		t.Fatalf("(N-1)*G should equal -G: got Inf=%d X=%x Y=%x, want Inf=%d X=%x Y=%x",
			nMinus1G.Inf, nMinus1G.X.Bytes(), nMinus1G.Y.Bytes(),
			negG.Inf, negG.X.Bytes(), negG.Y.Bytes())
	}

	// Reference comparison: new constant-time ScalarMult matches branchy version.
	referenceScalarMult := func(p *Point, k Scalar) *Point {
		if k.IsZero() || p == nil || p.Inf != 0 {
			return NewInfinity()
		}
		kB := k.Bytes()
		acc := NewInfinity()
		base := Clone(p)
		for byteIdx := range 32 {
			b := kB[byteIdx]
			for bit := 7; bit >= 0; bit-- {
				acc = Double(acc)
				if b&(1<<bit) != 0 {
					acc = Add(acc, base)
				}
			}
		}
		if acc.Inf != 0 {
			return NewInfinity()
		}
		return acc
	}
	testScalars := []*big.Int{
		big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(7),
		big.NewInt(255), big.NewInt(256), big.NewInt(65535),
		new(big.Int).Sub(order, big.NewInt(1)), // N-1
		new(big.Int).Sub(order, big.NewInt(2)), // N-2
		new(big.Int).Sub(order, big.NewInt(3)), // N-3
	}
	for i, kBig := range testScalars {
		k := ScalarFromBigInt(kBig)
		got := ScalarMult(G, k)
		want := referenceScalarMult(G, k)
		if !Equal(got, want) {
			t.Fatalf("ScalarMult mismatch at iter %d k=%s: got Inf=%d X=%x, want Inf=%d X=%x",
				i, kBig, got.Inf, got.X.Bytes(), want.Inf, want.X.Bytes())
		}
	}

	// Group law: (k+1)*G - k*G = G for random scalars.
	for i := range 20 {
		k := deterministicScalar(t, int64(100+i))
		p1 := ScalarMult(G, ScalarAdd(k, ScalarOne()))
		p2 := ScalarMult(G, k)
		diff := Add(p1, &Point{X: p2.X, Y: FieldNeg(p2.Y)})
		if !Equal(diff, G) {
			t.Fatalf("group law violation at iteration %d", i)
		}
	}

	// Doubling consistency: 2*(k*G) = (2k)*G.
	for i := range 20 {
		k := deterministicScalar(t, int64(200+i))
		if !Equal(Double(ScalarMult(G, k)), ScalarMult(G, ScalarAdd(k, k))) {
			t.Fatalf("doubling consistency violation at iteration %d", i)
		}
	}

	// ScalarBaseMult matches ScalarMult(G, k).
	for i := range 10 {
		k := deterministicScalar(t, int64(300+i))
		if !Equal(ScalarBaseMult(k), ScalarMult(G, k)) {
			t.Fatal("ScalarBaseMult != ScalarMult(G, k)")
		}
	}

	// ScalarMult with non-G base point: k*(2G) = (2k)*G.
	// The homomorphic property verifies the generic double-and-add loop.
	twoG := Add(G, G)
	for i := range 15 {
		k := deterministicScalar(t, int64(400+i))
		got := ScalarMult(twoG, k)
		want := ScalarMult(G, ScalarMul(two, k))
		if !Equal(got, want) {
			t.Fatalf("ScalarMult(2G, k) != ScalarMult(G, 2k) at iteration %d", i)
		}
	}

	// ScalarMult with infinity base point returns infinity.
	if infResult := ScalarMult(inf, one); infResult.Inf == 0 {
		t.Fatal("ScalarMult(infinity, k) should be infinity")
	}
}

func TestScalarFromFieldElement(t *testing.T) {
	t.Parallel()

	// Compare scalarFromFieldElement against the old big.Int-based path
	// for randomly generated field elements and edge cases.
	oldPath := func(x FieldElement) Scalar {
		return scalarFromBig(new(big.Int).Mod(x.BigInt(), Order()))
	}

	// Random test points from scalar multiplications.
	for i := range 100 {
		k := deterministicScalar(t, int64(500+i))
		p := ScalarBaseMult(k)
		if p.Inf != 0 {
			continue
		}
		got := scalarFromFieldElement(p.X)
		want := oldPath(p.X)
		if !got.Equal(want) {
			t.Fatalf("mismatch for random point: got %x want %x", got.Bytes(), want.Bytes())
		}
	}

	// Edge cases: field elements near the scalar modulus n.
	for _, delta := range []int{-2, -1, 0} {
		bigN := Order()
		bigVal := new(big.Int).Add(bigN, big.NewInt(int64(delta)))
		fe := FieldElementFromBigInt(bigVal)
		got := scalarFromFieldElement(fe)
		want := oldPath(fe)
		if !got.Equal(want) {
			t.Fatalf("mismatch at n+%d: got %x want %x", delta, got.Bytes(), want.Bytes())
		}
	}

	// Edge case: field element equal to the field prime minus 1 (max field element).
	bigP := new(big.Int).SetBytes(fieldModulus[:])
	bigPm1 := new(big.Int).Sub(bigP, big.NewInt(1))
	feMax := FieldElementFromBigInt(bigPm1)
	got := scalarFromFieldElement(feMax)
	want := oldPath(feMax)
	if !got.Equal(want) {
		t.Fatalf("mismatch at p-1: got %x want %x", got.Bytes(), want.Bytes())
	}

	// Zero field element should produce ScalarZero.
	feZero := FieldZero()
	if r := scalarFromFieldElement(feZero); !r.IsZero() {
		t.Fatalf("expected zero scalar for zero field element, got %x", r.Bytes())
	}
}

func TestFiatFieldArithmeticMatchesBigInt(t *testing.T) {
	t.Parallel()

	a := FieldElementFromBigInt(big.NewInt(7))
	b := FieldElementFromBigInt(big.NewInt(11))
	got := FieldSquare(FieldAdd(a, b)).BigInt()
	want := new(big.Int).Mul(big.NewInt(18), big.NewInt(18))
	// P = secp256k1 field prime
	p := new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F})
	want.Mod(want, p)
	if got.Cmp(want) != 0 {
		t.Fatalf("fiat field arithmetic mismatch: got %s want %s", got, want)
	}
}

func deterministicScalar(t *testing.T, seed int64) Scalar {
	t.Helper()
	k, err := RandomScalar(testutil.DeterministicReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	return k
}
