package secp256k1

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestBasePointEncoding(t *testing.T) {
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
	secret, err := RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := ScalarBaseMult(secret)
	digest := sha256.Sum256([]byte("test"))
	r, s, err := SignECDSA(rand.Reader, digest[:], secret, true)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyECDSA(pub, digest[:], r, s) {
		t.Fatal("signature did not verify")
	}
}

func TestFiatScalarArithmeticMatchesBigInt(t *testing.T) {
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
		k, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p1 := ScalarMult(G, ScalarAdd(k, ScalarOne()))
		p2 := ScalarMult(G, k)
		diff := Add(p1, &Point{X: p2.X, Y: FieldNeg(p2.Y)})
		if !Equal(diff, G) {
			t.Fatalf("group law violation at iteration %d", i)
		}
	}

	// Doubling consistency: 2*(k*G) = (2k)*G.
	for i := range 20 {
		k, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !Equal(Double(ScalarMult(G, k)), ScalarMult(G, ScalarAdd(k, k))) {
			t.Fatalf("doubling consistency violation at iteration %d", i)
		}
	}

	// ScalarBaseMult matches ScalarMult(G, k).
	for range 10 {
		k, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !Equal(ScalarBaseMult(k), ScalarMult(G, k)) {
			t.Fatal("ScalarBaseMult != ScalarMult(G, k)")
		}
	}

	// ScalarMult with non-G base point: k*(2G) = (2k)*G.
	// The homomorphic property verifies the generic double-and-add loop.
	twoG := Add(G, G)
	for i := range 15 {
		k, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
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

func TestScalarMultAllocCount(t *testing.T) {
	base := G
	// Verify that ScalarMult with different non-zero scalars allocates
	// the same number of objects (heuristic constant-time check).
	var first float64
	for i := range 10 {
		k, err := RandomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		allocs := testing.AllocsPerRun(1, func() {
			_ = ScalarMult(base, k)
		})
		if i == 0 {
			first = allocs
		} else if allocs != first {
			t.Fatalf("allocation count differs: got %.0f, expected %.0f at iteration %d", allocs, first, i)
		}
	}
}

func TestFiatFieldArithmeticMatchesBigInt(t *testing.T) {
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
