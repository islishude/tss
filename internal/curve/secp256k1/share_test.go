package secp256k1

import (
	"testing"
)

func mustPointBytes(t *testing.T, p *Point) []byte {
	t.Helper()
	enc, err := PointBytes(p)
	if err != nil {
		t.Fatalf("PointBytes: %v", err)
	}
	return enc
}

// makeCommitments builds Feldman commitments for coefficients a₀…aₖ (each a Scalar).
// Returns compressed encoding of a₀*G, a₁*G, …
func makeCommitments(t *testing.T, coeffs ...Scalar) [][]byte {
	t.Helper()
	out := make([][]byte, len(coeffs))
	for i, c := range coeffs {
		out[i] = mustPointBytes(t, ScalarBaseMult(c))
	}
	return out
}

// evalPoly evaluates f(x) = a₀ + a₁*x + a₂*x² + … at x.
func evalPoly(x Scalar, coeffs ...Scalar) Scalar {
	pow := ScalarOne()
	sum := ScalarZero()
	for _, a := range coeffs {
		sum = ScalarAdd(sum, ScalarMul(a, pow))
		pow = ScalarMul(pow, x)
	}
	return sum
}

func TestEvalCommitments_empty(t *testing.T) {
	t.Parallel()

	got, err := EvalCommitments(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Inf == 0 {
		t.Fatal("empty commitments should return point at infinity")
	}
}

func TestEvalCommitments_constantPoly(t *testing.T) {
	t.Parallel()

	// f(x) = a₀  → commitment[0] = a₀*G, eval at any id = a₀*G
	a0 := deterministicScalar(t, 600)
	com := makeCommitments(t, a0)
	got, err := EvalCommitments(com, 42)
	if err != nil {
		t.Fatal(err)
	}
	want := ScalarBaseMult(a0)
	if !Equal(got, want) {
		t.Fatal("constant polynomial: eval != a0*G")
	}
}

func TestEvalCommitments_linearPoly(t *testing.T) {
	t.Parallel()

	// f(x) = a₀ + a₁*x
	a0 := deterministicScalar(t, 601)
	a1 := deterministicScalar(t, 602)
	com := makeCommitments(t, a0, a1)

	id := uint32(7)
	x := scalarFromUint64(uint64(id))

	got, err := EvalCommitments(com, id)
	if err != nil {
		t.Fatal(err)
	}
	want := ScalarBaseMult(evalPoly(x, a0, a1))
	if !Equal(got, want) {
		t.Fatal("linear polynomial: eval mismatch")
	}
}

func TestEvalCommitments_degree5(t *testing.T) {
	t.Parallel()

	// f(x) = a₀ + a₁*x + … + a₄*x⁴
	const deg = 5
	coeffs := make([]Scalar, deg)
	for i := range coeffs {
		coeffs[i] = deterministicScalar(t, int64(610+i))
	}
	com := makeCommitments(t, coeffs...)

	for _, id := range []uint32{1, 2, 3, 100, 0xFFFFFFFF} {
		x := scalarFromUint64(uint64(id))
		got, err := EvalCommitments(com, id)
		if err != nil {
			t.Fatalf("id=%d: %v", id, err)
		}
		want := ScalarBaseMult(evalPoly(x, coeffs...))
		if !Equal(got, want) {
			t.Fatalf("degree-%d poly mismatch at id=%d", deg, id)
		}
	}
}

func TestEvalCommitments_withNilEntries(t *testing.T) {
	t.Parallel()

	// f(x) = a₀ + 0*x + a₂*x²
	// Commitments: [a₀*G, nil, a₂*G] — nil entry signals zero coefficient.
	a0 := deterministicScalar(t, 620)
	a2 := deterministicScalar(t, 621)
	com := [][]byte{
		mustPointBytes(t, ScalarBaseMult(a0)),
		nil, // zero coefficient
		mustPointBytes(t, ScalarBaseMult(a2)),
	}

	id := uint32(5)
	x := scalarFromUint64(uint64(id))

	got, err := EvalCommitments(com, id)
	if err != nil {
		t.Fatal(err)
	}
	want := ScalarBaseMult(evalPoly(x, a0, ScalarZero(), a2))
	if !Equal(got, want) {
		t.Fatal("polynomial with zero coefficient mismatch")
	}
}

func TestEvalCommitments_invalidBytes(t *testing.T) {
	t.Parallel()

	com := [][]byte{{0x00, 0x01, 0x02}} // too short, not compressed
	_, err := EvalCommitments(com, 1)
	if err == nil {
		t.Fatal("expected error for invalid point bytes")
	}
}

func TestVerifyShare_valid(t *testing.T) {
	t.Parallel()

	// f(x) = a₀ + a₁*x  → share = f(id)
	a0 := deterministicScalar(t, 630)
	a1 := deterministicScalar(t, 631)
	com := makeCommitments(t, a0, a1)

	id := uint32(99)
	x := scalarFromUint64(uint64(id))
	share := evalPoly(x, a0, a1)

	if err := VerifyShare(com, id, share); err != nil {
		t.Fatalf("valid share was rejected: %v", err)
	}
}

func TestVerifyShare_wrongShare(t *testing.T) {
	t.Parallel()

	a0 := deterministicScalar(t, 640)
	a1 := deterministicScalar(t, 641)
	com := makeCommitments(t, a0, a1)

	id := uint32(3)
	x := scalarFromUint64(uint64(id))
	correct := evalPoly(x, a0, a1)
	wrong := ScalarAdd(correct, ScalarOne())

	if err := VerifyShare(com, id, wrong); err == nil {
		t.Fatal("expected error for wrong share, got nil")
	}
}

func TestVerifyShare_badCommitment(t *testing.T) {
	t.Parallel()

	share := deterministicScalar(t, 650)
	com := [][]byte{{0xFF}} // invalid compressed point
	if err := VerifyShare(com, 1, share); err == nil {
		t.Fatal("expected error for bad commitment bytes")
	}
}

func TestVerifyShare_differentID(t *testing.T) {
	t.Parallel()

	// Share computed for id=5, but verified against id=7 should fail.
	a0 := deterministicScalar(t, 660)
	a1 := deterministicScalar(t, 661)
	com := makeCommitments(t, a0, a1)

	x5 := scalarFromUint64(5)
	share := evalPoly(x5, a0, a1)

	if err := VerifyShare(com, 7, share); err == nil {
		t.Fatal("share for id=5 should not verify against id=7")
	}
}

func TestVerifyShare_zeroShare(t *testing.T) {
	t.Parallel()

	// f(x) where f(id) = 0 is a valid share (evaluates to zero scalar).
	// Need a0 + a1*id = 0 mod n → a1 = -a0 * id^{-1}
	a0 := deterministicScalar(t, 670)
	id := uint32(42)
	x := scalarFromUint64(uint64(id))
	inv, err := ScalarInvert(x)
	if err != nil {
		t.Fatal(err)
	}
	a1 := ScalarNeg(ScalarMul(a0, inv)) // a1 = -a0/x

	com := makeCommitments(t, a0, a1)
	share := ScalarZero() // f(id) = a0 + a1*id = 0

	if err := VerifyShare(com, id, share); err != nil {
		t.Fatalf("valid zero share was rejected: %v", err)
	}
}
