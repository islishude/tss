package mta

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestMTAWideMaskDefeatsScalarIntervalExtraction(t *testing.T) {
	t.Parallel()

	const bits = uint32(512)
	mask, err := randomWideMask(bytes.NewReader(bytes.Repeat([]byte{0xff}, int((bits+8)/8))), bits)
	if err != nil {
		t.Fatal(err)
	}
	defer mask.Destroy()
	if mask.FixedLen() <= secp.ScalarSize {
		t.Fatal("MtA mask retained curve-scalar width")
	}
	magnitude := mask.FixedMagnitude()
	defer clear(magnitude)
	beta := new(big.Int).SetBytes(magnitude)
	defer secret.ClearBigInt(beta)
	if beta.Cmp(secp.Order()) <= 0 {
		t.Fatal("test mask did not exceed the old scalar interval")
	}
	b := big.NewInt(7)
	a := new(big.Int).Sub(secp.Order(), big.NewInt(1))
	alpha := new(big.Int).Mul(a, b)
	alpha.Add(alpha, beta)
	lower := new(big.Int).Sub(alpha, new(big.Int).Sub(secp.Order(), big.NewInt(1)))
	lower.Add(lower, new(big.Int).Sub(a, big.NewInt(1)))
	lower.Div(lower, a)
	upper := new(big.Int).Sub(alpha, big.NewInt(1))
	upper.Div(upper, a)
	if b.Cmp(lower) >= 0 && b.Cmp(upper) <= 0 {
		t.Fatal("wide MtA mask remained recoverable from the old scalar interval")
	}
}

func testSecurityParams() zkpai.SecurityParams {
	return zkpai.SecurityParams{
		Ell:             256,
		EllPrime:        512,
		Epsilon:         64,
		ChallengeBits:   128,
		MinPaillierBits: 768,
	}
}

// setupTestEnv creates fresh Paillier keys and Ring-Pedersen parameters with
// reduced security parameters for Tier 1 tests.
func setupTestEnv(tb testing.TB) (skA, skB *pai.PrivateKey, rpA, rpB *zkpai.RingPedersenParams) {
	tb.Helper()
	var err error
	skA, err = pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	skB, err = pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	auxSKA, err := pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	defer auxSKA.Destroy()
	auxSKB, err := pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	defer auxSKB.Destroy()
	var lambdaA *secret.Scalar
	rpA, lambdaA, err = zkpai.GenerateRingPedersenParams(nil, auxSKA)
	if err != nil {
		tb.Fatal(err)
	}
	lambdaA.Destroy()
	var lambdaB *secret.Scalar
	rpB, lambdaB, err = zkpai.GenerateRingPedersenParams(nil, auxSKB)
	if err != nil {
		tb.Fatal(err)
	}
	lambdaB.Destroy()
	return skA, skB, rpA, rpB
}

func testSecretScalar(tb testing.TB, x *big.Int) *secret.Scalar {
	tb.Helper()
	if x == nil {
		return nil
	}
	magnitude := new(big.Int).Abs(x)
	defer secret.ClearBigInt(magnitude)
	out, err := secret.NewScalar(magnitude.FillBytes(make([]byte, secp.ScalarSize)), secp.ScalarSize)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(out.Destroy)
	return out
}

func testSecretBig(tb testing.TB, x *secret.Scalar) *big.Int {
	tb.Helper()
	if x == nil {
		return nil
	}
	fixed := x.FixedBytes()
	defer clear(fixed)
	return new(big.Int).SetBytes(fixed)
}

func seedMessages(tb testing.TB) (*StartMessage, *ResponseMessage) {
	tb.Helper()
	skA, skB, rpA, rpB := setupTestEnv(tb)
	a := big.NewInt(13)
	b := big.NewInt(37)
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		tb.Fatal(err)
	}
	aCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(a)))
	if err != nil {
		tb.Fatal(err)
	}
	start, err := Start(nil, testSecretScalar(tb, a), skA.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	params := testSecurityParams()
	startProof, err := ProveStartForVerifier(params, nil, []byte("start"), start, aCommit, skA.PublicKey, rpB)
	if err != nil {
		tb.Fatal(err)
	}
	response, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, aCommit, testSecretScalar(tb, b), bCommit, skA.PublicKey, skB.PublicKey, rpB, rpA)
	if err != nil {
		tb.Fatal(err)
	}
	return &start.Message, response
}

// Tier 0: helper validation tests (no crypto keygen).

func TestValidatePositiveIntegerBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{name: "empty", input: nil, wantErr: "empty integer"},
		{name: "zero len", input: []byte{}, wantErr: "empty integer"},
		{name: "leading zero", input: []byte{0x00, 0x01}, wantErr: "non-minimal integer encoding"},
		{name: "zero value", input: []byte{0x00}, wantErr: "non-minimal integer encoding"},
		{name: "all zeros", input: []byte{0x00, 0x00, 0x00}, wantErr: "non-minimal integer encoding"},
		{name: "valid small", input: []byte{0x01}, wantErr: ""},
		{name: "valid medium", input: []byte{0x42}, wantErr: ""},
		{name: "valid large", input: []byte{0xFF, 0xFF, 0xFF}, wantErr: ""},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validatePositiveIntegerBytes(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("got error %q, want %q", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

func TestRandomSecretScalar(t *testing.T) {
	t.Parallel()

	x, err := randomSecretScalar(testutil.DeterministicReader(1))
	if err != nil {
		t.Fatal(err)
	}
	xScalar, err := secpScalarFromSecret(x)
	if err != nil || xScalar.IsZero() {
		t.Fatal("random scalar is invalid")
	}

	xAgain, err := randomSecretScalar(testutil.DeterministicReader(1))
	if err != nil {
		t.Fatal(err)
	}
	if !x.Equal(xAgain) {
		t.Fatal("randomSecretScalar did not consume deterministic reader reproducibly")
	}
}

func TestMessageVersion(t *testing.T) {
	t.Parallel()

	if startMessageWireVersion != 1 || responseMessageWireVersion != 1 {
		t.Fatal("MtA wire version changed; wire format may be incompatible")
	}
}
