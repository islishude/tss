package secp256k1

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/testutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestIndependentRingPedersenRejectsEqualModulusAndDestroysFactors(t *testing.T) {
	auxiliaryKey, err := pai.GenerateKeyForTest(context.Background(), testutil.DeterministicReader(1701), 512)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := new(big.Int).Set(auxiliaryKey.N)

	_, _, err = proveIndependentRingPedersen(
		testutil.DeterministicReader(1702),
		forbidden,
		1,
		func(*zkpai.RingPedersenParams) ([]byte, error) { return []byte("equal-modulus-test"), nil },
		auxiliaryKey,
	)
	if err == nil || !strings.Contains(err.Error(), "must be independent") {
		t.Fatalf("equal-modulus error = %v", err)
	}
	assertDestroyedAuxiliaryKey(t, auxiliaryKey)
}

func TestIndependentRingPedersenProducesVerifiablePublicMaterial(t *testing.T) {
	forbiddenKey, err := pai.GenerateKeyForTest(context.Background(), testutil.DeterministicReader(1711), 512)
	if err != nil {
		t.Fatal(err)
	}
	defer forbiddenKey.Destroy()
	auxiliaryKey, err := pai.GenerateKeyForTest(context.Background(), testutil.DeterministicReader(1712), 512)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("independent-ring-pedersen-test")
	params, proof, err := proveIndependentRingPedersen(
		testutil.DeterministicReader(1713),
		forbiddenKey.N,
		1,
		func(*zkpai.RingPedersenParams) ([]byte, error) { return domain, nil },
		auxiliaryKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertDestroyedAuxiliaryKey(t, auxiliaryKey)
	if params.N.Cmp(forbiddenKey.N) == 0 {
		t.Fatal("generated auxiliary modulus equals forbidden Paillier modulus")
	}
	security := zkpai.SecurityParams{
		Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 512,
	}
	if !zkpai.VerifyRingPedersen(security, domain, params, 1, proof) {
		t.Fatal("independent Ring-Pedersen proof did not verify")
	}
}

func TestIndependentRingPedersenDestroysFactorsWhenDomainConstructionFails(t *testing.T) {
	auxiliaryKey, err := pai.GenerateKeyForTest(context.Background(), testutil.DeterministicReader(1721), 512)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := new(big.Int).Add(auxiliaryKey.N, big.NewInt(2))
	want := errors.New("injected domain failure")

	_, _, err = proveIndependentRingPedersen(
		testutil.DeterministicReader(1722),
		forbidden,
		1,
		func(*zkpai.RingPedersenParams) ([]byte, error) { return nil, want },
		auxiliaryKey,
	)
	if !errors.Is(err, want) {
		t.Fatalf("domain failure error = %v, want %v", err, want)
	}
	assertDestroyedAuxiliaryKey(t, auxiliaryKey)
}

func assertDestroyedAuxiliaryKey(t testing.TB, key *pai.PrivateKey) {
	t.Helper()
	if key == nil || key.P == nil || key.Q == nil || key.Lambda == nil || key.Mu == nil {
		t.Fatal("auxiliary key unexpectedly missing secret handles")
	}
	if key.P.FixedLen() != 0 || key.Q.FixedLen() != 0 || key.Lambda.FixedLen() != 0 || key.Mu.FixedLen() != 0 {
		t.Fatal("auxiliary factors or exponents survived ownership cleanup")
	}
}
