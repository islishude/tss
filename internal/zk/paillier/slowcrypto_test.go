//go:build slowcrypto

package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
)

func TestSlowCrypto_PaillierZKProductionProofs(t *testing.T) {
	t.Parallel()
	params := DefaultSecurityParams()
	sk := testPaillierKey(t, int(params.MinPaillierBits))
	domain := []byte("slowcrypto paillier zk")

	modProof, err := ProveModulus(nil, domain, sk, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyModulus(domain, &sk.PublicKey, 1, modProof) {
		t.Fatal("production modulus proof did not verify")
	}
	if VerifyModulus([]byte("other"), &sk.PublicKey, 1, modProof) {
		t.Fatal("production modulus proof verified under wrong domain")
	}

	aux, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	rpProof, err := ProveRingPedersen(nil, domain, sk, aux, lambda, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRingPedersen(domain, aux, 1, rpProof) {
		t.Fatal("production Ring-Pedersen proof did not verify")
	}
	if VerifyRingPedersen([]byte("other"), aux, 1, rpProof) {
		t.Fatal("production Ring-Pedersen proof verified under wrong domain")
	}

	encStmt, encWitness, encProof := slowEncProof(t, params, sk, aux)
	if err := VerifyEnc(params, domain, encStmt, encProof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnc(params, []byte("other"), encStmt, encProof); err == nil {
		t.Fatal("production EncProof verified under wrong state")
	}
	if _, err := ProveEnc(params, domain, encStmt, EncWitness{K: new(big.Int).Add(encWitness.K, big.NewInt(1)), Rho: encWitness.Rho}, nil); err == nil {
		t.Fatal("production EncProof accepted wrong witness")
	}

	affGStmt, affGWitness, affGProof := slowAffGProof(t, params, sk, aux)
	if err := VerifyAffG(params, domain, affGStmt, affGProof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAffG(params, []byte("other"), affGStmt, affGProof); err == nil {
		t.Fatal("production AffGProof verified under wrong state")
	}
	if _, err := ProveAffG(params, domain, affGStmt, AffGWitness{
		X: new(big.Int).Add(affGWitness.X, big.NewInt(1)), Y: affGWitness.Y, Rho: affGWitness.Rho, RhoY: affGWitness.RhoY,
	}, nil); err == nil {
		t.Fatal("production AffGProof accepted wrong witness")
	}

	logStmt, logWitness, logProof := slowLogStarProof(t, params, sk, aux)
	if err := VerifyLogStar(params, domain, logStmt, logProof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLogStar(params, []byte("other"), logStmt, logProof); err == nil {
		t.Fatal("production LogStarProof verified under wrong state")
	}
	if _, err := ProveLogStar(params, domain, logStmt, LogStarWitness{X: new(big.Int).Add(logWitness.X, big.NewInt(1)), Rho: logWitness.Rho}, nil); err == nil {
		t.Fatal("production LogStarProof accepted wrong witness")
	}
}

func slowEncProof(t *testing.T, params SecurityParams, sk *pai.PrivateKey, aux *RingPedersenParams) (EncStatement, EncWitness, *EncProof) {
	t.Helper()
	k := big.NewInt(17)
	ciphertext, rho, err := sk.Encrypt(nil, k)
	if err != nil {
		t.Fatal(err)
	}
	stmt := EncStatement{ProverPaillierN: &sk.PublicKey, CiphertextK: ciphertext, VerifierAux: *aux}
	witness := EncWitness{K: k, Rho: rho}
	proof, err := ProveEnc(params, []byte("slowcrypto paillier zk"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return stmt, witness, proof
}

func slowAffGProof(t *testing.T, params SecurityParams, sk *pai.PrivateKey, aux *RingPedersenParams) (AffGStatement, AffGWitness, *AffGProof) {
	t.Helper()
	x := big.NewInt(23)
	y := big.NewInt(29)
	c, _, err := sk.Encrypt(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	encYReceiver, rho, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	xMulC, err := OMulCT(&sk.PublicKey, x, c, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(&sk.PublicKey, xMulC, encYReceiver)
	if err != nil {
		t.Fatal(err)
	}
	proverY, rhoY, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	stmt := AffGStatement{
		ReceiverPaillierN: &sk.PublicKey,
		ProverPaillierN:   &sk.PublicKey,
		C:                 c,
		D:                 d,
		Y:                 proverY,
		X:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		VerifierAux:       *aux,
	}
	witness := AffGWitness{X: x, Y: y, Rho: rho, RhoY: rhoY}
	proof, err := ProveAffG(params, []byte("slowcrypto paillier zk"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return stmt, witness, proof
}

func slowLogStarProof(t *testing.T, params SecurityParams, sk *pai.PrivateKey, aux *RingPedersenParams) (LogStarStatement, LogStarWitness, *LogStarProof) {
	t.Helper()
	x := big.NewInt(31)
	c, rho, err := sk.Encrypt(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	base := secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1)))
	stmt := LogStarStatement{
		PaillierN:   &sk.PublicKey,
		C:           c,
		X:           secp.ScalarMult(base, secp.ScalarFromBigInt(x)),
		B:           base,
		VerifierAux: *aux,
	}
	witness := LogStarWitness{X: x, Rho: rho}
	proof, err := ProveLogStar(params, []byte("slowcrypto paillier zk"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return stmt, witness, proof
}
