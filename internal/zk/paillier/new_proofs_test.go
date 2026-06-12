package paillier

import (
	"fmt"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

// primeRingPedersenFixture returns a VerifierAux whose modulus is a 512-bit
// prime. ValidateRingPedersenParams (called by validateRPParamsForCommit)
// rejects prime moduli because Ring-Pedersen commitments require a composite N.
func primeRingPedersenFixture() RingPedersenParams {
	// 2^511 + 111, a 512-bit prime.
	primeN, ok := new(big.Int).SetString("6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042159", 10)
	if !ok {
		panic("failed to parse hardcoded prime")
	}
	return RingPedersenParams{
		N: primeN,
		S: big.NewInt(2),
		T: big.NewInt(3),
	}
}

func TestNewProofUnmarshalRejectsNonCanonicalSignedIntegers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		raw       []byte
		wireType  string
		tags      []uint16
		unmarshal func([]byte) error
	}{
		{
			name:     "EncProof",
			raw:      mustMarshalBinary(t, seedEncProof()),
			wireType: encProofWireType,
			tags:     []uint16{encProofFieldZ1, encProofFieldZ3},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalEncProof(raw)
				return err
			},
		},
		{
			name:     "AffGProof",
			raw:      mustMarshalBinary(t, seedAffGProof(t)),
			wireType: affGProofWireType,
			tags:     []uint16{affGProofFieldZ1, affGProofFieldZ2, affGProofFieldZ3, affGProofFieldZ4},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalAffGProof(raw)
				return err
			},
		},
		{
			name:     "LogStarProof",
			raw:      mustMarshalBinary(t, seedLogStarProof()),
			wireType: logStarProofWireType,
			tags:     []uint16{logStarProofFieldZ1, logStarProofFieldZ3},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalLogStarProof(raw)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tag := range tc.tags {
				t.Run(wireFieldName(tag), func(t *testing.T) {
					mutated, err := rewriteProofWireField(tc.raw, tc.wireType, tag, []byte{0x00, 0x00, 0x01})
					if err != nil {
						t.Fatal(err)
					}
					if err := tc.unmarshal(mutated); err == nil {
						t.Fatal("accepted non-canonical signed integer")
					}
				})
			}
		})
	}
}

func encProofFixture(t *testing.T) (SecurityParams, EncStatement, EncWitness, *EncProof) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	k := big.NewInt(17)
	ciphertext, rho, err := sk.Encrypt(nil, k)
	if err != nil {
		t.Fatal(err)
	}
	stmt := EncStatement{
		ProverPaillierN: &sk.PublicKey,
		CiphertextK:     ciphertext,
		VerifierAux:     *aux,
	}
	witness := EncWitness{K: k, Rho: rho}
	proof, err := ProveEnc(params, []byte("enc matrix"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return params, stmt, witness, proof
}

func affGProofFixture(t *testing.T) (SecurityParams, AffGStatement, AffGWitness, *AffGProof) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
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
	proof, err := ProveAffG(params, []byte("affg matrix"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return params, stmt, witness, proof
}

func logStarProofFixture(t *testing.T) (SecurityParams, LogStarStatement, LogStarWitness, *LogStarProof) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
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
	proof, err := ProveLogStar(params, []byte("logstar matrix"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return params, stmt, witness, proof
}

func fastProofParams() SecurityParams {
	return SecurityParams{Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 512}
}

func signedPowerOfTwo(bits uint) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), bits)
}

func multRangeOutside(n *big.Int, bits uint) *big.Int {
	out := new(big.Int).Lsh(big.NewInt(1), bits)
	out.Mul(out, n)
	return out
}

func rewriteProofWireField(raw []byte, wireType string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, wireType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = append([]byte(nil), value...)
			return wire.MarshalFields(version, wireType, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %d", tag)
}

func wireFieldName(tag uint16) string {
	return fmt.Sprintf("field %d", tag)
}
