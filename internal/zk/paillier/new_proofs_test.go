package paillier

import (
	"fmt"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
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
		fields    []string
		unmarshal func([]byte) error
	}{
		{
			name:     "EncProof",
			raw:      mustMarshalBinary(t, seedEncProof()),
			wireType: encProofWireType,
			fields:   []string{"Z1", "Z3"},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalEncProof(raw)
				return err
			},
		},
		{
			name:     "AffGProof",
			raw:      mustMarshalBinary(t, seedAffGProof(t)),
			wireType: affGProofWireType,
			fields:   []string{"Z1", "Z2", "Z3", "Z4"},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalAffGProof(raw)
				return err
			},
		},
		{
			name:     "LogStarProof",
			raw:      mustMarshalBinary(t, seedLogStarProof()),
			wireType: logStarProofWireType,
			fields:   []string{"Z1", "Z3"},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalLogStarProof(raw)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range tc.fields {
				t.Run(wireFieldName(name), func(t *testing.T) {
					mutated, err := rewriteProofWireField(tc.raw, tc.wireType, proofModelForWireType(tc.wireType), name, []byte{0x00, 0x00, 0x01})
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

func TestSecretWitnessesRejectMalformedFixedScalars(t *testing.T) {
	t.Parallel()

	wrongWidth, err := secret.NewScalar([]byte{1}, secp.ScalarSize-1)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongWidth.Destroy()
	orderBytes := secp.Order().FillBytes(make([]byte, secp.ScalarSize))
	outOfRange, err := secret.NewScalar(orderBytes, secp.ScalarSize)
	clear(orderBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer outOfRange.Destroy()

	t.Run("enc", func(t *testing.T) {
		params, stmt, witness, _ := encProofFixture(t)
		for _, bad := range []EncWitness{
			{K: wrongWidth, Rho: witness.Rho},
			{K: outOfRange, Rho: witness.Rho},
			{K: witness.K, Rho: wrongWidth},
		} {
			if _, err := ProveEnc(params, []byte("enc matrix"), stmt, bad, nil); err == nil {
				t.Fatal("EncProof accepted malformed secret witness")
			}
		}
		destroyed := witness.K.Clone()
		destroyed.Destroy()
		if _, err := ProveEnc(params, []byte("enc matrix"), stmt, EncWitness{
			K: destroyed, Rho: witness.Rho,
		}, nil); err == nil {
			t.Fatal("EncProof accepted destroyed secret witness")
		}
	})

	t.Run("affg", func(t *testing.T) {
		params, stmt, witness, _ := affGProofFixture(t)
		for _, bad := range []AffGWitness{
			{X: wrongWidth, Y: witness.Y, Rho: witness.Rho, RhoY: witness.RhoY},
			{X: witness.X, Y: outOfRange, Rho: witness.Rho, RhoY: witness.RhoY},
			{X: witness.X, Y: witness.Y, Rho: wrongWidth, RhoY: witness.RhoY},
		} {
			if _, err := ProveAffG(params, []byte("affg matrix"), stmt, bad, nil); err == nil {
				t.Fatal("AffGProof accepted malformed secret witness")
			}
		}
	})

	t.Run("logstar", func(t *testing.T) {
		params, stmt, witness, _ := logStarProofFixture(t)
		for _, bad := range []LogStarWitness{
			{X: wrongWidth, Rho: witness.Rho},
			{X: outOfRange, Rho: witness.Rho},
			{X: witness.X, Rho: wrongWidth},
		} {
			if _, err := ProveLogStar(params, []byte("logstar matrix"), stmt, bad, nil); err == nil {
				t.Fatal("LogStarProof accepted malformed secret witness")
			}
		}
	})
}

func encProofFixture(t *testing.T) (SecurityParams, EncStatement, EncWitness, *EncProof) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	lambda.Destroy()
	k := big.NewInt(17)
	kSecret := testSecpSecretScalar(t, k)
	ciphertext, rho, err := sk.EncryptSecret(nil, kSecret)
	if err != nil {
		t.Fatal(err)
	}
	stmt := EncStatement{
		ProverPaillierN: &sk.PublicKey,
		CiphertextK:     ciphertext,
		VerifierAux:     *aux,
	}
	witness := EncWitness{K: kSecret, Rho: rho}
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
	aux, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	lambda.Destroy()
	x := big.NewInt(23)
	y := big.NewInt(29)
	xSecret := testSecpSecretScalar(t, x)
	ySecret := testSecpSecretScalar(t, y)
	c, _, err := sk.EncryptSecret(nil, xSecret)
	if err != nil {
		t.Fatal(err)
	}
	encYReceiver, rho, err := sk.EncryptSecret(nil, ySecret)
	if err != nil {
		t.Fatal(err)
	}
	xSigned := testSignedSecret(t, x, signedPowerOfTwoBytes(params.Ell))
	xMulC, err := OMulCT(&sk.PublicKey, xSigned, c, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(&sk.PublicKey, xMulC, encYReceiver)
	if err != nil {
		t.Fatal(err)
	}
	proverY, rhoY, err := sk.EncryptSecret(nil, ySecret)
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
	witness := AffGWitness{X: xSecret, Y: ySecret, Rho: rho, RhoY: rhoY}
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
	aux, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	lambda.Destroy()
	x := big.NewInt(31)
	xSecret := testSecpSecretScalar(t, x)
	c, rho, err := sk.EncryptSecret(nil, xSecret)
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
	witness := LogStarWitness{X: xSecret, Rho: rho}
	proof, err := ProveLogStar(params, []byte("logstar matrix"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return params, stmt, witness, proof
}

func fastProofParams() SecurityParams {
	return SecurityParams{Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 512}
}

func signedPowerOfTwo(bits uint32) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(bits))
}

func multRangeOutside(n *big.Int, bits uint32) *big.Int {
	out := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	out.Mul(out, n)
	return out
}

func rewriteProofWireField(raw []byte, wireType string, model any, fieldName string, value []byte) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, wireType)
	if err != nil {
		return nil, err
	}
	tag, err := wire.FieldTag(model, fieldName)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = append([]byte(nil), value...)
			return wire.MarshalFields(version, wireType, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %q", fieldName)
}

func wireFieldName(name string) string {
	return fmt.Sprintf("field %s", name)
}

func proofModelForWireType(wireType string) any {
	switch wireType {
	case encProofWireType:
		return EncProof{}
	case affGProofWireType:
		return affGProofWire{}
	case logStarProofWireType:
		return logStarProofWire{}
	default:
		panic(fmt.Sprintf("unknown proof wire type: %s", wireType))
	}
}
