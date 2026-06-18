package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const publicShareProofRounds = 128

func TestFast_PublicSharesCanonicalBinaryEncoding(t *testing.T) {
	t.Parallel()

	verification := testVerificationShare(t)
	verificationRaw, err := verification.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	var verificationDecoded VerificationShare
	if err := verificationDecoded.UnmarshalBinaryWithLimits(verificationRaw, testLimits()); err != nil {
		t.Fatal(err)
	}
	if verificationDecoded.Party != verification.Party ||
		!bytes.Equal(verificationDecoded.PublicKey, verification.PublicKey) {
		t.Fatal("verification share changed after round trip")
	}

	paillier := testPaillierPublicShare(t)
	paillierRaw, err := paillier.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	var paillierDecoded PaillierPublicShare
	if err := paillierDecoded.UnmarshalBinaryWithLimits(paillierRaw, testLimits()); err != nil {
		t.Fatal(err)
	}
	if paillierDecoded.Party != paillier.Party ||
		!bytes.Equal(paillierDecoded.PublicKey, paillier.PublicKey) ||
		!bytes.Equal(paillierDecoded.Proof, paillier.Proof) {
		t.Fatal("Paillier public share changed after round trip")
	}

	ringPedersen := testRingPedersenPublicShare(t)
	ringPedersenRaw, err := ringPedersen.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	var ringPedersenDecoded RingPedersenPublicShare
	if err := ringPedersenDecoded.UnmarshalBinaryWithLimits(ringPedersenRaw, testLimits()); err != nil {
		t.Fatal(err)
	}
	if ringPedersenDecoded.Party != ringPedersen.Party ||
		!bytes.Equal(ringPedersenDecoded.Params, ringPedersen.Params) ||
		!bytes.Equal(ringPedersenDecoded.Proof, ringPedersen.Proof) {
		t.Fatal("Ring-Pedersen public share changed after round trip")
	}

	for name, tc := range map[string]struct {
		raw    []byte
		decode func([]byte) error
	}{
		"verification": {
			raw: verificationRaw,
			decode: func(in []byte) error {
				var decoded VerificationShare
				return decoded.UnmarshalBinaryWithLimits(in, testLimits())
			},
		},
		"paillier": {
			raw: paillierRaw,
			decode: func(in []byte) error {
				var decoded PaillierPublicShare
				return decoded.UnmarshalBinaryWithLimits(in, testLimits())
			},
		},
		"ring-pedersen": {
			raw: ringPedersenRaw,
			decode: func(in []byte) error {
				var decoded RingPedersenPublicShare
				return decoded.UnmarshalBinaryWithLimits(in, testLimits())
			},
		},
	} {
		t.Run(name+" trailing byte", func(t *testing.T) {
			if err := tc.decode(append(bytes.Clone(tc.raw), 0)); err == nil {
				t.Fatal("accepted trailing byte")
			}
		})
	}
}

func TestFast_PublicSharesRejectMalformedAndOversizedFields(t *testing.T) {
	t.Parallel()

	verification := testVerificationShare(t)
	raw, err := verification.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := testutil.RewriteWireFieldByName(
		raw,
		verificationShareWireType,
		VerificationShare{},
		"Party",
		wire.Uint32(tss.BroadcastPartyId),
	)
	if err != nil {
		t.Fatal(err)
	}
	var decoded VerificationShare
	if err := decoded.UnmarshalBinaryWithLimits(mutated, testLimits()); err == nil {
		t.Fatal("accepted zero verification-share party")
	}

	limits := testLimits()
	limits.Curve.MaxPointBytes = len(verification.PublicKey) - 1
	if _, err := verification.MarshalBinaryWithLimits(limits); err == nil {
		t.Fatal("encoded verification share above point limit")
	}

	paillier := testPaillierPublicShare(t)
	limits = testLimits()
	limits.Paillier.MaxPublicKeyBytes = len(paillier.PublicKey) - 1
	if _, err := paillier.MarshalBinaryWithLimits(limits); err == nil {
		t.Fatal("encoded Paillier public share above key limit")
	}

	ringPedersen := testRingPedersenPublicShare(t)
	limits = testLimits()
	limits.Paillier.MaxRingPedersenBytes = len(ringPedersen.Params) - 1
	if _, err := ringPedersen.MarshalBinaryWithLimits(limits); err == nil {
		t.Fatal("encoded Ring-Pedersen public share above parameter limit")
	}
}

func testVerificationShare(t testing.TB) VerificationShare {
	t.Helper()
	point, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
	if err != nil {
		t.Fatal(err)
	}
	return VerificationShare{Party: 1, PublicKey: point}
}

func testPaillierPublicShare(t testing.TB) PaillierPublicShare {
	t.Helper()
	n := big.NewInt(77)
	publicKey := pai.PublicKey{
		N:        n,
		G:        new(big.Int).Add(n, big.NewInt(1)),
		NSquared: new(big.Int).Mul(n, n),
	}
	publicKeyRaw, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	x := make([][]byte, publicShareProofRounds)
	z := make([][]byte, publicShareProofRounds)
	for i := range publicShareProofRounds {
		x[i] = []byte{byte(i + 1)}
		z[i] = []byte{byte(i + 2)}
	}
	proofRaw, err := (&zkpai.ModulusProof{
		W:              []byte{1},
		TranscriptHash: bytes.Repeat([]byte{2}, sha256.Size),
		X:              x,
		A:              make([]byte, publicShareProofRounds),
		B:              make([]byte, publicShareProofRounds),
		Z:              z,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return PaillierPublicShare{Party: 1, PublicKey: publicKeyRaw, Proof: proofRaw}
}

func testRingPedersenPublicShare(t testing.TB) RingPedersenPublicShare {
	t.Helper()
	paramsRaw, err := zkpai.MarshalRingPedersenParams(&zkpai.RingPedersenParams{
		N: big.NewInt(77),
		S: big.NewInt(4),
		T: big.NewInt(9),
	})
	if err != nil {
		t.Fatal(err)
	}
	commitments := make([][]byte, publicShareProofRounds)
	responses := make([][]byte, publicShareProofRounds)
	for i := range publicShareProofRounds {
		commitments[i] = []byte{byte(i + 1)}
		responses[i] = []byte{byte(i + 2)}
	}
	proofRaw, err := (&zkpai.RingPedersenProof{
		TranscriptHash: bytes.Repeat([]byte{3}, sha256.Size),
		Commitments:    commitments,
		Challenges:     make([]byte, publicShareProofRounds),
		Responses:      responses,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return RingPedersenPublicShare{Party: 1, Params: paramsRaw, Proof: proofRaw}
}
