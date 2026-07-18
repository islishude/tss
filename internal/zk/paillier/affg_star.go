package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss/internal/clone"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const (
	affGStarProofType      = "zk.paillier.aff-g-star-proof"
	affGStarProofVersion   = 1
	affGStarMaxRounds      = 256
	affGStarMaxProofBytes  = 1 << 20
	affGStarChallengeLabel = "github.com/islishude/tss/internal/zk/paillier/aff-g-star/challenge/v1"
)

// AffGStarStatement is the setup-less Figure 27 Πaff-g* statement:
// D=C^x*Enc_N0(y;rho), Y=Enc_N1(y;mu), and X=[x]G.
type AffGStarStatement struct {
	ReceiverPaillierN *pai.PublicKey
	ProverPaillierN   *pai.PublicKey
	C                 *big.Int
	D                 *big.Int
	Y                 *big.Int
	X                 *secp.Point
}

// AffGStarWitness is the secret opening of an AffGStarStatement.
type AffGStarWitness struct {
	X   *secret.Scalar
	Y   *secret.SignedInt
	Rho *secret.Scalar
	Mu  *secret.Scalar
}

// AffGStarProof is the Fiat-Shamir form of setup-less Figure 27 Πaff-g*.
// Every list contains one item per bit challenge.
type AffGStarProof struct {
	A              [][]byte `wire:"1,byteslist,max_bytes=paillier_modulus,max_items=proof_rounds"`
	B              [][]byte `wire:"2,byteslist,max_bytes=paillier_modulus,max_items=proof_rounds"`
	R              [][]byte `wire:"3,byteslist,max_bytes=point,max_items=proof_rounds"`
	Z              [][]byte `wire:"4,byteslist,max_bytes=signed_response,max_items=proof_rounds"`
	ZPrime         [][]byte `wire:"5,byteslist,max_bytes=signed_response,max_items=proof_rounds"`
	W              [][]byte `wire:"6,byteslist,max_bytes=paillier_signed,max_items=proof_rounds"`
	Lambda         [][]byte `wire:"7,byteslist,max_bytes=paillier_signed,max_items=proof_rounds"`
	TranscriptHash []byte   `wire:"8,bytes,len=32"`
}

// WireType returns the canonical Πaff-g* proof wire type.
func (AffGStarProof) WireType() string { return affGStarProofType }

// WireVersion returns the canonical Πaff-g* proof wire version.
func (AffGStarProof) WireVersion() uint16 { return affGStarProofVersion }

// Clone returns an independently owned Πaff-g* proof.
func (p *AffGStarProof) Clone() *AffGStarProof {
	if p == nil {
		return nil
	}
	return &AffGStarProof{
		A:              clone.ByteSlices(p.A),
		B:              clone.ByteSlices(p.B),
		R:              clone.ByteSlices(p.R),
		Z:              clone.ByteSlices(p.Z),
		ZPrime:         clone.ByteSlices(p.ZPrime),
		W:              clone.ByteSlices(p.W),
		Lambda:         clone.ByteSlices(p.Lambda),
		TranscriptHash: bytes.Clone(p.TranscriptHash),
	}
}

// Destroy clears all proof fields.
func (p *AffGStarProof) Destroy() {
	if p == nil {
		return
	}
	for _, list := range [][][]byte{p.A, p.B, p.R, p.Z, p.ZPrime, p.W, p.Lambda} {
		for _, value := range list {
			clear(value)
		}
	}
	clear(p.TranscriptHash)
	*p = AffGStarProof{}
}

// Validate checks the structural and canonical Πaff-g* proof encoding.
func (p *AffGStarProof) Validate() error {
	if p == nil {
		return errors.New("nil AffGStarProof")
	}
	rounds := len(p.A)
	if rounds == 0 || rounds > affGStarMaxRounds ||
		len(p.B) != rounds || len(p.R) != rounds || len(p.Z) != rounds ||
		len(p.ZPrime) != rounds || len(p.W) != rounds || len(p.Lambda) != rounds {
		return errors.New("AffGStarProof: inconsistent round lists")
	}
	for i := range rounds {
		if err := validateCanonicalPositiveBytes(fmt.Sprintf("A[%d]", i), p.A[i]); err != nil {
			return err
		}
		if err := validateCanonicalPositiveBytes(fmt.Sprintf("B[%d]", i), p.B[i]); err != nil {
			return err
		}
		if _, err := secp.PointFromBytes(p.R[i]); err != nil {
			return fmt.Errorf("AffGStarProof: invalid R[%d]: %w", i, err)
		}
		if err := validateCanonicalSignedBytes(fmt.Sprintf("z[%d]", i), p.Z[i]); err != nil {
			return err
		}
		if err := validateCanonicalSignedBytes(fmt.Sprintf("zPrime[%d]", i), p.ZPrime[i]); err != nil {
			return err
		}
		if err := validateCanonicalPositiveBytes(fmt.Sprintf("w[%d]", i), p.W[i]); err != nil {
			return err
		}
		if err := validateCanonicalPositiveBytes(fmt.Sprintf("lambda[%d]", i), p.Lambda[i]); err != nil {
			return err
		}
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("AffGStarProof: invalid transcript hash")
	}
	return nil
}

// MarshalBinary encodes a canonical Πaff-g* proof.
func (p *AffGStarProof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes a canonical Πaff-g* proof.
func (p *AffGStarProof) UnmarshalBinary(in []byte) error {
	var decoded AffGStarProof
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(zkFrameLimits(affGStarMaxProofBytes)),
		wire.WithFieldLimits(zkFieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// ProveAffGStar creates a setup-less Figure 27 Πaff-g* proof bound to state.
func ProveAffGStar(params SecurityParams, state []byte, stmt AffGStarStatement, witness AffGStarWitness, rng io.Reader) (*AffGStarProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := validateAffGStarStatement(params, stmt, witness); err != nil {
		return nil, err
	}
	rounds := int(params.ChallengeBits)
	if rounds > affGStarMaxRounds {
		return nil, errors.New("AffGStarProof: too many soundness rounds")
	}
	n0 := stmt.ReceiverPaillierN
	n1 := stmt.ProverPaillierN
	proof := &AffGStarProof{
		A:      make([][]byte, rounds),
		B:      make([][]byte, rounds),
		R:      make([][]byte, rounds),
		Z:      make([][]byte, rounds),
		ZPrime: make([][]byte, rounds),
		W:      make([][]byte, rounds),
		Lambda: make([][]byte, rounds),
	}
	alpha := make([]*secret.SignedInt, rounds)
	beta := make([]*secret.SignedInt, rounds)
	randomness0 := make([]*secret.Scalar, rounds)
	randomness1 := make([]*secret.Scalar, rounds)
	defer func() {
		for i := range rounds {
			if alpha[i] != nil {
				alpha[i].Destroy()
			}
			if beta[i] != nil {
				beta[i].Destroy()
			}
			if randomness0[i] != nil {
				randomness0[i].Destroy()
			}
			if randomness1[i] != nil {
				randomness1[i].Destroy()
			}
		}
	}()

	for i := range rounds {
		for {
			candidate, err := sampleSignedSecret(rng, params.EncRange())
			if err != nil {
				return nil, err
			}
			candidateScalar, err := signedSecretSecpScalar(candidate)
			if err != nil {
				candidate.Destroy()
				return nil, err
			}
			rPoint := secp.ScalarBaseMult(candidateScalar)
			candidateScalar.Set(secp.ScalarZero())
			if rPoint.Inf != 0 {
				candidate.Destroy()
				continue
			}
			alpha[i] = candidate
			proof.R[i], err = secp.PointBytes(rPoint)
			if err != nil {
				return nil, err
			}
			break
		}
		var err error
		beta[i], err = sampleSignedSecret(rng, params.AffGRange())
		if err != nil {
			return nil, err
		}
		randomness0[i], err = sampleZNStarSecret(rng, n0.N)
		if err != nil {
			return nil, err
		}
		randomness1[i], err = sampleZNStarSecret(rng, n1.N)
		if err != nil {
			return nil, err
		}
		alphaC, err := OMulCT(n0, alpha[i], stmt.C, signedPowerOfTwoBytes(params.EncRange()))
		if err != nil {
			return nil, err
		}
		encBeta0, err := encRandomSecrets(n0, beta[i], randomness0[i])
		if err != nil {
			return nil, err
		}
		a, err := OAdd(n0, alphaC, encBeta0)
		if err != nil {
			return nil, err
		}
		proof.A[i] = a.Bytes()
		b, err := encRandomSecrets(n1, beta[i], randomness1[i])
		if err != nil {
			return nil, err
		}
		proof.B[i] = b.Bytes()
	}

	root, err := affGStarTranscript(params, state, stmt, proof.A, proof.B, proof.R)
	if err != nil {
		return nil, err
	}
	challenges := affGStarChallenges(root, rounds)
	x, err := secretScalarBig(witness.X)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(x)
	y, err := signedSecretBig(witness.Y)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(y)
	rho, err := secretScalarBig(witness.Rho)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rho)
	mu, err := secretScalarBig(witness.Mu)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(mu)
	for i := range rounds {
		z, err := signedSecretBig(alpha[i])
		if err != nil {
			return nil, err
		}
		zPrime, err := signedSecretBig(beta[i])
		if err != nil {
			secret.ClearBigInt(z)
			return nil, err
		}
		w, err := secretScalarBig(randomness0[i])
		if err != nil {
			secret.ClearBigInt(z)
			secret.ClearBigInt(zPrime)
			return nil, err
		}
		lambda, err := secretScalarBig(randomness1[i])
		if err != nil {
			secret.ClearBigInt(z)
			secret.ClearBigInt(zPrime)
			secret.ClearBigInt(w)
			return nil, err
		}
		if affGStarChallengeBit(challenges, i) == 1 {
			z.Add(z, x)
			zPrime.Add(zPrime, y)
			w.Mul(w, rho).Mod(w, n0.N)
			lambda.Mul(lambda, mu).Mod(lambda, n1.N)
		}
		proof.Z[i], err = wire.EncodeBigInt(z)
		secret.ClearBigInt(z)
		if err != nil {
			return nil, err
		}
		proof.ZPrime[i], err = wire.EncodeBigInt(zPrime)
		secret.ClearBigInt(zPrime)
		if err != nil {
			return nil, err
		}
		proof.W[i] = w.Bytes()
		secret.ClearBigInt(w)
		proof.Lambda[i] = lambda.Bytes()
		secret.ClearBigInt(lambda)
	}
	proof.TranscriptHash = root
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	return proof, nil
}

// VerifyAffGStar verifies a setup-less Figure 27 Πaff-g* proof bound to state.
func VerifyAffGStar(params SecurityParams, state []byte, stmt AffGStarStatement, proof *AffGStarProof) error {
	if err := validateAffGStarPublic(params, stmt); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	rounds := int(params.ChallengeBits)
	if len(proof.A) != rounds {
		return fmt.Errorf("AffGStarProof: got %d rounds, want %d", len(proof.A), rounds)
	}
	root, err := affGStarTranscript(params, state, stmt, proof.A, proof.B, proof.R)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, proof.TranscriptHash) {
		return errors.New("AffGStarProof: transcript hash mismatch")
	}
	challenges := affGStarChallenges(root, rounds)
	n0 := stmt.ReceiverPaillierN
	n1 := stmt.ProverPaillierN
	for i := range rounds {
		a := new(big.Int).SetBytes(proof.A[i])
		b := new(big.Int).SetBytes(proof.B[i])
		if _, err := RequireZN2Star(a, n0.N); err != nil {
			return fmt.Errorf("AffGStarProof: invalid A[%d]: %w", i, err)
		}
		if _, err := RequireZN2Star(b, n1.N); err != nil {
			return fmt.Errorf("AffGStarProof: invalid B[%d]: %w", i, err)
		}
		r, _ := secp.PointFromBytes(proof.R[i])
		z, _ := wire.DecodeBigInt(proof.Z[i])
		zPrime, _ := wire.DecodeBigInt(proof.ZPrime[i])
		w := new(big.Int).SetBytes(proof.W[i])
		lambda := new(big.Int).SetBytes(proof.Lambda[i])
		if _, err := RequireZNStar(w, n0.N); err != nil {
			return fmt.Errorf("AffGStarProof: invalid w[%d]: %w", i, err)
		}
		if _, err := RequireZNStar(lambda, n1.N); err != nil {
			return fmt.Errorf("AffGStarProof: invalid lambda[%d]: %w", i, err)
		}
		if !InSignedPowerOfTwo(z, params.EncRange()+1) {
			return fmt.Errorf("AffGStarProof: z[%d] out of range", i)
		}
		if !InSignedPowerOfTwo(zPrime, params.AffGRange()+1) {
			return fmt.Errorf("AffGStarProof: zPrime[%d] out of range", i)
		}

		zC, err := OMulPublic(n0, z, stmt.C)
		if err != nil {
			return err
		}
		encZPrime0, err := EncRandom(n0, zPrime, w)
		if err != nil {
			return err
		}
		left0, err := OAdd(n0, zC, encZPrime0)
		if err != nil {
			return err
		}
		right0 := a
		if affGStarChallengeBit(challenges, i) == 1 {
			right0, err = OAdd(n0, a, stmt.D)
			if err != nil {
				return err
			}
		}
		if left0.Cmp(right0) != 0 {
			return fmt.Errorf("AffGStarProof: affine equation failed in round %d", i)
		}

		leftCurve := secp.ScalarBaseMult(secp.ScalarFromBigInt(z))
		rightCurve := r
		if affGStarChallengeBit(challenges, i) == 1 {
			rightCurve = secp.Add(r, stmt.X)
		}
		if !secp.Equal(leftCurve, rightCurve) {
			return fmt.Errorf("AffGStarProof: curve equation failed in round %d", i)
		}

		left1, err := EncRandom(n1, zPrime, lambda)
		if err != nil {
			return err
		}
		right1 := b
		if affGStarChallengeBit(challenges, i) == 1 {
			right1, err = OAdd(n1, b, stmt.Y)
			if err != nil {
				return err
			}
		}
		if left1.Cmp(right1) != 0 {
			return fmt.Errorf("AffGStarProof: encryption equation failed in round %d", i)
		}
	}
	return nil
}

func validateAffGStarPublic(params SecurityParams, stmt AffGStarStatement) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if stmt.ReceiverPaillierN == nil || stmt.ProverPaillierN == nil ||
		stmt.C == nil || stmt.D == nil || stmt.Y == nil || stmt.X == nil {
		return errors.New("AffGStarProof: incomplete statement")
	}
	for name, key := range map[string]*pai.PublicKey{"N0": stmt.ReceiverPaillierN, "N1": stmt.ProverPaillierN} {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("AffGStarProof: invalid %s: %w", name, err)
		}
		if err := params.CheckPaillierModulus(key); err != nil {
			return fmt.Errorf("AffGStarProof: invalid %s: %w", name, err)
		}
	}
	if err := stmt.ReceiverPaillierN.ValidateCiphertext(stmt.C); err != nil {
		return fmt.Errorf("AffGStarProof: invalid C: %w", err)
	}
	if err := stmt.ReceiverPaillierN.ValidateCiphertext(stmt.D); err != nil {
		return fmt.Errorf("AffGStarProof: invalid D: %w", err)
	}
	if err := stmt.ProverPaillierN.ValidateCiphertext(stmt.Y); err != nil {
		return fmt.Errorf("AffGStarProof: invalid Y: %w", err)
	}
	if _, err := secp.PointBytes(stmt.X); err != nil {
		return fmt.Errorf("AffGStarProof: invalid X: %w", err)
	}
	return nil
}

func validateAffGStarStatement(params SecurityParams, stmt AffGStarStatement, witness AffGStarWitness) error {
	if err := validateAffGStarPublic(params, stmt); err != nil {
		return err
	}
	if witness.X == nil || witness.Y == nil || witness.Rho == nil || witness.Mu == nil {
		return errors.New("AffGStarProof: incomplete witness")
	}
	if witness.X.FixedLen() != secp.ScalarSize || witness.Y.FixedLen() != signedPowerOfTwoBytes(params.EllPrime) {
		return errors.New("AffGStarProof: witness has invalid width")
	}
	xScalar, err := secpScalarFromSecretAllowZero(witness.X, "x")
	if err != nil {
		return err
	}
	defer xScalar.Set(secp.ScalarZero())
	x, err := secretScalarBig(witness.X)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(x)
	y, err := signedSecretBig(witness.Y)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(y)
	if !InUnsignedPowerOfTwo(x, params.Ell) || !InSignedPowerOfTwo(y, params.EllPrime) {
		return errors.New("AffGStarProof: witness out of range")
	}
	if witness.Rho.FixedLen() != modulusBytes(stmt.ReceiverPaillierN.N) ||
		witness.Mu.FixedLen() != modulusBytes(stmt.ProverPaillierN.N) {
		return errors.New("AffGStarProof: randomness witness has invalid width")
	}
	rho, err := secretScalarBig(witness.Rho)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(rho)
	mu, err := secretScalarBig(witness.Mu)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(mu)
	if !IsZNStar(rho, stmt.ReceiverPaillierN.N) || !IsZNStar(mu, stmt.ProverPaillierN.N) {
		return errors.New("AffGStarProof: invalid randomness witness")
	}
	xSigned, err := signedSecretFromScalar(witness.X, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		return err
	}
	defer xSigned.Destroy()
	xC, err := OMulCT(stmt.ReceiverPaillierN, xSigned, stmt.C, xSigned.FixedLen())
	if err != nil {
		return err
	}
	encY0, err := stmt.ReceiverPaillierN.EncryptSignedWithSecretRandomness(witness.Y, witness.Rho)
	if err != nil {
		return err
	}
	expectedD, err := OAdd(stmt.ReceiverPaillierN, xC, encY0)
	if err != nil {
		return err
	}
	if expectedD.Cmp(stmt.D) != 0 {
		return errors.New("AffGStarProof: witness does not open D")
	}
	expectedY, err := stmt.ProverPaillierN.EncryptSignedWithSecretRandomness(witness.Y, witness.Mu)
	if err != nil {
		return err
	}
	if expectedY.Cmp(stmt.Y) != 0 {
		return errors.New("AffGStarProof: witness does not open Y")
	}
	if !secp.Equal(secp.ScalarBaseMult(xScalar), stmt.X) {
		return errors.New("AffGStarProof: witness does not open X")
	}
	return nil
}

func affGStarTranscript(params SecurityParams, state []byte, stmt AffGStarStatement, a, b, r [][]byte) ([]byte, error) {
	if err := validateAffGStarPublic(params, stmt); err != nil {
		return nil, err
	}
	if len(a) == 0 || len(a) != len(b) || len(a) != len(r) {
		return nil, errors.New("AffGStarProof transcript: inconsistent commitments")
	}
	t := NewTranscript("cggmp21-paillier-aff-g-star-proof-v1")
	appendSecurityParams(t, params)
	t.AppendBytes("state", state)
	for _, field := range []struct {
		name  string
		value *big.Int
	}{
		{"N0", stmt.ReceiverPaillierN.N},
		{"N1", stmt.ProverPaillierN.N},
		{"C", stmt.C},
		{"D", stmt.D},
		{"Y", stmt.Y},
	} {
		if err := t.AppendBigInt(field.name, field.value); err != nil {
			return nil, err
		}
	}
	if err := t.AppendPoint("X", stmt.X); err != nil {
		return nil, err
	}
	t.AppendUint32("rounds", uint32(len(a)))
	for i := range a {
		t.AppendUint32("round", uint32(i))
		t.AppendBytes("A", a[i])
		t.AppendBytes("B", b[i])
		if err := t.AppendPointBytes("R", r[i]); err != nil {
			return nil, err
		}
	}
	return t.Sum(), nil
}

func affGStarChallenges(root []byte, rounds int) []byte {
	return expandHash((rounds+7)/8, []byte(affGStarChallengeLabel), root, nil, nil)
}

func affGStarChallengeBit(challenges []byte, round int) byte {
	return (challenges[round/8] >> (7 - uint(round%8))) & 1
}

func validateCanonicalPositiveBytes(name string, encoded []byte) error {
	if len(encoded) == 0 || encoded[0] == 0 {
		return fmt.Errorf("AffGStarProof: %s is not a canonical positive integer", name)
	}
	return nil
}

func validateCanonicalSignedBytes(name string, encoded []byte) error {
	value, err := wire.DecodeBigInt(encoded)
	if err != nil {
		return fmt.Errorf("AffGStarProof: invalid %s: %w", name, err)
	}
	reencoded, err := wire.EncodeBigInt(value)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return fmt.Errorf("AffGStarProof: non-canonical %s", name)
	}
	return nil
}
