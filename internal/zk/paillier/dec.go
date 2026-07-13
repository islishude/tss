package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const (
	decProofVersion   = 1
	decMaxRounds      = 256
	decMaxProofBytes  = 1 << 20
	decChallengeLabel = "github.com/islishude/tss/internal/zk/paillier/dec/challenge/v1"
)

// DecStatement is the Figure 28 Πdec statement. It asserts that
// Enc_N(y;rho)=K^x*D, X=[x]G, and S=[y]PlaintextBase. PlaintextBase is explicit
// because the accountability relations use both the fixed curve generator and
// a session-derived base such as Γ.
type DecStatement struct {
	PaillierN     *pai.PublicKey
	K             *big.Int
	D             *big.Int
	X             *secp.Point
	S             *secp.Point
	PlaintextBase *secp.Point
}

// DecWitness is the secret opening of a Figure 28 Πdec statement.
type DecWitness struct {
	X   *secret.Scalar
	Y   *secret.SignedInt
	Rho *secret.Scalar
}

// DecProof is the Fiat-Shamir form of the setup-less Figure 28 Πdec protocol.
// Every list contains one item per independent bit challenge.
type DecProof struct {
	A              [][]byte `wire:"1,byteslist,max_bytes=paillier_modulus,max_items=proof_rounds"`
	B              [][]byte `wire:"2,byteslist,max_bytes=point,max_items=proof_rounds"`
	C              [][]byte `wire:"3,byteslist,max_bytes=point,max_items=proof_rounds"`
	Z              [][]byte `wire:"4,byteslist,max_bytes=signed_response,max_items=proof_rounds"`
	W              [][]byte `wire:"5,byteslist,max_bytes=signed_response,max_items=proof_rounds"`
	Nu             [][]byte `wire:"6,byteslist,max_bytes=paillier_signed,max_items=proof_rounds"`
	TranscriptHash []byte   `wire:"7,bytes,len=32"`
}

// WireType returns the canonical Πdec proof wire type.
func (DecProof) WireType() string { return decProofType }

// WireVersion returns the canonical Πdec proof wire version.
func (DecProof) WireVersion() uint16 { return decProofVersion }

// Clone returns an independently owned Πdec proof.
func (p *DecProof) Clone() *DecProof {
	if p == nil {
		return nil
	}
	return &DecProof{
		A:              tss.CloneByteSlices(p.A),
		B:              tss.CloneByteSlices(p.B),
		C:              tss.CloneByteSlices(p.C),
		Z:              tss.CloneByteSlices(p.Z),
		W:              tss.CloneByteSlices(p.W),
		Nu:             tss.CloneByteSlices(p.Nu),
		TranscriptHash: bytes.Clone(p.TranscriptHash),
	}
}

// Destroy clears all proof fields.
func (p *DecProof) Destroy() {
	if p == nil {
		return
	}
	for _, list := range [][][]byte{p.A, p.B, p.C, p.Z, p.W, p.Nu} {
		for _, value := range list {
			clear(value)
		}
	}
	clear(p.TranscriptHash)
	*p = DecProof{}
}

// Validate checks the structural and canonical Πdec proof encoding.
func (p *DecProof) Validate() error {
	if p == nil {
		return errors.New("nil DecProof")
	}
	rounds := len(p.A)
	if rounds == 0 || rounds > decMaxRounds || len(p.B) != rounds ||
		len(p.C) != rounds || len(p.Z) != rounds || len(p.W) != rounds ||
		len(p.Nu) != rounds {
		return errors.New("DecProof: inconsistent round lists")
	}
	for i := range rounds {
		if err := validateDecPositiveBytes(fmt.Sprintf("A[%d]", i), p.A[i]); err != nil {
			return err
		}
		if _, err := secp.PointFromBytes(p.B[i]); err != nil {
			return fmt.Errorf("DecProof: invalid B[%d]: %w", i, err)
		}
		if _, err := secp.PointFromBytes(p.C[i]); err != nil {
			return fmt.Errorf("DecProof: invalid C[%d]: %w", i, err)
		}
		if err := validateDecSignedBytes(fmt.Sprintf("z[%d]", i), p.Z[i]); err != nil {
			return err
		}
		if err := validateDecSignedBytes(fmt.Sprintf("w[%d]", i), p.W[i]); err != nil {
			return err
		}
		if err := validateDecPositiveBytes(fmt.Sprintf("nu[%d]", i), p.Nu[i]); err != nil {
			return err
		}
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("DecProof: invalid transcript hash")
	}
	return nil
}

// MarshalBinary encodes a canonical Πdec proof.
func (p *DecProof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes a canonical Πdec proof.
func (p *DecProof) UnmarshalBinary(in []byte) error {
	var decoded DecProof
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(zkFrameLimits(decMaxProofBytes)),
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

// ProveDec creates a setup-less Figure 28 Πdec proof bound to state.
func ProveDec(params SecurityParams, state []byte, stmt DecStatement, witness DecWitness, rng io.Reader) (*DecProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := validateDecStatement(params, stmt, witness); err != nil {
		return nil, err
	}
	rounds := int(params.ChallengeBits)
	if rounds > decMaxRounds {
		return nil, errors.New("DecProof: too many soundness rounds")
	}
	proof := &DecProof{
		A:  make([][]byte, rounds),
		B:  make([][]byte, rounds),
		C:  make([][]byte, rounds),
		Z:  make([][]byte, rounds),
		W:  make([][]byte, rounds),
		Nu: make([][]byte, rounds),
	}
	alpha := make([]*secret.SignedInt, rounds)
	beta := make([]*secret.SignedInt, rounds)
	randomness := make([]*secret.Scalar, rounds)
	defer func() {
		for i := range rounds {
			if alpha[i] != nil {
				alpha[i].Destroy()
			}
			if beta[i] != nil {
				beta[i].Destroy()
			}
			if randomness[i] != nil {
				randomness[i].Destroy()
			}
		}
	}()

	for i := range rounds {
		var alphaScalar, betaScalar secp.Scalar
		for {
			candidate, err := sampleSignedSecret(rng, params.EncRange())
			if err != nil {
				return nil, err
			}
			alphaScalar, err = signedSecretSecpScalar(candidate)
			if err != nil {
				candidate.Destroy()
				return nil, err
			}
			if alphaScalar.IsZero() {
				candidate.Destroy()
				continue
			}
			alpha[i] = candidate
			break
		}
		for {
			candidate, err := sampleSignedSecret(rng, params.DecRange())
			if err != nil {
				alphaScalar.Set(secp.ScalarZero())
				return nil, err
			}
			betaScalar, err = signedSecretSecpScalar(candidate)
			if err != nil {
				candidate.Destroy()
				alphaScalar.Set(secp.ScalarZero())
				return nil, err
			}
			if betaScalar.IsZero() {
				candidate.Destroy()
				continue
			}
			beta[i] = candidate
			break
		}
		var err error
		randomness[i], err = sampleZNStarSecret(rng, stmt.PaillierN.N)
		if err != nil {
			alphaScalar.Set(secp.ScalarZero())
			betaScalar.Set(secp.ScalarZero())
			return nil, err
		}
		negativeAlpha, err := negateSignedSecret(alpha[i])
		if err != nil {
			alphaScalar.Set(secp.ScalarZero())
			betaScalar.Set(secp.ScalarZero())
			return nil, err
		}
		kNegativeAlpha, err := OMulCT(stmt.PaillierN, negativeAlpha, stmt.K, negativeAlpha.FixedLen())
		negativeAlpha.Destroy()
		if err != nil {
			alphaScalar.Set(secp.ScalarZero())
			betaScalar.Set(secp.ScalarZero())
			return nil, err
		}
		encBeta, err := encRandomSecrets(stmt.PaillierN, beta[i], randomness[i])
		if err != nil {
			alphaScalar.Set(secp.ScalarZero())
			betaScalar.Set(secp.ScalarZero())
			return nil, err
		}
		a, err := OAdd(stmt.PaillierN, kNegativeAlpha, encBeta)
		if err != nil {
			alphaScalar.Set(secp.ScalarZero())
			betaScalar.Set(secp.ScalarZero())
			return nil, err
		}
		proof.A[i] = a.Bytes()
		proof.B[i], err = secp.PointBytes(secp.ScalarMult(stmt.PlaintextBase, betaScalar))
		if err != nil {
			alphaScalar.Set(secp.ScalarZero())
			betaScalar.Set(secp.ScalarZero())
			return nil, err
		}
		proof.C[i], err = secp.PointBytes(secp.ScalarBaseMult(alphaScalar))
		alphaScalar.Set(secp.ScalarZero())
		betaScalar.Set(secp.ScalarZero())
		if err != nil {
			return nil, err
		}
	}

	root, err := decTranscript(params, state, stmt, proof.A, proof.B, proof.C)
	if err != nil {
		return nil, err
	}
	challenges := decChallenges(root, rounds)
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
	for i := range rounds {
		z, err := signedSecretBig(alpha[i])
		if err != nil {
			return nil, err
		}
		w, err := signedSecretBig(beta[i])
		if err != nil {
			secret.ClearBigInt(z)
			return nil, err
		}
		nu, err := secretScalarBig(randomness[i])
		if err != nil {
			secret.ClearBigInt(z)
			secret.ClearBigInt(w)
			return nil, err
		}
		if decChallengeBit(challenges, i) == 1 {
			z.Add(z, x)
			w.Add(w, y)
			nu.Mul(nu, rho).Mod(nu, stmt.PaillierN.N)
		}
		proof.Z[i], err = wire.EncodeBigInt(z)
		secret.ClearBigInt(z)
		if err != nil {
			secret.ClearBigInt(w)
			secret.ClearBigInt(nu)
			return nil, err
		}
		proof.W[i], err = wire.EncodeBigInt(w)
		secret.ClearBigInt(w)
		if err != nil {
			secret.ClearBigInt(nu)
			return nil, err
		}
		proof.Nu[i] = nu.Bytes()
		secret.ClearBigInt(nu)
	}
	proof.TranscriptHash = root
	if err := proof.Validate(); err != nil {
		proof.Destroy()
		return nil, err
	}
	return proof, nil
}

// VerifyDec verifies a setup-less Figure 28 Πdec proof bound to state.
func VerifyDec(params SecurityParams, state []byte, stmt DecStatement, proof *DecProof) error {
	if err := validateDecPublic(params, stmt); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	rounds := int(params.ChallengeBits)
	if len(proof.A) != rounds {
		return fmt.Errorf("DecProof: got %d rounds, want %d", len(proof.A), rounds)
	}
	root, err := decTranscript(params, state, stmt, proof.A, proof.B, proof.C)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, proof.TranscriptHash) {
		return errors.New("DecProof: transcript hash mismatch")
	}
	challenges := decChallenges(root, rounds)
	for i := range rounds {
		a := new(big.Int).SetBytes(proof.A[i])
		if _, err := RequireZN2Star(a, stmt.PaillierN.N); err != nil {
			return fmt.Errorf("DecProof: invalid A[%d]: %w", i, err)
		}
		b, _ := secp.PointFromBytes(proof.B[i])
		c, _ := secp.PointFromBytes(proof.C[i])
		z, _ := wire.DecodeBigInt(proof.Z[i])
		w, _ := wire.DecodeBigInt(proof.W[i])
		nu := new(big.Int).SetBytes(proof.Nu[i])
		if _, err := RequireZNStar(nu, stmt.PaillierN.N); err != nil {
			return fmt.Errorf("DecProof: invalid nu[%d]: %w", i, err)
		}
		if !InSignedPowerOfTwo(z, params.EncRange()+1) {
			return fmt.Errorf("DecProof: z[%d] out of range", i)
		}
		if !InSignedPowerOfTwo(w, params.DecRange()+1) {
			return fmt.Errorf("DecProof: w[%d] out of range", i)
		}

		leftPaillier, err := EncRandom(stmt.PaillierN, w, nu)
		if err != nil {
			return err
		}
		kZ, err := OMulPublic(stmt.PaillierN, z, stmt.K)
		if err != nil {
			return err
		}
		rightPaillier, err := OAdd(stmt.PaillierN, a, kZ)
		if err != nil {
			return err
		}
		if decChallengeBit(challenges, i) == 1 {
			rightPaillier, err = OAdd(stmt.PaillierN, rightPaillier, stmt.D)
			if err != nil {
				return err
			}
		}
		if leftPaillier.Cmp(rightPaillier) != 0 {
			return fmt.Errorf("DecProof: Paillier equation failed in round %d", i)
		}

		zScalar := secp.ScalarFromBigInt(z)
		leftX := secp.ScalarBaseMult(zScalar)
		zScalar.Set(secp.ScalarZero())
		rightX := c
		if decChallengeBit(challenges, i) == 1 {
			rightX = secp.Add(c, stmt.X)
		}
		if !secp.Equal(leftX, rightX) {
			return fmt.Errorf("DecProof: x commitment equation failed in round %d", i)
		}

		wScalar := secp.ScalarFromBigInt(w)
		leftS := secp.ScalarMult(stmt.PlaintextBase, wScalar)
		wScalar.Set(secp.ScalarZero())
		rightS := b
		if decChallengeBit(challenges, i) == 1 {
			rightS = secp.Add(b, stmt.S)
		}
		if !secp.Equal(leftS, rightS) {
			return fmt.Errorf("DecProof: plaintext commitment equation failed in round %d", i)
		}
	}
	return nil
}

func validateDecPublic(params SecurityParams, stmt DecStatement) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if stmt.PaillierN == nil || stmt.K == nil || stmt.D == nil || stmt.X == nil ||
		stmt.S == nil || stmt.PlaintextBase == nil {
		return errors.New("DecProof: incomplete statement")
	}
	if err := stmt.PaillierN.Validate(); err != nil {
		return fmt.Errorf("DecProof: invalid Paillier key: %w", err)
	}
	if err := params.CheckPaillierModulus(stmt.PaillierN); err != nil {
		return fmt.Errorf("DecProof: invalid Paillier key: %w", err)
	}
	// Figure 28 responses must be interpreted as bounded integers rather than
	// merely as residues modulo N. Require enough headroom for the signed
	// response range so a wrapped response cannot satisfy a different opening.
	if uint32(stmt.PaillierN.N.BitLen()) <= params.DecRange()+1 {
		return errors.New("DecProof: Paillier modulus is too small for decryption response range")
	}
	if err := stmt.PaillierN.ValidateCiphertext(stmt.K); err != nil {
		return fmt.Errorf("DecProof: invalid K: %w", err)
	}
	if err := stmt.PaillierN.ValidateCiphertext(stmt.D); err != nil {
		return fmt.Errorf("DecProof: invalid D: %w", err)
	}
	for name, point := range map[string]*secp.Point{
		"X": stmt.X, "PlaintextBase": stmt.PlaintextBase,
	} {
		if _, err := secp.PointBytes(point); err != nil {
			return fmt.Errorf("DecProof: invalid or identity %s: %w", name, err)
		}
	}
	if _, err := encodeDecStatementPoint(stmt.S); err != nil {
		return fmt.Errorf("DecProof: invalid S: %w", err)
	}
	return nil
}

func validateDecStatement(params SecurityParams, stmt DecStatement, witness DecWitness) error {
	if err := validateDecPublic(params, stmt); err != nil {
		return err
	}
	if witness.X == nil || witness.Y == nil || witness.Rho == nil {
		return errors.New("DecProof: incomplete witness")
	}
	if witness.X.FixedLen() != secp.ScalarSize || witness.Y.FixedLen() == 0 ||
		witness.Y.FixedLen() > modulusBytes(stmt.PaillierN.N) {
		return errors.New("DecProof: witness has invalid width")
	}
	xScalar, err := secpScalarFromSecretAllowZero(witness.X, "x")
	if err != nil {
		return err
	}
	defer xScalar.Set(secp.ScalarZero())
	if xScalar.IsZero() {
		return errors.New("DecProof: x witness must be non-zero")
	}
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
	if !InUnsignedPowerOfTwo(x, params.Ell) || !InSignedPowerOfTwo(y, params.DecPlaintextRange()) {
		return errors.New("DecProof: witness out of range")
	}
	if witness.Rho.FixedLen() != modulusBytes(stmt.PaillierN.N) {
		return errors.New("DecProof: randomness witness has invalid width")
	}
	rho, err := secretScalarBig(witness.Rho)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(rho)
	if !IsZNStar(rho, stmt.PaillierN.N) {
		return errors.New("DecProof: invalid randomness witness")
	}
	xSigned, err := signedSecretFromScalar(witness.X, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		return err
	}
	defer xSigned.Destroy()
	kX, err := OMulCT(stmt.PaillierN, xSigned, stmt.K, xSigned.FixedLen())
	if err != nil {
		return err
	}
	expectedCiphertext, err := OAdd(stmt.PaillierN, kX, stmt.D)
	if err != nil {
		return err
	}
	openedCiphertext, err := stmt.PaillierN.EncryptSignedWithSecretRandomness(witness.Y, witness.Rho)
	if err != nil {
		return err
	}
	if expectedCiphertext.Cmp(openedCiphertext) != 0 {
		return errors.New("DecProof: witness does not open K^x*D")
	}
	if !secp.Equal(secp.ScalarBaseMult(xScalar), stmt.X) {
		return errors.New("DecProof: x witness does not open X")
	}
	yScalar := secp.ScalarFromBigInt(y)
	expectedS := secp.ScalarMult(stmt.PlaintextBase, yScalar)
	yScalar.Set(secp.ScalarZero())
	if !secp.Equal(expectedS, stmt.S) {
		return errors.New("DecProof: y witness does not open S")
	}
	return nil
}

func decTranscript(params SecurityParams, state []byte, stmt DecStatement, a, b, c [][]byte) ([]byte, error) {
	if err := validateDecPublic(params, stmt); err != nil {
		return nil, err
	}
	if len(a) == 0 || len(a) != len(b) || len(a) != len(c) {
		return nil, errors.New("DecProof transcript: inconsistent commitments")
	}
	t := NewTranscript("cggmp21-paillier-dec-proof-v1")
	appendSecurityParams(t, params)
	t.AppendBytes("state", state)
	for _, field := range []struct {
		name  string
		value *big.Int
	}{
		{"N0", stmt.PaillierN.N},
		{"K", stmt.K},
		{"D", stmt.D},
	} {
		if err := t.AppendBigInt(field.name, field.value); err != nil {
			return nil, err
		}
	}
	for _, field := range []struct {
		name  string
		point *secp.Point
	}{
		{"generator", secp.G},
		{"X", stmt.X},
		{"plaintext_base", stmt.PlaintextBase},
	} {
		if err := t.AppendPoint(field.name, field.point); err != nil {
			return nil, err
		}
	}
	// Figure 9's chi relation permits chi_i=0, hence S_i=[chi_i]Gamma
	// may be the identity. The empty value is the unique local encoding of
	// infinity; finite points remain canonical compressed SEC1 encodings.
	sEncoded, err := encodeDecStatementPoint(stmt.S)
	if err != nil {
		return nil, err
	}
	t.AppendBytes("S", sEncoded)
	t.AppendUint32("rounds", uint32(len(a)))
	for i := range a {
		t.AppendUint32("round", uint32(i))
		t.AppendBytes("A", a[i])
		if err := t.AppendPointBytes("B", b[i]); err != nil {
			return nil, err
		}
		if err := t.AppendPointBytes("C", c[i]); err != nil {
			return nil, err
		}
	}
	return t.Sum(), nil
}

func encodeDecStatementPoint(point *secp.Point) ([]byte, error) {
	if point == nil || !secp.IsOnCurve(point) {
		return nil, errors.New("nil or off-curve point")
	}
	if point.Inf != 0 {
		return nil, nil
	}
	return secp.PointBytes(point)
}

func decChallenges(root []byte, rounds int) []byte {
	return expandHash((rounds+7)/8, []byte(decChallengeLabel), root, nil, nil)
}

func decChallengeBit(challenges []byte, round int) byte {
	return (challenges[round/8] >> (7 - uint(round%8))) & 1
}

func negateSignedSecret(value *secret.SignedInt) (*secret.SignedInt, error) {
	decoded, err := signedSecretBig(value)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(decoded)
	decoded.Neg(decoded)
	return signedSecretFromBig(decoded, value.FixedLen())
}

func validateDecPositiveBytes(name string, encoded []byte) error {
	if len(encoded) == 0 || encoded[0] == 0 {
		return fmt.Errorf("DecProof: %s is not a canonical positive integer", name)
	}
	return nil
}

func validateDecSignedBytes(name string, encoded []byte) error {
	value, err := wire.DecodeBigInt(encoded)
	if err != nil {
		return fmt.Errorf("DecProof: invalid %s: %w", name, err)
	}
	reencoded, err := wire.EncodeBigInt(value)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return fmt.Errorf("DecProof: non-canonical %s", name)
	}
	return nil
}
