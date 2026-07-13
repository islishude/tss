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
	mulProofType     = "zk.paillier.mul-proof"
	mulStarProofType = "zk.paillier.mulstar-proof"
	decProofType     = "zk.paillier.dec-proof"
)

// MulStatement is the public statement X=Enc(x;rhoX), C=Y^x*rhoC^N.
type MulStatement struct {
	PaillierN *pai.PublicKey
	X         *big.Int
	Y         *big.Int
	C         *big.Int
}

// MulWitness is the secret witness for a Πmul proof.
type MulWitness struct {
	X    *secret.Scalar
	RhoX *secret.Scalar
	RhoC *secret.Scalar
}

// MulProof is the Fiat-Shamir form of CGGMP Πmul.
type MulProof struct {
	A              *big.Int `wire:"1,bigpos,max_bytes=paillier_modulus"`
	B              *big.Int `wire:"2,bigpos,max_bytes=paillier_modulus"`
	Z              *big.Int `wire:"3,bigpos,max_bytes=signed_response"`
	U              *big.Int `wire:"4,bigpos,max_bytes=paillier_signed"`
	V              *big.Int `wire:"5,bigpos,max_bytes=paillier_signed"`
	TranscriptHash []byte   `wire:"6,bytes,len=32"`
}

// WireType returns the canonical Πmul proof wire type.
func (MulProof) WireType() string { return mulProofType }

// WireVersion returns the canonical Πmul proof wire version.
func (MulProof) WireVersion() uint16 { return 1 }

// Clone returns an independently owned Πmul proof.
func (p *MulProof) Clone() *MulProof {
	if p == nil {
		return nil
	}
	return &MulProof{A: tss.CloneBigInt(p.A), B: tss.CloneBigInt(p.B), Z: tss.CloneBigInt(p.Z), U: tss.CloneBigInt(p.U), V: tss.CloneBigInt(p.V), TranscriptHash: bytes.Clone(p.TranscriptHash)}
}

// Destroy clears the proof's witness-derived responses.
func (p *MulProof) Destroy() {
	if p == nil {
		return
	}
	secret.ClearBigInt(p.A)
	secret.ClearBigInt(p.B)
	secret.ClearBigInt(p.Z)
	secret.ClearBigInt(p.U)
	secret.ClearBigInt(p.V)
	clear(p.TranscriptHash)
	*p = MulProof{}
}

// Validate checks the structural Πmul proof encoding.
func (p *MulProof) Validate() error {
	if p == nil || p.A == nil || p.B == nil || p.Z == nil || p.U == nil || p.V == nil {
		return errors.New("incomplete MulProof")
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("invalid MulProof transcript hash")
	}
	return nil
}

// MarshalBinary encodes a canonical Πmul proof.
func (p *MulProof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes a canonical Πmul proof.
func (p *MulProof) UnmarshalBinary(in []byte) error {
	var decoded MulProof
	if err := wire.Unmarshal(in, &decoded, wire.WithFrameLimits(zkFrameLimits(tss.DefaultMaxZKProofBytes)), wire.WithFieldLimits(zkFieldLimits())); err != nil {
		return err
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// ProveMul proves that the plaintext of C is the product of the plaintexts of X and Y.
func ProveMul(params SecurityParams, state []byte, stmt MulStatement, witness MulWitness, rng io.Reader) (*MulProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := validateMulStatement(params, stmt, witness); err != nil {
		return nil, err
	}
	n := stmt.PaillierN
	alpha, err := sampleZNStarSecret(rng, n.N)
	if err != nil {
		return nil, err
	}
	defer alpha.Destroy()
	r, err := sampleZNStarSecret(rng, n.N)
	if err != nil {
		return nil, err
	}
	defer r.Destroy()
	s, err := sampleZNStarSecret(rng, n.N)
	if err != nil {
		return nil, err
	}
	defer s.Destroy()

	alphaSigned, err := signedSecretFromScalar(alpha, alpha.FixedLen())
	if err != nil {
		return nil, err
	}
	defer alphaSigned.Destroy()
	alphaY, err := OMulCT(n, alphaSigned, stmt.Y, alpha.FixedLen())
	if err != nil {
		return nil, err
	}
	rBig, err := secretScalarBig(r)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rBig)
	encZeroR, err := EncRandom(n, big.NewInt(0), rBig)
	if err != nil {
		return nil, err
	}
	A, err := OAdd(n, alphaY, encZeroR)
	if err != nil {
		return nil, err
	}
	alphaBig, err := secretScalarBig(alpha)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(alphaBig)
	sBig, err := secretScalarBig(s)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(sBig)
	B, err := EncRandom(n, alphaBig, sBig)
	if err != nil {
		return nil, err
	}

	tr, err := buildMulTranscript(params, state, stmt, A, B)
	if err != nil {
		return nil, err
	}
	e, err := tr.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return nil, err
	}
	xBig, err := secretScalarBig(witness.X)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(xBig)
	z := new(big.Int).Mul(e, xBig)
	z.Add(z, alphaBig)
	u, err := publicChallengeRandomnessResponse(r, witness.RhoC, e, n.N)
	if err != nil {
		return nil, err
	}
	v, err := publicChallengeRandomnessResponse(s, witness.RhoX, e, n.N)
	if err != nil {
		secret.ClearBigInt(u)
		return nil, err
	}
	return &MulProof{A: A, B: B, Z: z, U: u, V: v, TranscriptHash: tr.Sum()}, nil
}

// VerifyMul verifies a Πmul proof.
func VerifyMul(params SecurityParams, state []byte, stmt MulStatement, proof *MulProof) error {
	if err := validateMulPublic(params, stmt); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	n := stmt.PaillierN
	for name, value := range map[string]*big.Int{"A": proof.A, "B": proof.B} {
		if _, err := RequireZN2Star(value, n.N); err != nil {
			return fmt.Errorf("MulProof: %s not in Z*_N^2: %w", name, err)
		}
	}
	for name, value := range map[string]*big.Int{"U": proof.U, "V": proof.V} {
		if _, err := RequireZNStar(value, n.N); err != nil {
			return fmt.Errorf("MulProof: %s not in Z*_N: %w", name, err)
		}
	}
	if proof.Z.Sign() < 0 || proof.Z.BitLen() > n.N.BitLen()+int(params.ChallengeBits)+2 {
		return errors.New("MulProof: z out of range")
	}
	tr, err := buildMulTranscript(params, state, stmt, proof.A, proof.B)
	if err != nil {
		return err
	}
	if !bytes.Equal(tr.Sum(), proof.TranscriptHash) {
		return errors.New("MulProof: transcript hash mismatch")
	}
	e, err := tr.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return err
	}
	left1, err := OMulPublic(n, proof.Z, stmt.Y)
	if err != nil {
		return err
	}
	encZeroU, err := EncRandom(n, big.NewInt(0), proof.U)
	if err != nil {
		return err
	}
	left1, err = OAdd(n, left1, encZeroU)
	if err != nil {
		return err
	}
	ce, err := OMulPublic(n, e, stmt.C)
	if err != nil {
		return err
	}
	right1, err := OAdd(n, proof.A, ce)
	if err != nil {
		return err
	}
	if left1.Cmp(right1) != 0 {
		return errors.New("MulProof: product equation failed")
	}
	left2, err := EncRandom(n, proof.Z, proof.V)
	if err != nil {
		return err
	}
	xe, err := OMulPublic(n, e, stmt.X)
	if err != nil {
		return err
	}
	right2, err := OAdd(n, proof.B, xe)
	if err != nil {
		return err
	}
	if left2.Cmp(right2) != 0 {
		return errors.New("MulProof: plaintext equation failed")
	}
	return nil
}

func validateMulPublic(params SecurityParams, stmt MulStatement) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if stmt.PaillierN == nil {
		return errors.New("MulProof: nil Paillier key")
	}
	if err := stmt.PaillierN.Validate(); err != nil {
		return err
	}
	if err := params.CheckPaillierModulus(stmt.PaillierN); err != nil {
		return err
	}
	for name, value := range map[string]*big.Int{"X": stmt.X, "Y": stmt.Y, "C": stmt.C} {
		if _, err := RequireZN2Star(value, stmt.PaillierN.N); err != nil {
			return fmt.Errorf("MulProof: %s not in Z*_N^2: %w", name, err)
		}
	}
	return nil
}

func validateMulStatement(params SecurityParams, stmt MulStatement, witness MulWitness) error {
	if err := validateMulPublic(params, stmt); err != nil {
		return err
	}
	if witness.X == nil || witness.RhoX == nil || witness.RhoC == nil {
		return errors.New("MulProof: incomplete witness")
	}
	xBig, err := secretScalarBig(witness.X)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(xBig)
	rhoX, err := secretScalarBig(witness.RhoX)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(rhoX)
	wantX, err := EncRandom(stmt.PaillierN, xBig, rhoX)
	if err != nil || wantX.Cmp(stmt.X) != 0 {
		return errors.New("MulProof: X witness mismatch")
	}
	xSigned, err := signedSecretFromScalar(witness.X, max(witness.X.FixedLen(), signedPowerOfTwoBytes(params.Ell)))
	if err != nil {
		return err
	}
	defer xSigned.Destroy()
	yx, err := OMulCT(stmt.PaillierN, xSigned, stmt.Y, xSigned.FixedLen())
	if err != nil {
		return err
	}
	rhoC, err := secretScalarBig(witness.RhoC)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(rhoC)
	zero, err := EncRandom(stmt.PaillierN, big.NewInt(0), rhoC)
	if err != nil {
		return err
	}
	wantC, err := OAdd(stmt.PaillierN, yx, zero)
	if err != nil || wantC.Cmp(stmt.C) != 0 {
		return errors.New("MulProof: C witness mismatch")
	}
	return nil
}

func buildMulTranscript(params SecurityParams, state []byte, stmt MulStatement, A, B *big.Int) (*Transcript, error) {
	t := NewTranscript("cggmp21-paillier-mul-proof-v1")
	appendSecurityParams(t, params)
	t.AppendBytes("state", state)
	for _, item := range []struct {
		label string
		value *big.Int
	}{{"N", stmt.PaillierN.N}, {"X", stmt.X}, {"Y", stmt.Y}, {"C", stmt.C}, {"A", A}, {"B", B}} {
		if err := t.AppendBigInt(item.label, item.value); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// MulStarStatement is the public statement D=C^x*rho^N and X=x*B.
type MulStarStatement struct {
	PaillierN   *pai.PublicKey
	C           *big.Int
	D           *big.Int
	X           *secp.Point
	B           *secp.Point
	VerifierAux *RingPedersenParams
}

// MulStarWitness is the secret witness for Πmul*.
type MulStarWitness struct {
	X   *secret.Scalar
	Rho *secret.Scalar
}

// MulStarProof is the Fiat-Shamir form of CGGMP Πmul*.
type MulStarProof struct {
	A              *big.Int    `wire:"1,bigpos,max_bytes=paillier_modulus"`
	Bx             *secp.Point `wire:"2,custom,max_bytes=point"`
	S              *big.Int    `wire:"3,bigpos,max_bytes=paillier_modulus"`
	E              *big.Int    `wire:"4,bigpos,max_bytes=paillier_modulus"`
	Z1             *big.Int    `wire:"5,bigint,max_bytes=signed_response"`
	Z2             *big.Int    `wire:"6,bigint,max_bytes=signed_response"`
	W              *big.Int    `wire:"7,bigpos,max_bytes=paillier_signed"`
	TranscriptHash []byte      `wire:"8,bytes,len=32"`
}

// WireType returns the canonical Πmul* proof wire type.
func (MulStarProof) WireType() string { return mulStarProofType }

// WireVersion returns the canonical Πmul* proof wire version.
func (MulStarProof) WireVersion() uint16 { return 1 }

// Clone returns an independently owned Πmul* proof.
func (p *MulStarProof) Clone() *MulStarProof {
	if p == nil {
		return nil
	}
	return &MulStarProof{A: tss.CloneBigInt(p.A), Bx: secp.Clone(p.Bx), S: tss.CloneBigInt(p.S), E: tss.CloneBigInt(p.E), Z1: tss.CloneBigInt(p.Z1), Z2: tss.CloneBigInt(p.Z2), W: tss.CloneBigInt(p.W), TranscriptHash: bytes.Clone(p.TranscriptHash)}
}

// Destroy clears the proof's witness-derived responses.
func (p *MulStarProof) Destroy() {
	if p == nil {
		return
	}
	secret.ClearBigInt(p.A)
	secret.ClearBigInt(p.S)
	secret.ClearBigInt(p.E)
	secret.ClearBigInt(p.Z1)
	secret.ClearBigInt(p.Z2)
	secret.ClearBigInt(p.W)
	clear(p.TranscriptHash)
	*p = MulStarProof{}
}

// Validate checks the structural Πmul* proof encoding.
func (p *MulStarProof) Validate() error {
	if p == nil || p.A == nil || p.Bx == nil || p.S == nil || p.E == nil || p.Z1 == nil || p.Z2 == nil || p.W == nil {
		return errors.New("incomplete MulStarProof")
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("invalid MulStarProof transcript hash")
	}
	return nil
}

// MarshalBinary encodes a canonical Πmul* proof.
func (p *MulStarProof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes a canonical Πmul* proof.
func (p *MulStarProof) UnmarshalBinary(in []byte) error {
	var d MulStarProof
	if err := wire.Unmarshal(in, &d, wire.WithFrameLimits(zkFrameLimits(tss.DefaultMaxZKProofBytes)), wire.WithFieldLimits(zkFieldLimits())); err != nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return err
	}
	*p = d
	return nil
}

// ProveMulStar proves D=C^x*rho^N and X=x*B with x in the scalar range.
func ProveMulStar(params SecurityParams, state []byte, stmt MulStarStatement, w MulStarWitness, rng io.Reader) (*MulStarProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := validateMulStarStatement(params, stmt, w); err != nil {
		return nil, err
	}
	n := stmt.PaillierN
	nh := stmt.VerifierAux.N
	alpha, err := sampleSignedSecret(rng, params.EncRange())
	if err != nil {
		return nil, err
	}
	defer alpha.Destroy()
	r, err := sampleZNStarSecret(rng, n.N)
	if err != nil {
		return nil, err
	}
	defer r.Destroy()
	m, err := sampleMultRangeSecret(rng, params.Ell, nh)
	if err != nil {
		return nil, err
	}
	defer m.Destroy()
	gamma, err := sampleMultRangeSecret(rng, params.EncRange(), nh)
	if err != nil {
		return nil, err
	}
	defer gamma.Destroy()
	aC, err := OMulCT(n, alpha, stmt.C, alpha.FixedLen())
	if err != nil {
		return nil, err
	}
	rBig, err := secretScalarBig(r)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rBig)
	zero, err := EncRandom(n, big.NewInt(0), rBig)
	if err != nil {
		return nil, err
	}
	A, err := OAdd(n, aC, zero)
	if err != nil {
		return nil, err
	}
	aScalar, err := signedSecretSecpScalar(alpha)
	if err != nil {
		return nil, err
	}
	Bx := secp.ScalarMult(stmt.B, aScalar)
	commitLen := max(signedPowerOfTwoBytes(params.Ell), multRangeBytes(nh, params.Ell))
	xSigned, err := signedSecretFromScalar(w.X, commitLen)
	if err != nil {
		return nil, err
	}
	defer xSigned.Destroy()
	mp, err := resizeSignedSecret(m, commitLen)
	if err != nil {
		return nil, err
	}
	defer mp.Destroy()
	S, err := RPCommitCT(stmt.VerifierAux, xSigned, mp, commitLen)
	if err != nil {
		return nil, err
	}
	maskLen := max(signedPowerOfTwoBytes(params.EncRange()), multRangeBytes(nh, params.EncRange()))
	ap, err := resizeSignedSecret(alpha, maskLen)
	if err != nil {
		return nil, err
	}
	defer ap.Destroy()
	gp, err := resizeSignedSecret(gamma, maskLen)
	if err != nil {
		return nil, err
	}
	defer gp.Destroy()
	E, err := RPCommitCT(stmt.VerifierAux, ap, gp, maskLen)
	if err != nil {
		return nil, err
	}
	tr, err := buildMulStarTranscript(params, state, stmt, A, Bx, S, E)
	if err != nil {
		return nil, err
	}
	e, err := tr.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return nil, err
	}
	xBig, err := secretScalarBig(w.X)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(xBig)
	aBig, err := signedSecretBig(alpha)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(aBig)
	z1 := new(big.Int).Mul(e, xBig)
	z1.Add(z1, aBig)
	mBig, err := signedSecretBig(m)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(mBig)
	gBig, err := signedSecretBig(gamma)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(gBig)
	z2 := new(big.Int).Mul(e, mBig)
	z2.Add(z2, gBig)
	wResp, err := publicChallengeRandomnessResponse(r, w.Rho, e, n.N)
	if err != nil {
		return nil, err
	}
	return &MulStarProof{A: A, Bx: Bx, S: S, E: E, Z1: z1, Z2: z2, W: wResp, TranscriptHash: tr.Sum()}, nil
}

// VerifyMulStar verifies a Πmul* proof.
func VerifyMulStar(params SecurityParams, state []byte, stmt MulStarStatement, p *MulStarProof) error {
	if err := validateMulStarPublic(params, stmt); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	n := stmt.PaillierN
	nh := stmt.VerifierAux.N
	if _, err := RequireZN2Star(p.A, n.N); err != nil {
		return err
	}
	if _, err := RequireZNStar(p.W, n.N); err != nil {
		return err
	}
	if _, err := RequireZNStar(p.S, nh); err != nil {
		return err
	}
	if _, err := RequireZNStar(p.E, nh); err != nil {
		return err
	}
	if !InSignedPowerOfTwo(p.Z1, params.EncRange()+1) {
		return errors.New("MulStarProof: z1 out of range")
	}
	if !inMultRange(p.Z2, nh, params.EncRange()+1) {
		return errors.New("MulStarProof: z2 out of range")
	}
	tr, err := buildMulStarTranscript(params, state, stmt, p.A, p.Bx, p.S, p.E)
	if err != nil {
		return err
	}
	if !bytes.Equal(tr.Sum(), p.TranscriptHash) {
		return errors.New("MulStarProof: transcript hash mismatch")
	}
	e, err := tr.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return err
	}
	left, err := OMulPublic(n, p.Z1, stmt.C)
	if err != nil {
		return err
	}
	zero, err := EncRandom(n, big.NewInt(0), p.W)
	if err != nil {
		return err
	}
	left, err = OAdd(n, left, zero)
	if err != nil {
		return err
	}
	de, err := OMulPublic(n, e, stmt.D)
	if err != nil {
		return err
	}
	right, err := OAdd(n, p.A, de)
	if err != nil {
		return err
	}
	if left.Cmp(right) != 0 {
		return errors.New("MulStarProof: Paillier equation failed")
	}
	lp := secp.ScalarMult(stmt.B, secp.ScalarFromBigInt(p.Z1))
	rp := secp.Add(p.Bx, secp.ScalarMult(stmt.X, secp.ScalarFromBigInt(e)))
	if !secp.Equal(lp, rp) {
		return errors.New("MulStarProof: curve equation failed")
	}
	lr, err := RPCommit(stmt.VerifierAux, p.Z1, p.Z2)
	if err != nil {
		return err
	}
	se, err := ExpSignedMod(p.S, e, nh)
	if err != nil {
		return err
	}
	rr := new(big.Int).Mul(p.E, se)
	rr.Mod(rr, nh)
	if lr.Cmp(rr) != 0 {
		return errors.New("MulStarProof: Ring-Pedersen equation failed")
	}
	return nil
}

func validateMulStarPublic(params SecurityParams, stmt MulStarStatement) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if stmt.PaillierN == nil || stmt.C == nil || stmt.D == nil || stmt.X == nil || stmt.B == nil {
		return errors.New("MulStarProof: incomplete statement")
	}
	if err := stmt.PaillierN.Validate(); err != nil {
		return err
	}
	if err := params.CheckPaillierModulus(stmt.PaillierN); err != nil {
		return err
	}
	if err := validateRPParamsForProof(params, stmt.VerifierAux); err != nil {
		return err
	}
	if err := validateAuxModulusDistinct(stmt.VerifierAux, stmt.PaillierN); err != nil {
		return err
	}
	if _, err := RequireZN2Star(stmt.C, stmt.PaillierN.N); err != nil {
		return err
	}
	if _, err := RequireZN2Star(stmt.D, stmt.PaillierN.N); err != nil {
		return err
	}
	return nil
}
func validateMulStarStatement(params SecurityParams, stmt MulStarStatement, w MulStarWitness) error {
	if err := validateMulStarPublic(params, stmt); err != nil {
		return err
	}
	if w.X == nil || w.Rho == nil {
		return errors.New("MulStarProof: incomplete witness")
	}
	xs, err := signedSecretFromScalar(w.X, max(w.X.FixedLen(), signedPowerOfTwoBytes(params.Ell)))
	if err != nil {
		return err
	}
	defer xs.Destroy()
	cx, err := OMulCT(stmt.PaillierN, xs, stmt.C, xs.FixedLen())
	if err != nil {
		return err
	}
	rho, err := secretScalarBig(w.Rho)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(rho)
	zero, err := EncRandom(stmt.PaillierN, big.NewInt(0), rho)
	if err != nil {
		return err
	}
	want, err := OAdd(stmt.PaillierN, cx, zero)
	if err != nil || want.Cmp(stmt.D) != 0 {
		return errors.New("MulStarProof: Paillier witness mismatch")
	}
	xBig, err := secretScalarBig(w.X)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(xBig)
	if !secp.Equal(secp.ScalarMult(stmt.B, secp.ScalarFromBigInt(xBig)), stmt.X) {
		return errors.New("MulStarProof: curve witness mismatch")
	}
	return nil
}
func buildMulStarTranscript(params SecurityParams, state []byte, stmt MulStarStatement, A *big.Int, Bx *secp.Point, S, E *big.Int) (*Transcript, error) {
	t := NewTranscript("cggmp21-paillier-mulstar-proof-v1")
	appendSecurityParams(t, params)
	t.AppendBytes("state", state)
	for _, v := range []struct {
		l string
		x *big.Int
	}{{"N", stmt.PaillierN.N}, {"C", stmt.C}, {"D", stmt.D}, {"Nhat", stmt.VerifierAux.N}, {"s", stmt.VerifierAux.S}, {"t", stmt.VerifierAux.T}, {"A", A}, {"S", S}, {"E", E}} {
		if err := t.AppendBigInt(v.l, v.x); err != nil {
			return nil, err
		}
	}
	if err := t.AppendPoint("X", stmt.X); err != nil {
		return nil, err
	}
	if err := t.AppendPoint("B", stmt.B); err != nil {
		return nil, err
	}
	if err := t.AppendPoint("Bx", Bx); err != nil {
		return nil, err
	}
	return t, nil
}

func publicChallengeRandomnessResponse(mask, witness *secret.Scalar, e, modulus *big.Int) (*big.Int, error) {
	m, err := secretScalarBig(mask)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(m)
	w, err := secretScalarBig(witness)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(w)
	// e is the public Fiat-Shamir challenge. Route the operation through the
	// audited public-exponent helper so secret-exponent call-site checks remain
	// closed by default.
	we, err := ExpSignedMod(w, e, modulus)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(we)
	out := new(big.Int).Mul(m, we)
	out.Mod(out, modulus)
	return out, nil
}
