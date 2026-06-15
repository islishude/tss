package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
)

const affGProofVersion = 1

const affGProofWireType = "zk.paillier.aff-g-proof"

// AffGStatement is the public input for a Πaff-g proof: the MtA ciphertexts,
// the curve commitment, the Paillier keys of both parties, and the verifier's
// Ring-Pedersen auxiliary parameters.
type AffGStatement struct {
	// ReceiverPaillierN is the initiator's Paillier modulus (Nj).
	ReceiverPaillierN *pai.PublicKey
	// ProverPaillierN is the responder's Paillier modulus (Ni).
	ProverPaillierN *pai.PublicKey

	C *big.Int    // encA under Nj (the start ciphertext)
	D *big.Int    // D = x ⊙ C ⊕ Enc_Nj(y; rho) (the MtA response)
	Y *big.Int    // Y = Enc_Ni(y; rhoY) (responder encrypts y under own key)
	X *secp.Point // X = x * G (responder's curve commitment)

	VerifierAux RingPedersenParams // initiator's RP params (Nhat_j = Nj)
}

// AffGWitness is the secret witness for a Πaff-g proof.
type AffGWitness struct {
	X    *big.Int // affine multiplier (scalar for curve point X)
	Y    *big.Int // affine additive term
	Rho  *big.Int // randomness for Enc_Nj(y; rho) inside D
	RhoY *big.Int // randomness for Y = Enc_Ni(y; rhoY)
}

// AffGProof is a CGGMP-compatible Πaff-g proof that an MtA response was
// computed correctly: D = x ⊙ C ⊕ Enc_Nj(y; rho) with X = x*G and Y = Enc_Ni(y).
// Y is included in the proof so the verifier can check equation 3 without
// separately receiving the responder's encryption of y.
type AffGProof struct {
	Version uint16

	A  *big.Int    // (alpha ⊙ C) ⊕ Enc_Nj(beta; r)
	Bx *secp.Point // alpha * G
	By *big.Int    // Enc_Ni(beta; rY)
	E  *big.Int    // RP: s_j^alpha * t_j^gamma mod Nhat_j
	S  *big.Int    // RP: s_j^x * t_j^m mod Nhat_j
	F  *big.Int    // RP: s_j^beta * t_j^delta mod Nhat_j
	T  *big.Int    // RP: s_j^y * t_j^mu mod Nhat_j

	Y *big.Int // Enc_Ni(y; rhoY) — public, carried in proof for verifier

	Z1 *big.Int // alpha + e*x
	Z2 *big.Int // beta + e*y
	Z3 *big.Int // gamma + e*m
	Z4 *big.Int // delta + e*mu
	W  *big.Int // r * rho^e mod Nj
	WY *big.Int // rY * rhoY^e mod Ni

	TranscriptHash []byte
}

// Clone returns a deep copy of the AffGProof.
func (p *AffGProof) Clone() *AffGProof {
	if p == nil {
		return nil
	}
	cp := &AffGProof{
		Version:        p.Version,
		A:              new(big.Int).Set(p.A),
		Bx:             secp.Clone(p.Bx),
		By:             new(big.Int).Set(p.By),
		E:              new(big.Int).Set(p.E),
		S:              new(big.Int).Set(p.S),
		F:              new(big.Int).Set(p.F),
		T:              new(big.Int).Set(p.T),
		Y:              new(big.Int).Set(p.Y),
		Z1:             new(big.Int).Set(p.Z1),
		Z2:             new(big.Int).Set(p.Z2),
		Z3:             new(big.Int).Set(p.Z3),
		Z4:             new(big.Int).Set(p.Z4),
		W:              new(big.Int).Set(p.W),
		WY:             new(big.Int).Set(p.WY),
		TranscriptHash: append([]byte(nil), p.TranscriptHash...),
	}
	return cp
}

// ProveAffG creates a Πaff-g proof for the MtA response.
func ProveAffG(params SecurityParams, state []byte, stmt AffGStatement, w AffGWitness, rng io.Reader) (*AffGProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if err := validateAffGStatement(params, stmt, w); err != nil {
		return nil, err
	}

	Ni := stmt.ProverPaillierN
	Nj := stmt.ReceiverPaillierN
	Nhat := stmt.VerifierAux.N // Nhat_j = Nj

	// Sample masks.
	alpha, err := SampleSignedPowerOfTwo(rng, params.EncRange()) // ±2^(Ell+Epsilon)
	if err != nil {
		return nil, err
	}
	beta, err := SampleSignedPowerOfTwo(rng, params.AffGRange()) // ±2^(EllPrime+Epsilon)
	if err != nil {
		return nil, err
	}
	r, err := SampleZNStar(rng, Nj.N)
	if err != nil {
		return nil, err
	}
	rY, err := SampleZNStar(rng, Ni.N)
	if err != nil {
		return nil, err
	}
	gamma, err := SampleMultRange(rng, params.EncRange(), Nhat) // ±(2^(Ell+Epsilon) * Nhat)
	if err != nil {
		return nil, err
	}
	delta, err := SampleMultRange(rng, params.AffGRange(), Nhat) // ±(2^(EllPrime+Epsilon) * Nhat)
	if err != nil {
		return nil, err
	}
	mask, err := SampleMultRange(rng, params.Ell, Nhat) // ±(2^Ell * Nhat)
	if err != nil {
		return nil, err
	}
	mu, err := SampleMultRange(rng, params.Ell, Nhat) // ±(2^Ell * Nhat)
	if err != nil {
		return nil, err
	}

	// A = (alpha ⊙ C) ⊕ Enc_Nj(beta; r)
	alphaMulC, err := OMulCT(Nj, alpha, stmt.C, signedPowerOfTwoBytes(params.EncRange()))
	if err != nil {
		return nil, err
	}
	encBeta, err := EncRandom(Nj, beta, r)
	if err != nil {
		return nil, err
	}
	A, err := OAdd(Nj, alphaMulC, encBeta)
	if err != nil {
		return nil, err
	}

	// Bx = alpha * G
	Bx := secp.ScalarBaseMult(secp.ScalarFromBigInt(alpha))

	// By = Enc_Ni(beta; rY)
	By, err := EncRandom(Ni, beta, rY)
	if err != nil {
		return nil, err
	}

	// RP commitments.
	encMaskCommitLen := max(signedPowerOfTwoBytes(params.EncRange()), multRangeBytes(Nhat, params.EncRange()))
	E, err := RPCommitCT(stmt.VerifierAux, alpha, gamma, encMaskCommitLen)
	if err != nil {
		return nil, err
	}
	secretCommitLen := max(signedPowerOfTwoBytes(params.Ell), multRangeBytes(Nhat, params.Ell))
	S, err := RPCommitCT(stmt.VerifierAux, w.X, mask, secretCommitLen)
	if err != nil {
		return nil, err
	}
	affineCommitLen := max(signedPowerOfTwoBytes(params.AffGRange()), multRangeBytes(Nhat, params.AffGRange()))
	F, err := RPCommitCT(stmt.VerifierAux, beta, delta, affineCommitLen)
	if err != nil {
		return nil, err
	}
	yCommitLen := max(signedPowerOfTwoBytes(params.EllPrime), multRangeBytes(Nhat, params.Ell))
	T, err := RPCommitCT(stmt.VerifierAux, w.Y, mu, yCommitLen)
	if err != nil {
		return nil, err
	}

	// Transcript and challenge.
	transcript, err := buildAffGTranscript(params, state, stmt, stmt.Y, A, Bx, By, E, S, F, T)
	if err != nil {
		return nil, err
	}
	e, err := transcript.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return nil, err
	}

	// Responses.
	z1 := new(big.Int).Mul(e, w.X)
	z1.Add(z1, alpha)

	z2 := new(big.Int).Mul(e, w.Y)
	z2.Add(z2, beta)

	z3 := new(big.Int).Mul(e, mask)
	z3.Add(z3, gamma)

	z4 := new(big.Int).Mul(e, mu)
	z4.Add(z4, delta)

	// w = r * rho^e mod Nj.
	// math/big.Int.Exp is used here with a secret base (w.Rho, Paillier
	// randomness) but a public exponent (e, the Fiat-Shamir challenge).
	// This is acceptable because the prover generates the proof locally
	// and already owns the witness; observable timing differences in base
	// size are not exploitable by a remote verifier in the non-interactive
	// setting. The value is further masked by multiplication with the
	// fresh random r before being included in the proof.
	rhoExp := new(big.Int).Exp(w.Rho, e, Nj.N)
	wVal := new(big.Int).Mul(r, rhoExp)
	wVal.Mod(wVal, Nj.N)

	// wY = rY * rhoY^e mod Ni.
	// Same rationale as above: public exponent, prover-local computation.
	rhoYExp := new(big.Int).Exp(w.RhoY, e, Ni.N)
	wY := new(big.Int).Mul(rY, rhoYExp)
	wY.Mod(wY, Ni.N)

	return &AffGProof{
		Version:        affGProofVersion,
		A:              new(big.Int).Set(A),
		Bx:             Bx,
		By:             new(big.Int).Set(By),
		E:              new(big.Int).Set(E),
		S:              new(big.Int).Set(S),
		F:              new(big.Int).Set(F),
		T:              new(big.Int).Set(T),
		Y:              new(big.Int).Set(stmt.Y),
		Z1:             new(big.Int).Set(z1),
		Z2:             new(big.Int).Set(z2),
		Z3:             new(big.Int).Set(z3),
		Z4:             new(big.Int).Set(z4),
		W:              new(big.Int).Set(wVal),
		WY:             new(big.Int).Set(wY),
		TranscriptHash: transcript.Sum(),
	}, nil
}

// VerifyAffG checks a Πaff-g proof. Returns nil on success or an error.
func VerifyAffG(params SecurityParams, state []byte, stmt AffGStatement, proof *AffGProof) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if proof == nil {
		return errors.New("nil AffGProof")
	}
	if proof.Version != affGProofVersion {
		return fmt.Errorf("unsupported AffGProof version %d", proof.Version)
	}

	Ni := stmt.ProverPaillierN
	Nj := stmt.ReceiverPaillierN
	Nhat := stmt.VerifierAux.N

	// Structural checks.
	if err := params.CheckPaillierModulus(Ni); err != nil {
		return err
	}
	if err := params.CheckPaillierModulus(Nj); err != nil {
		return err
	}
	if _, err := RequireZN2Star(stmt.C, Nj.N); err != nil {
		return fmt.Errorf("AffGProof: C not in Z*_Nj^2: %w", err)
	}
	if _, err := RequireZN2Star(stmt.D, Nj.N); err != nil {
		return fmt.Errorf("AffGProof: D not in Z*_Nj^2: %w", err)
	}
	if _, err := RequireZN2Star(proof.Y, Ni.N); err != nil {
		return fmt.Errorf("AffGProof: Y not in Z*_Ni^2: %w", err)
	}
	// Bind the proof-carried Y to the statement Y. The statement is the
	// authenticated public input; rejecting a mismatch ensures a caller that
	// independently authenticates Y cannot accept a proof computed for a
	// different Y.
	if stmt.Y == nil {
		return errors.New("AffGProof: nil statement Y")
	}
	if stmt.Y.Cmp(proof.Y) != 0 {
		return errors.New("AffGProof: statement Y does not match proof Y")
	}
	if stmt.X == nil {
		return errors.New("AffGProof: nil X point")
	}
	if err := validateRPParamsForCommit(stmt.VerifierAux); err != nil {
		return fmt.Errorf("AffGProof: invalid verifier aux: %w", err)
	}

	// Validate proof fields.
	if _, err := RequireZN2Star(proof.A, Nj.N); err != nil {
		return fmt.Errorf("AffGProof: A not in Z*_Nj^2: %w", err)
	}
	if proof.Bx == nil {
		return errors.New("AffGProof: nil Bx")
	}
	if _, err := RequireZN2Star(proof.By, Ni.N); err != nil {
		return fmt.Errorf("AffGProof: By not in Z*_Ni^2: %w", err)
	}
	if _, err := RequireZNStar(proof.E, Nhat); err != nil {
		return fmt.Errorf("AffGProof: E not in Z*_Nhat: %w", err)
	}
	if _, err := RequireZNStar(proof.S, Nhat); err != nil {
		return fmt.Errorf("AffGProof: S not in Z*_Nhat: %w", err)
	}
	if _, err := RequireZNStar(proof.F, Nhat); err != nil {
		return fmt.Errorf("AffGProof: F not in Z*_Nhat: %w", err)
	}
	if _, err := RequireZNStar(proof.T, Nhat); err != nil {
		return fmt.Errorf("AffGProof: T not in Z*_Nhat: %w", err)
	}
	if _, err := RequireZNStar(proof.W, Nj.N); err != nil {
		return fmt.Errorf("AffGProof: w not in Z*_Nj: %w", err)
	}
	if _, err := RequireZNStar(proof.WY, Ni.N); err != nil {
		return fmt.Errorf("AffGProof: wY not in Z*_Ni: %w", err)
	}

	// Range checks BEFORE algebraic equations.
	// +1 accounts for the addition of mask and challenge*secret term.
	if !InSignedPowerOfTwo(proof.Z1, params.EncRange()+1) {
		return fmt.Errorf("AffGProof: z1 out of range ±2^%d", params.EncRange()+1)
	}
	if !InSignedPowerOfTwo(proof.Z2, params.AffGRange()+1) {
		return fmt.Errorf("AffGProof: z2 out of range ±2^%d", params.AffGRange()+1)
	}
	// z3 ∈ ±(Nhat * 2^(EncRange + 1))
	if !inMultRange(proof.Z3, Nhat, params.EncRange()+1) {
		return errors.New("AffGProof: z3 out of range")
	}
	// z4 ∈ ±(Nhat * 2^(AffGRange + 1))
	if !inMultRange(proof.Z4, Nhat, params.AffGRange()+1) {
		return errors.New("AffGProof: z4 out of range")
	}

	// Recompute challenge.
	transcript, err := buildAffGTranscript(params, state, stmt, proof.Y, proof.A, proof.Bx, proof.By, proof.E, proof.S, proof.F, proof.T)
	if err != nil {
		return err
	}
	if len(proof.TranscriptHash) != sha256.Size || !bytes.Equal(transcript.Sum(), proof.TranscriptHash) {
		return errors.New("AffGProof: transcript hash mismatch")
	}
	e, err := transcript.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return err
	}

	// Equation 1: A ⊕ (e ⊙ D) == (z1 ⊙ C) ⊕ Enc_Nj(z2; w)
	eMulD, err := OMulPublic(Nj, e, stmt.D)
	if err != nil {
		return fmt.Errorf("AffGProof: e ⊙ D: %w", err)
	}
	left1, err := OAdd(Nj, proof.A, eMulD)
	if err != nil {
		return fmt.Errorf("AffGProof: A ⊕ (e ⊙ D): %w", err)
	}
	z1MulC, err := OMulPublic(Nj, proof.Z1, stmt.C)
	if err != nil {
		return fmt.Errorf("AffGProof: z1 ⊙ C: %w", err)
	}
	encZ2, err := EncRandom(Nj, proof.Z2, proof.W)
	if err != nil {
		return fmt.Errorf("AffGProof: Enc(z2; w): %w", err)
	}
	right1, err := OAdd(Nj, z1MulC, encZ2)
	if err != nil {
		return fmt.Errorf("AffGProof: (z1 ⊙ C) ⊕ Enc(z2): %w", err)
	}
	if left1.Cmp(right1) != 0 {
		return errors.New("AffGProof: equation 1 failed")
	}

	// Equation 2: z1 * G == Bx + e * X
	left2 := secp.ScalarBaseMult(secp.ScalarFromBigInt(proof.Z1))
	right2 := secp.Add(proof.Bx, secp.ScalarMult(stmt.X, secp.ScalarFromBigInt(e)))
	if !secp.Equal(left2, right2) {
		return errors.New("AffGProof: equation 2 failed")
	}

	// Equation 3: By ⊕ (e ⊙ Y) == Enc_Ni(z2; wY)
	eMulY, err := OMulPublic(Ni, e, proof.Y)
	if err != nil {
		return fmt.Errorf("AffGProof: e ⊙ Y: %w", err)
	}
	left3, err := OAdd(Ni, proof.By, eMulY)
	if err != nil {
		return fmt.Errorf("AffGProof: By ⊕ (e ⊙ Y): %w", err)
	}
	encZ2Ni, err := EncRandom(Ni, proof.Z2, proof.WY)
	if err != nil {
		return fmt.Errorf("AffGProof: Enc_Ni(z2; wY): %w", err)
	}
	if left3.Cmp(encZ2Ni) != 0 {
		return errors.New("AffGProof: equation 3 failed")
	}

	// Equation 4: s_j^z1 * t_j^z3 == E * S^e mod Nhat
	left4, err := RPCommit(stmt.VerifierAux, proof.Z1, proof.Z3)
	if err != nil {
		return fmt.Errorf("AffGProof: RP(z1,z3): %w", err)
	}
	se, err := ExpSignedMod(proof.S, e, Nhat)
	if err != nil {
		return fmt.Errorf("AffGProof: S^e: %w", err)
	}
	right4 := new(big.Int).Mul(proof.E, se)
	right4.Mod(right4, Nhat)
	if left4.Cmp(right4) != 0 {
		return errors.New("AffGProof: equation 4 failed")
	}

	// Equation 5: s_j^z2 * t_j^z4 == F * T^e mod Nhat
	left5, err := RPCommit(stmt.VerifierAux, proof.Z2, proof.Z4)
	if err != nil {
		return fmt.Errorf("AffGProof: RP(z2,z4): %w", err)
	}
	te, err := ExpSignedMod(proof.T, e, Nhat)
	if err != nil {
		return fmt.Errorf("AffGProof: T^e: %w", err)
	}
	right5 := new(big.Int).Mul(proof.F, te)
	right5.Mod(right5, Nhat)
	if left5.Cmp(right5) != 0 {
		return errors.New("AffGProof: equation 5 failed")
	}

	return nil
}

// affGProofWire is the wire DTO for AffGProof.
type affGProofWire struct {
	Version        uint16         `wire:"1,u16"`
	A              *big.Int       `wire:"2,bigpos,max_bytes=paillier_modulus"`
	Bx             secp.WirePoint `wire:"3,custom,max_bytes=point"`
	By             *big.Int       `wire:"4,bigpos,max_bytes=paillier_modulus"`
	E              *big.Int       `wire:"5,bigpos,max_bytes=paillier_modulus"`
	S              *big.Int       `wire:"6,bigpos,max_bytes=paillier_modulus"`
	F              *big.Int       `wire:"7,bigpos,max_bytes=paillier_modulus"`
	T              *big.Int       `wire:"8,bigpos,max_bytes=paillier_modulus"`
	Y              *big.Int       `wire:"9,bigpos,max_bytes=paillier_modulus"`
	Z1             *big.Int       `wire:"10,bigint,max_bytes=signed_response"`
	Z2             *big.Int       `wire:"11,bigint,max_bytes=signed_response"`
	Z3             *big.Int       `wire:"12,bigint,max_bytes=signed_response"`
	Z4             *big.Int       `wire:"13,bigint,max_bytes=signed_response"`
	W              *big.Int       `wire:"14,bigpos,max_bytes=paillier_modulus"`
	WY             *big.Int       `wire:"15,bigpos,max_bytes=paillier_modulus"`
	TranscriptHash []byte         `wire:"16,bytes"`
}

// WireType returns the canonical wire type identifier for affGProofWire.
func (affGProofWire) WireType() string { return affGProofWireType }

// WireVersion returns the wire format version for affGProofWire.
func (affGProofWire) WireVersion() uint16 { return affGProofVersion }

// MarshalBinary encodes the AffGProof using the object-level wire codec.
func (p *AffGProof) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil AffGProof")
	}
	return wire.Marshal(affGProofWire{
		Version:        p.Version,
		A:              p.A,
		Bx:             secp.WirePoint{P: p.Bx},
		By:             p.By,
		E:              p.E,
		S:              p.S,
		F:              p.F,
		T:              p.T,
		Y:              p.Y,
		Z1:             p.Z1,
		Z2:             p.Z2,
		Z3:             p.Z3,
		Z4:             p.Z4,
		W:              p.W,
		WY:             p.WY,
		TranscriptHash: p.TranscriptHash,
	}, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalAffGProof decodes a canonical TLV AffGProof.
func UnmarshalAffGProof(in []byte) (*AffGProof, error) {
	var w affGProofWire
	if err := wire.Unmarshal(in, &w, wire.WithFieldLimits(zkFieldLimits())); err != nil {
		return nil, err
	}
	if w.Version != affGProofVersion {
		return nil, fmt.Errorf("unsupported AffGProof version %d", w.Version)
	}
	return &AffGProof{
		Version:        w.Version,
		A:              w.A,
		Bx:             w.Bx.P,
		By:             w.By,
		E:              w.E,
		S:              w.S,
		F:              w.F,
		T:              w.T,
		Y:              w.Y,
		Z1:             w.Z1,
		Z2:             w.Z2,
		Z3:             w.Z3,
		Z4:             w.Z4,
		W:              w.W,
		WY:             w.WY,
		TranscriptHash: w.TranscriptHash,
	}, nil
}

func validateAffGStatement(params SecurityParams, stmt AffGStatement, w AffGWitness) error {
	if stmt.ReceiverPaillierN == nil || stmt.ProverPaillierN == nil {
		return errors.New("nil Paillier key")
	}
	if err := stmt.ReceiverPaillierN.Validate(); err != nil {
		return fmt.Errorf("invalid receiver Paillier key: %w", err)
	}
	if err := stmt.ProverPaillierN.Validate(); err != nil {
		return fmt.Errorf("invalid prover Paillier key: %w", err)
	}
	if err := params.CheckPaillierModulus(stmt.ReceiverPaillierN); err != nil {
		return err
	}
	if err := params.CheckPaillierModulus(stmt.ProverPaillierN); err != nil {
		return err
	}
	if stmt.C == nil || stmt.D == nil || stmt.Y == nil || stmt.X == nil {
		return errors.New("nil statement field")
	}
	if err := stmt.ReceiverPaillierN.ValidateCiphertext(stmt.C); err != nil {
		return fmt.Errorf("invalid C: %w", err)
	}
	if err := stmt.ReceiverPaillierN.ValidateCiphertext(stmt.D); err != nil {
		return fmt.Errorf("invalid D: %w", err)
	}
	if err := stmt.ProverPaillierN.ValidateCiphertext(stmt.Y); err != nil {
		return fmt.Errorf("invalid Y: %w", err)
	}
	if err := validateRPParamsForCommit(stmt.VerifierAux); err != nil {
		return fmt.Errorf("invalid verifier aux: %w", err)
	}

	if w.X == nil || w.Y == nil || w.Rho == nil || w.RhoY == nil {
		return errors.New("nil witness field")
	}
	if !InSignedPowerOfTwo(w.X, params.Ell) {
		return errors.New("witness x out of range")
	}
	if !InSignedPowerOfTwo(w.Y, params.EllPrime) {
		return errors.New("witness y out of range")
	}
	if !IsZNStar(w.Rho, stmt.ReceiverPaillierN.N) {
		return errors.New("witness rho not in Z*_Nj")
	}
	if !IsZNStar(w.RhoY, stmt.ProverPaillierN.N) {
		return errors.New("witness rhoY not in Z*_Ni")
	}

	// Verify D == (x ⊙ C) ⊕ Enc_Nj(y; rho).
	xMulC, err := OMulCT(stmt.ReceiverPaillierN, w.X, stmt.C, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		return fmt.Errorf("cannot verify D: %w", err)
	}
	encY, err := EncRandom(stmt.ReceiverPaillierN, w.Y, w.Rho)
	if err != nil {
		return fmt.Errorf("cannot verify D: %w", err)
	}
	expectedD, err := OAdd(stmt.ReceiverPaillierN, xMulC, encY)
	if err != nil {
		return fmt.Errorf("cannot verify D: %w", err)
	}
	if expectedD.Cmp(stmt.D) != 0 {
		return errors.New("witness does not open D")
	}

	// Verify Y == Enc_Ni(y; rhoY).
	expectedY, err := EncRandom(stmt.ProverPaillierN, w.Y, w.RhoY)
	if err != nil {
		return fmt.Errorf("cannot verify Y: %w", err)
	}
	if expectedY.Cmp(stmt.Y) != 0 {
		return errors.New("witness does not open Y")
	}

	// Verify X == x * G.
	expectedX := secp.ScalarBaseMult(secp.ScalarFromBigInt(w.X))
	if !secp.Equal(stmt.X, expectedX) {
		return errors.New("witness x does not open X")
	}

	return nil
}

func buildAffGTranscript(params SecurityParams, state []byte, stmt AffGStatement, yVal *big.Int, A *big.Int, Bx *secp.Point, By *big.Int, E, S, F, T *big.Int) (*Transcript, error) {
	t := NewTranscript("cggmp-paillier-zk")
	t.AppendBytes("curve", []byte("secp256k1"))
	t.AppendBytes("proof", []byte("aff-g"))
	t.AppendUint16("version", 1)
	t.AppendUint32("ell", params.Ell)
	t.AppendUint32("ell_prime", params.EllPrime)
	t.AppendUint32("epsilon", params.Epsilon)
	t.AppendUint32("challenge_bits", params.ChallengeBits)
	t.AppendBytes("state", state)

	// Statement.
	t.AppendBigInt("receiver_N", stmt.ReceiverPaillierN.N)
	t.AppendBigInt("prover_N", stmt.ProverPaillierN.N)
	nhatLen := modulusBytes(stmt.VerifierAux.N)
	t.AppendBytes("verifier_N", fixedModNBytes(stmt.VerifierAux.N, nhatLen))
	t.AppendBytes("verifier_S", fixedModNBytes(stmt.VerifierAux.S, nhatLen))
	t.AppendBytes("verifier_T", fixedModNBytes(stmt.VerifierAux.T, nhatLen))
	t.AppendBigInt("C", stmt.C)
	t.AppendBigInt("D", stmt.D)
	t.AppendBigInt("Y", yVal)
	if err := t.AppendPoint("X", stmt.X); err != nil {
		return nil, err
	}

	// Commitments.
	t.AppendBigInt("A", A)
	if err := t.AppendPoint("Bx", Bx); err != nil {
		return nil, err
	}
	t.AppendBigInt("By", By)
	t.AppendBigInt("E", E)
	t.AppendBigInt("S", S)
	t.AppendBigInt("F", F)
	t.AppendBigInt("T", T)

	return t, nil
}
