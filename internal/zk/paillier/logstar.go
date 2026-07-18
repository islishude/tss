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
	"github.com/islishude/tss/internal/clone"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const logStarProofVersion = 1

const logStarProofType = "zk.paillier.logstar-proof"

// LogStarStatement is the public input for a Πlog* proof: the Paillier
// ciphertext, the curve points X = x*B and B, and the verifier's
// Ring-Pedersen auxiliary parameters.
type LogStarStatement struct {
	PaillierN   *pai.PublicKey
	C           *big.Int    // C = Enc_N(x; rho)
	X           *secp.Point // X = x * B
	B           *secp.Point // base point (usually G)
	VerifierAux *RingPedersenParams
}

// LogStarWitness is the secret witness for a Πlog* proof.
type LogStarWitness struct {
	X   *secret.Scalar // scalar
	Rho *secret.Scalar // Paillier encryption randomness
}

// LogStarProof is a CGGMP-compatible Πlog* proof that a Paillier ciphertext
// and a curve point share the same discrete logarithm, with the scalar in the
// configured range.
type LogStarProof struct {
	S *big.Int    `wire:"1,bigpos,max_bytes=paillier_modulus"` // RP: s_j^x * t_j^m mod N_j
	A *big.Int    `wire:"2,bigpos,max_bytes=paillier_modulus"` // Enc_N(alpha; r)
	Y *secp.Point `wire:"3,custom,max_bytes=point"`            // alpha * B
	D *big.Int    `wire:"4,bigpos,max_bytes=paillier_modulus"` // RP: s_j^alpha * t_j^gamma mod N_j

	Z1 *big.Int `wire:"5,bigint,max_bytes=signed_response"` // alpha + e*x
	Z2 *big.Int `wire:"6,bigpos,max_bytes=paillier_signed"` // r * rho^e mod N
	Z3 *big.Int `wire:"7,bigint,max_bytes=signed_response"` // gamma + e*m

	TranscriptHash []byte `wire:"8,bytes"`
}

// WireType returns the canonical wire type identifier for LogStarProof.
func (LogStarProof) WireType() string { return logStarProofType }

// WireVersion returns the wire format version for LogStarProof.
func (LogStarProof) WireVersion() uint16 { return logStarProofVersion }

// Clone returns a deep copy of the LogStarProof.
func (p *LogStarProof) Clone() *LogStarProof {
	if p == nil {
		return nil
	}
	return &LogStarProof{
		S:              clone.BigInt(p.S),
		A:              clone.BigInt(p.A),
		Y:              secp.Clone(p.Y),
		D:              clone.BigInt(p.D),
		Z1:             clone.BigInt(p.Z1),
		Z2:             clone.BigInt(p.Z2),
		Z3:             clone.BigInt(p.Z3),
		TranscriptHash: bytes.Clone(p.TranscriptHash),
	}
}

// Validate checks that the LogStarProof is structurally complete.
func (p *LogStarProof) Validate() error {
	if p == nil {
		return errors.New("nil LogStarProof")
	}
	if p.S == nil || p.A == nil || p.Y == nil || p.D == nil || p.Z1 == nil || p.Z2 == nil || p.Z3 == nil {
		return errors.New("incomplete LogStarProof")
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("invalid LogStarProof transcript hash")
	}
	return nil
}

// Destroy clears witness-derived integer material retained by the proof.
func (p *LogStarProof) Destroy() {
	if p == nil {
		return
	}
	secret.ClearBigInt(p.S)
	secret.ClearBigInt(p.A)
	secret.ClearBigInt(p.D)
	secret.ClearBigInt(p.Z1)
	secret.ClearBigInt(p.Z2)
	secret.ClearBigInt(p.Z3)
	clear(p.TranscriptHash)
	*p = LogStarProof{}
}

// ProveLogStar creates a Πlog* proof.
func ProveLogStar(params SecurityParams, state []byte, stmt LogStarStatement, w LogStarWitness, rng io.Reader) (*LogStarProof, error) {
	return proveLogStarOnce(params, state, stmt, w, rng)
}

func proveLogStarOnce(params SecurityParams, state []byte, stmt LogStarStatement, w LogStarWitness, rng io.Reader) (*LogStarProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if err := validateLogStarStatement(params, stmt, w); err != nil {
		return nil, err
	}

	N := stmt.PaillierN
	Nj := stmt.VerifierAux.N

	// Sample masks.
	alpha, err := sampleSignedSecret(rng, params.EncRange()) // ±2^(Ell+Epsilon)
	if err != nil {
		return nil, err
	}
	defer alpha.Destroy()
	r, err := sampleZNStarSecret(rng, N.N)
	if err != nil {
		return nil, err
	}
	defer r.Destroy()
	mask, err := sampleMultRangeSecret(rng, params.Ell, Nj) // ±(2^Ell * Nj)
	if err != nil {
		return nil, err
	}
	defer mask.Destroy()
	gamma, err := sampleMultRangeSecret(rng, params.EncRange(), Nj) // ±(2^(Ell+Epsilon) * Nj)
	if err != nil {
		return nil, err
	}
	defer gamma.Destroy()

	// Commitments.
	secretCommitLen := max(signedPowerOfTwoBytes(params.Ell), multRangeBytes(Nj, params.Ell))
	xSigned, err := signedSecretFromScalar(w.X, secretCommitLen)
	if err != nil {
		return nil, err
	}
	defer xSigned.Destroy()
	maskPadded, err := resizeSignedSecret(mask, secretCommitLen)
	if err != nil {
		return nil, err
	}
	defer maskPadded.Destroy()
	S, err := RPCommitCT(stmt.VerifierAux, xSigned, maskPadded, secretCommitLen)
	if err != nil {
		return nil, err
	}
	A, err := encRandomSecrets(N, alpha, r)
	if err != nil {
		return nil, err
	}
	alphaScalar, err := signedSecretSecpScalar(alpha)
	if err != nil {
		return nil, err
	}
	Y := secp.ScalarMult(stmt.B, alphaScalar)
	maskCommitLen := max(signedPowerOfTwoBytes(params.EncRange()), multRangeBytes(Nj, params.EncRange()))
	alphaPadded, err := resizeSignedSecret(alpha, maskCommitLen)
	if err != nil {
		return nil, err
	}
	defer alphaPadded.Destroy()
	gammaPadded, err := resizeSignedSecret(gamma, maskCommitLen)
	if err != nil {
		return nil, err
	}
	defer gammaPadded.Destroy()
	D, err := RPCommitCT(stmt.VerifierAux, alphaPadded, gammaPadded, maskCommitLen)
	if err != nil {
		return nil, err
	}

	// Transcript and challenge.
	transcript, err := buildLogStarTranscript(params, state, stmt, S, A, Y, D)
	if err != nil {
		return nil, err
	}
	e, err := transcript.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return nil, err
	}

	// Responses.
	xBig, err := secretScalarBig(w.X)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(xBig)
	alphaBig, err := signedSecretBig(alpha)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(alphaBig)
	z1 := new(big.Int).Mul(e, xBig)
	z1.Add(z1, alphaBig)

	rhoBig, err := secretScalarBig(w.Rho)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rhoBig)
	rBig, err := secretScalarBig(r)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rBig)
	rhoExp := new(big.Int).Exp(rhoBig, e, N.N)
	defer secret.ClearBigInt(rhoExp)
	z2 := new(big.Int).Mul(rBig, rhoExp)
	z2.Mod(z2, N.N)

	maskBig, err := signedSecretBig(mask)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(maskBig)
	gammaBig, err := signedSecretBig(gamma)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(gammaBig)
	z3 := new(big.Int).Mul(e, maskBig)
	z3.Add(z3, gammaBig)

	return &LogStarProof{
		S:              new(big.Int).Set(S),
		A:              new(big.Int).Set(A),
		Y:              Y,
		D:              new(big.Int).Set(D),
		Z1:             new(big.Int).Set(z1),
		Z2:             new(big.Int).Set(z2),
		Z3:             new(big.Int).Set(z3),
		TranscriptHash: transcript.Sum(),
	}, nil
}

// VerifyLogStar checks a Πlog* proof. Returns nil on success or an error.
func VerifyLogStar(params SecurityParams, state []byte, stmt LogStarStatement, proof *LogStarProof) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	if err := validateRPParamsForProof(params, stmt.VerifierAux); err != nil {
		return fmt.Errorf("LogStarProof: invalid verifier aux: %w", err)
	}
	if err := validateAuxModulusDistinct(stmt.VerifierAux, stmt.PaillierN); err != nil {
		return fmt.Errorf("LogStarProof: invalid verifier aux: %w", err)
	}

	N := stmt.PaillierN
	Nj := stmt.VerifierAux.N

	// Structural checks.
	if err := params.CheckPaillierModulus(N); err != nil {
		return err
	}
	if _, err := RequireZN2Star(stmt.C, N.N); err != nil {
		return fmt.Errorf("LogStarProof: C not in Z*_N^2: %w", err)
	}
	if stmt.X == nil || stmt.B == nil {
		return errors.New("LogStarProof: nil curve point")
	}
	if _, err := RequireZNStar(proof.S, Nj); err != nil {
		return fmt.Errorf("LogStarProof: S not in Z*_Nj: %w", err)
	}
	if _, err := RequireZN2Star(proof.A, N.N); err != nil {
		return fmt.Errorf("LogStarProof: A not in Z*_N^2: %w", err)
	}
	if _, err := RequireZNStar(proof.D, Nj); err != nil {
		return fmt.Errorf("LogStarProof: D not in Z*_Nj: %w", err)
	}
	if _, err := RequireZNStar(proof.Z2, N.N); err != nil {
		return fmt.Errorf("LogStarProof: z2 not in Z*_N: %w", err)
	}

	// Range checks BEFORE algebraic equations.
	if !InSignedPowerOfTwo(proof.Z1, params.EncRange()+1) {
		return fmt.Errorf("LogStarProof: z1 out of range ±2^%d", params.EncRange()+1)
	}
	if !inMultRange(proof.Z3, Nj, params.EncRange()+1) {
		return errors.New("LogStarProof: z3 out of range")
	}

	// Recompute challenge.
	transcript, err := buildLogStarTranscript(params, state, stmt, proof.S, proof.A, proof.Y, proof.D)
	if err != nil {
		return err
	}
	if !bytes.Equal(transcript.Sum(), proof.TranscriptHash) {
		return errors.New("LogStarProof: transcript hash mismatch")
	}
	e, err := transcript.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return err
	}

	// Equation 1: A ⊕ (e ⊙ C) == Enc_N(z1; z2).
	eMulC, err := OMulPublic(N, e, stmt.C)
	if err != nil {
		return fmt.Errorf("LogStarProof: e ⊙ C: %w", err)
	}
	left1, err := OAdd(N, proof.A, eMulC)
	if err != nil {
		return fmt.Errorf("LogStarProof: A ⊕ (e ⊙ C): %w", err)
	}
	encZ1, err := EncRandom(N, proof.Z1, proof.Z2)
	if err != nil {
		return fmt.Errorf("LogStarProof: Enc(z1; z2): %w", err)
	}
	if left1.Cmp(encZ1) != 0 {
		return errors.New("LogStarProof: equation 1 failed")
	}

	// Equation 2: z1 * B == Y + e * X.
	left2 := secp.ScalarMult(stmt.B, secp.ScalarFromBigInt(proof.Z1))
	right2 := secp.Add(proof.Y, secp.ScalarMult(stmt.X, secp.ScalarFromBigInt(e)))
	if !secp.Equal(left2, right2) {
		return errors.New("LogStarProof: equation 2 failed")
	}

	// Equation 3: s_j^z1 * t_j^z3 == D * S^e mod N_j.
	left3, err := RPCommit(stmt.VerifierAux, proof.Z1, proof.Z3)
	if err != nil {
		return fmt.Errorf("LogStarProof: RP(z1,z3): %w", err)
	}
	se, err := ExpSignedMod(proof.S, e, Nj)
	if err != nil {
		return fmt.Errorf("LogStarProof: S^e: %w", err)
	}
	right3 := new(big.Int).Mul(proof.D, se)
	right3.Mod(right3, Nj)
	if left3.Cmp(right3) != 0 {
		return errors.New("LogStarProof: equation 3 failed")
	}

	return nil
}

// MarshalBinary encodes the LogStarProof using the object-level wire codec.
func (p *LogStarProof) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil LogStarProof")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// MarshalWireValue encodes the LogStarProof as a canonical TLV value for
// custom wire fields.
func (p *LogStarProof) MarshalWireValue() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil LogStarProof")
	}
	return p.MarshalBinary()
}

// UnmarshalBinary decodes a canonical TLV LogStarProof.
func (p *LogStarProof) UnmarshalBinary(in []byte) error {
	var decoded LogStarProof
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(zkFrameLimits(tss.DefaultMaxZKProofBytes)),
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

// UnmarshalWireValue decodes the LogStarProof from a canonical custom wire
// field value.
func (p *LogStarProof) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil LogStarProof")
	}
	return p.UnmarshalBinary(in)
}

func validateLogStarStatement(params SecurityParams, stmt LogStarStatement, w LogStarWitness) error {
	if stmt.PaillierN == nil {
		return errors.New("nil Paillier key")
	}
	if err := stmt.PaillierN.Validate(); err != nil {
		return err
	}
	if err := params.CheckPaillierModulus(stmt.PaillierN); err != nil {
		return err
	}
	if stmt.C == nil || stmt.X == nil || stmt.B == nil {
		return errors.New("nil statement field")
	}
	if err := stmt.PaillierN.ValidateCiphertext(stmt.C); err != nil {
		return fmt.Errorf("invalid C: %w", err)
	}
	if err := validateRPParamsForProof(params, stmt.VerifierAux); err != nil {
		return fmt.Errorf("invalid verifier aux: %w", err)
	}
	if err := validateAuxModulusDistinct(stmt.VerifierAux, stmt.PaillierN); err != nil {
		return fmt.Errorf("invalid verifier aux: %w", err)
	}
	if w.X == nil || w.Rho == nil {
		return errors.New("nil witness field")
	}
	if w.X.FixedLen() != secp.ScalarSize {
		return errors.New("witness x has invalid width")
	}
	xBytes := w.X.FixedBytes()
	if _, err := secp.ScalarFromBytesAllowZero(xBytes); err != nil {
		clear(xBytes)
		return errors.New("witness x is not canonical")
	}
	clear(xBytes)
	if w.Rho.FixedLen() != modulusBytes(stmt.PaillierN.N) {
		return errors.New("witness rho has invalid width")
	}
	x, err := secretScalarBig(w.X)
	if err != nil {
		return errors.New("invalid witness x")
	}
	defer secret.ClearBigInt(x)
	if !InUnsignedPowerOfTwo(x, params.Ell) {
		return errors.New("witness x out of range")
	}
	rho, err := secretScalarBig(w.Rho)
	if err != nil {
		return errors.New("invalid witness rho")
	}
	defer secret.ClearBigInt(rho)
	if !IsZNStar(rho, stmt.PaillierN.N) {
		return errors.New("witness rho not in Z*_N")
	}

	// Verify C == Enc_N(x; rho).
	expectedC, err := stmt.PaillierN.EncryptWithSecretRandomness(w.X, w.Rho)
	if err != nil {
		return fmt.Errorf("cannot verify ciphertext: %w", err)
	}
	if expectedC.Cmp(stmt.C) != 0 {
		return errors.New("witness does not open ciphertext")
	}

	// Verify X == x * B.
	xBytes = w.X.FixedBytes()
	defer clear(xBytes)
	xScalar, err := secp.ScalarFromBytesAllowZero(xBytes)
	if err != nil {
		return errors.New("invalid witness x scalar")
	}
	expectedX := secp.ScalarMult(stmt.B, xScalar)
	if !secp.Equal(stmt.X, expectedX) {
		return errors.New("witness x does not open X")
	}

	return nil
}

func buildLogStarTranscript(params SecurityParams, state []byte, stmt LogStarStatement, S, A *big.Int, Y *secp.Point, D *big.Int) (*Transcript, error) {
	if stmt.PaillierN == nil {
		return nil, errors.New("LogStarProof transcript: nil Paillier key")
	}
	t := NewTranscript("cggmp-paillier-zk")
	t.AppendBytes("curve", []byte("secp256k1"))
	t.AppendBytes("proof", []byte("logstar"))
	t.AppendUint16("version", 1)
	appendSecurityParams(t, params)
	t.AppendBytes("state", state)

	// Statement.
	if err := t.AppendBigInt("paillier_N", stmt.PaillierN.N); err != nil {
		return nil, err
	}
	njLen := modulusBytes(stmt.VerifierAux.N)
	verifierN, err := fixedModNBytes(stmt.VerifierAux.N, njLen)
	if err != nil {
		return nil, fmt.Errorf("LogStarProof transcript verifier N: %w", err)
	}
	verifierS, err := fixedModNBytes(stmt.VerifierAux.S, njLen)
	if err != nil {
		return nil, fmt.Errorf("LogStarProof transcript verifier S: %w", err)
	}
	verifierT, err := fixedModNBytes(stmt.VerifierAux.T, njLen)
	if err != nil {
		return nil, fmt.Errorf("LogStarProof transcript verifier T: %w", err)
	}
	t.AppendBytes("verifier_N", verifierN)
	t.AppendBytes("verifier_S", verifierS)
	t.AppendBytes("verifier_T", verifierT)
	if err := t.AppendBigInt("C", stmt.C); err != nil {
		return nil, err
	}
	if stmt.X.Inf != 0 {
		t.AppendBytes("X", nil)
	} else if err := t.AppendPoint("X", stmt.X); err != nil {
		return nil, err
	}
	if err := t.AppendPoint("B", stmt.B); err != nil {
		return nil, err
	}

	// Commitments.
	if err := t.AppendBigInt("S", S); err != nil {
		return nil, err
	}
	if err := t.AppendBigInt("A", A); err != nil {
		return nil, err
	}
	if err := t.AppendPoint("Y", Y); err != nil {
		return nil, err
	}
	if err := t.AppendBigInt("D", D); err != nil {
		return nil, err
	}

	return t, nil
}
