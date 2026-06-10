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

const logStarProofVersion = 1

const logStarProofWireType = "zk.paillier.logstar-proof"

const (
	logStarProofFieldVersion uint16 = iota + 1
	logStarProofFieldS
	logStarProofFieldA
	logStarProofFieldY
	logStarProofFieldD
	logStarProofFieldZ1
	logStarProofFieldZ2
	logStarProofFieldZ3
	logStarProofFieldTranscriptHash
)

// LogStarStatement is the public input for a Πlog* proof: the Paillier
// ciphertext, the curve points X = x*B and B, and the verifier's
// Ring-Pedersen auxiliary parameters.
type LogStarStatement struct {
	PaillierN   *pai.PublicKey
	C           *big.Int    // C = Enc_N(x; rho)
	X           *secp.Point // X = x * B
	B           *secp.Point // base point (usually G)
	VerifierAux RingPedersenParams
}

// LogStarWitness is the secret witness for a Πlog* proof.
type LogStarWitness struct {
	X   *big.Int // scalar
	Rho *big.Int // Paillier encryption randomness
}

// LogStarProof is a CGGMP-compatible Πlog* proof that a Paillier ciphertext
// and a curve point share the same discrete logarithm, with the scalar in the
// configured range.
type LogStarProof struct {
	Version uint16

	S *big.Int    // RP: s_j^x * t_j^m mod N_j
	A *big.Int    // Enc_N(alpha; r)
	Y *secp.Point // alpha * B
	D *big.Int    // RP: s_j^alpha * t_j^gamma mod N_j

	Z1 *big.Int // alpha + e*x
	Z2 *big.Int // r * rho^e mod N
	Z3 *big.Int // gamma + e*m

	TranscriptHash []byte
}

// ProveLogStar creates a Πlog* proof.
func ProveLogStar(params SecurityParams, state []byte, stmt LogStarStatement, w LogStarWitness, rng io.Reader) (*LogStarProof, error) {
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
	alpha, err := SampleSignedPowerOfTwo(rng, params.EncRange()) // ±2^(Ell+Epsilon)
	if err != nil {
		return nil, err
	}
	r, err := SampleZNStar(rng, N.N)
	if err != nil {
		return nil, err
	}
	mask, err := SampleMultRange(rng, params.Ell, Nj) // ±(2^Ell * Nj)
	if err != nil {
		return nil, err
	}
	gamma, err := SampleMultRange(rng, params.EncRange(), Nj) // ±(2^(Ell+Epsilon) * Nj)
	if err != nil {
		return nil, err
	}

	// Commitments.
	secretCommitLen := max(signedPowerOfTwoBytes(params.Ell), multRangeBytes(Nj, params.Ell))
	S, err := RPCommitCT(stmt.VerifierAux, w.X, mask, secretCommitLen)
	if err != nil {
		return nil, err
	}
	A, err := EncRandom(N, alpha, r)
	if err != nil {
		return nil, err
	}
	Y := secp.ScalarMult(stmt.B, secp.ScalarFromBigInt(alpha))
	maskCommitLen := max(signedPowerOfTwoBytes(params.EncRange()), multRangeBytes(Nj, params.EncRange()))
	D, err := RPCommitCT(stmt.VerifierAux, alpha, gamma, maskCommitLen)
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
	z1 := new(big.Int).Mul(e, w.X)
	z1.Add(z1, alpha)

	rhoExp := new(big.Int).Exp(w.Rho, e, N.N)
	z2 := new(big.Int).Mul(r, rhoExp)
	z2.Mod(z2, N.N)

	z3 := new(big.Int).Mul(e, mask)
	z3.Add(z3, gamma)

	return &LogStarProof{
		Version:        logStarProofVersion,
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
	if proof == nil {
		return errors.New("nil LogStarProof")
	}
	if proof.Version != logStarProofVersion {
		return fmt.Errorf("unsupported LogStarProof version %d", proof.Version)
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
	if err := validateRPParamsForCommit(stmt.VerifierAux); err != nil {
		return fmt.Errorf("LogStarProof: invalid verifier aux: %w", err)
	}

	if _, err := RequireZNStar(proof.S, Nj); err != nil {
		return fmt.Errorf("LogStarProof: S not in Z*_Nj: %w", err)
	}
	if _, err := RequireZN2Star(proof.A, N.N); err != nil {
		return fmt.Errorf("LogStarProof: A not in Z*_N^2: %w", err)
	}
	if proof.Y == nil {
		return errors.New("LogStarProof: nil Y")
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
	if len(proof.TranscriptHash) != sha256.Size || !bytes.Equal(transcript.Sum(), proof.TranscriptHash) {
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

// logStarProofWire is the wire DTO for LogStarProof.
type logStarProofWire struct {
	Version        uint16         `wire:"1,u16"`
	S              *big.Int       `wire:"2,bigpos,max_bytes=paillier_modulus"`
	A              *big.Int       `wire:"3,bigpos,max_bytes=paillier_modulus"`
	Y              secp.WirePoint `wire:"4,custom,max_bytes=point"`
	D              *big.Int       `wire:"5,bigpos,max_bytes=paillier_modulus"`
	Z1             *big.Int       `wire:"6,bigint,max_bytes=signed_response"`
	Z2             *big.Int       `wire:"7,bigpos,max_bytes=paillier_signed"`
	Z3             *big.Int       `wire:"8,bigint,max_bytes=signed_response"`
	TranscriptHash []byte         `wire:"9,bytes"`
}

// WireType returns the canonical wire type identifier for logStarProofWire.
func (logStarProofWire) WireType() string { return logStarProofWireType }

// WireVersion returns the wire format version for logStarProofWire.
func (logStarProofWire) WireVersion() uint16 { return logStarProofVersion }

// MarshalBinary encodes the LogStarProof using the object-level wire codec.
func (p *LogStarProof) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil LogStarProof")
	}
	return wire.Marshal(logStarProofWire{
		Version:        p.Version,
		S:              p.S,
		A:              p.A,
		Y:              secp.WirePoint{P: p.Y},
		D:              p.D,
		Z1:             p.Z1,
		Z2:             p.Z2,
		Z3:             p.Z3,
		TranscriptHash: p.TranscriptHash,
	}, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalLogStarProof decodes a canonical TLV LogStarProof.
func UnmarshalLogStarProof(in []byte) (*LogStarProof, error) {
	var w logStarProofWire
	if err := wire.Unmarshal(in, &w, wire.WithFieldLimits(zkFieldLimits())); err != nil {
		return nil, err
	}
	if w.Version != logStarProofVersion {
		return nil, fmt.Errorf("unsupported LogStarProof version %d", w.Version)
	}
	return &LogStarProof{
		Version:        w.Version,
		S:              w.S,
		A:              w.A,
		Y:              w.Y.P,
		D:              w.D,
		Z1:             w.Z1,
		Z2:             w.Z2,
		Z3:             w.Z3,
		TranscriptHash: w.TranscriptHash,
	}, nil
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
	if err := validateRPParamsForCommit(stmt.VerifierAux); err != nil {
		return fmt.Errorf("invalid verifier aux: %w", err)
	}
	if w.X == nil || w.Rho == nil {
		return errors.New("nil witness field")
	}
	if !InSignedPowerOfTwo(w.X, params.Ell) {
		return errors.New("witness x out of range")
	}
	if !IsZNStar(w.Rho, stmt.PaillierN.N) {
		return errors.New("witness rho not in Z*_N")
	}

	// Verify C == Enc_N(x; rho).
	expectedC, err := EncRandom(stmt.PaillierN, w.X, w.Rho)
	if err != nil {
		return fmt.Errorf("cannot verify ciphertext: %w", err)
	}
	if expectedC.Cmp(stmt.C) != 0 {
		return errors.New("witness does not open ciphertext")
	}

	// Verify X == x * B.
	expectedX := secp.ScalarMult(stmt.B, secp.ScalarFromBigInt(w.X))
	if !secp.Equal(stmt.X, expectedX) {
		return errors.New("witness x does not open X")
	}

	return nil
}

func buildLogStarTranscript(params SecurityParams, state []byte, stmt LogStarStatement, S, A *big.Int, Y *secp.Point, D *big.Int) (*Transcript, error) {
	t := NewTranscript("cggmp-paillier-zk")
	t.AppendBytes("curve", []byte("secp256k1"))
	t.AppendBytes("proof", []byte("logstar"))
	t.AppendUint16("version", 1)
	t.AppendUint32("ell", uint32(params.Ell))
	t.AppendUint32("epsilon", uint32(params.Epsilon))
	t.AppendUint32("challenge_bits", uint32(params.ChallengeBits))
	t.AppendBytes("state", state)

	// Statement.
	t.AppendBigInt("paillier_N", stmt.PaillierN.N)
	njLen := modulusBytes(stmt.VerifierAux.N)
	t.AppendBytes("verifier_N", fixedModNBytes(stmt.VerifierAux.N, njLen))
	t.AppendBytes("verifier_S", fixedModNBytes(stmt.VerifierAux.S, njLen))
	t.AppendBytes("verifier_T", fixedModNBytes(stmt.VerifierAux.T, njLen))
	t.AppendBigInt("C", stmt.C)
	if err := t.AppendPoint("X", stmt.X); err != nil {
		return nil, err
	}
	if err := t.AppendPoint("B", stmt.B); err != nil {
		return nil, err
	}

	// Commitments.
	t.AppendBigInt("S", S)
	t.AppendBigInt("A", A)
	if err := t.AppendPoint("Y", Y); err != nil {
		return nil, err
	}
	t.AppendBigInt("D", D)

	return t, nil
}
