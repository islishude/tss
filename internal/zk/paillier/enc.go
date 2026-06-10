package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
)

// Proof version for the new CGGMP-compatible proofs.
const encProofVersion = 1

const encProofWireType = "zk.paillier.enc-proof"

const (
	encProofFieldVersion uint16 = iota + 1
	encProofFieldS
	encProofFieldA
	encProofFieldC
	encProofFieldZ1
	encProofFieldZ2
	encProofFieldZ3
	encProofFieldTranscriptHash
)

// EncStatement is the public input for a Πenc proof: the prover's Paillier
// modulus, the ciphertext, and the verifier's Ring-Pedersen auxiliary parameters.
type EncStatement struct {
	ProverPaillierN *pai.PublicKey
	CiphertextK     *big.Int
	VerifierAux     RingPedersenParams
}

// EncWitness is the secret witness for a Πenc proof.
type EncWitness struct {
	K   *big.Int // plaintext scalar, in ±2^Ell
	Rho *big.Int // Paillier encryption randomness for K
}

// EncProof is a CGGMP-compatible Πenc proof that a Paillier ciphertext
// encrypts a plaintext in the range ±2^Ell. It uses Ring-Pedersen commitments
// and large integer masks for statistical zero-knowledge.
type EncProof struct {
	Version uint16 `wire:"1,u16"`

	S  *big.Int `wire:"2,bigpos,max_bytes=paillier_modulus"` // RP commitment: s_j^k * t_j^mu mod N_j
	A  *big.Int `wire:"3,bigpos,max_bytes=paillier_modulus"` // Paillier encryption: Enc_Ni(alpha; r)
	C  *big.Int `wire:"4,bigpos,max_bytes=paillier_modulus"` // RP commitment: s_j^alpha * t_j^gamma mod N_j
	Z1 *big.Int `wire:"5,bigint,max_bytes=signed_response"`  // alpha + e*k (signed integer)
	Z2 *big.Int `wire:"6,bigpos,max_bytes=paillier_signed"`  // r * rho^e mod N_i
	Z3 *big.Int `wire:"7,bigint,max_bytes=signed_response"`  // gamma + e*mu (signed integer)

	TranscriptHash []byte `wire:"8,bytes"`
}

// WireType returns the canonical wire type identifier for EncProof.
func (EncProof) WireType() string { return encProofWireType }

// WireVersion returns the wire format version for EncProof.
func (EncProof) WireVersion() uint16 { return encProofVersion }

// Validate checks that the EncProof is structurally complete.
func (p *EncProof) Validate() error {
	if p.Version != encProofVersion {
		return fmt.Errorf("unsupported EncProof version %d", p.Version)
	}
	if p.S == nil || p.A == nil || p.C == nil || p.Z1 == nil || p.Z2 == nil || p.Z3 == nil {
		return errors.New("incomplete EncProof")
	}
	return nil
}

// ProveEnc creates a Πenc proof that K = Enc_Ni(k; rho) encrypts a plaintext
// k in the range ±2^Ell under the prover's Paillier key, with a Ring-Pedersen
// commitment under the verifier's auxiliary parameters.
func ProveEnc(params SecurityParams, state []byte, statement EncStatement, witness EncWitness, rng io.Reader) (*EncProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if err := validateEncStatement(params, statement, witness); err != nil {
		return nil, err
	}

	Ni := statement.ProverPaillierN
	Nj := statement.VerifierAux.N

	// Sample masks.
	alpha, err := SampleSignedPowerOfTwo(rng, params.EncRange())
	if err != nil {
		return nil, err
	}
	// mu ← ±(2^Ell * N_j)
	mu, err := SampleMultRange(rng, params.Ell, Nj)
	if err != nil {
		return nil, err
	}
	r, err := SampleZNStar(rng, Ni.N)
	if err != nil {
		return nil, err
	}
	// gamma ← ±(2^(Ell + Epsilon) * N_j)
	gamma, err := SampleMultRange(rng, params.EncRange(), Nj)
	if err != nil {
		return nil, err
	}

	// Commitments.
	secretCommitLen := max(signedPowerOfTwoBytes(params.Ell), multRangeBytes(Nj, params.Ell))
	S, err := RPCommitCT(statement.VerifierAux, witness.K, mu, secretCommitLen)
	if err != nil {
		return nil, err
	}
	A, err := EncRandom(Ni, alpha, r)
	if err != nil {
		return nil, err
	}
	maskCommitLen := max(signedPowerOfTwoBytes(params.EncRange()), multRangeBytes(Nj, params.EncRange()))
	C, err := RPCommitCT(statement.VerifierAux, alpha, gamma, maskCommitLen)
	if err != nil {
		return nil, err
	}

	// Build transcript and challenge.
	transcript := buildEncTranscript(params, state, statement, S, A, C)
	e, err := transcript.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return nil, err
	}

	// Responses.
	// z1 = alpha + e*k
	z1 := new(big.Int).Mul(e, witness.K)
	z1.Add(z1, alpha)

	// z2 = r * rho^e mod N_i
	rhoExp := new(big.Int).Exp(witness.Rho, e, Ni.N)
	z2 := new(big.Int).Mul(r, rhoExp)
	z2.Mod(z2, Ni.N)

	// z3 = gamma + e*mu
	z3 := new(big.Int).Mul(e, mu)
	z3.Add(z3, gamma)

	return &EncProof{
		Version:        encProofVersion,
		S:              new(big.Int).Set(S),
		A:              new(big.Int).Set(A),
		C:              new(big.Int).Set(C),
		Z1:             z1,
		Z2:             z2,
		Z3:             z3,
		TranscriptHash: transcript.Sum(),
	}, nil
}

// VerifyEnc checks a Πenc proof. Returns nil on success or an error describing
// the verification failure.
func VerifyEnc(params SecurityParams, state []byte, statement EncStatement, proof *EncProof) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if proof == nil {
		return errors.New("nil EncProof")
	}
	if proof.Version != encProofVersion {
		return fmt.Errorf("unsupported EncProof version %d", proof.Version)
	}

	Ni := statement.ProverPaillierN
	Nj := statement.VerifierAux.N

	// Structural checks.
	if err := params.CheckPaillierModulus(Ni); err != nil {
		return err
	}
	if _, err := RequireZN2Star(statement.CiphertextK, Ni.N); err != nil {
		return fmt.Errorf("EncProof: ciphertext K not in Z*_N^2: %w", err)
	}
	if err := validateRPParamsForCommit(statement.VerifierAux); err != nil {
		return fmt.Errorf("EncProof: invalid verifier aux: %w", err)
	}
	if _, err := RequireZNStar(proof.S, Nj); err != nil {
		return fmt.Errorf("EncProof: S not in Z*_N_j: %w", err)
	}
	if _, err := RequireZN2Star(proof.A, Ni.N); err != nil {
		return fmt.Errorf("EncProof: A not in Z*_Ni^2: %w", err)
	}
	if _, err := RequireZNStar(proof.C, Nj); err != nil {
		return fmt.Errorf("EncProof: C not in Z*_N_j: %w", err)
	}
	if _, err := RequireZNStar(proof.Z2, Ni.N); err != nil {
		return fmt.Errorf("EncProof: z2 not in Z*_Ni: %w", err)
	}

	// Range checks BEFORE algebraic equations.
	// |z1| ≤ 2^(Ell+max(Epsilon,ChallengeBits)+1): mask + challenge contribution.
	if !InSignedPowerOfTwo(proof.Z1, params.EncRange()+1) {
		return fmt.Errorf("EncProof: z1 out of range ±2^%d", params.EncRange()+1)
	}
	// z3 ∈ ±(N_j * 2^(EncRange + 1))
	if !inMultRange(proof.Z3, Nj, params.EncRange()+1) {
		return errors.New("EncProof: z3 out of range")
	}

	// Recompute challenge.
	transcript := buildEncTranscript(params, state, statement, proof.S, proof.A, proof.C)
	if len(proof.TranscriptHash) != sha256.Size || !bytes.Equal(transcript.Sum(), proof.TranscriptHash) {
		return errors.New("EncProof: transcript hash mismatch")
	}
	e, err := transcript.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return err
	}

	// Verify: A ⊕ (e ⊙ K) == Enc_Ni(z1; z2).
	eMulK, err := OMulPublic(Ni, e, statement.CiphertextK)
	if err != nil {
		return fmt.Errorf("EncProof: e ⊙ K: %w", err)
	}
	leftPaillier, err := OAdd(Ni, proof.A, eMulK)
	if err != nil {
		return fmt.Errorf("EncProof: A ⊕ (e ⊙ K): %w", err)
	}
	encZ1, err := EncRandom(Ni, proof.Z1, proof.Z2)
	if err != nil {
		return fmt.Errorf("EncProof: Enc(z1; z2): %w", err)
	}
	if leftPaillier.Cmp(encZ1) != 0 {
		return errors.New("EncProof: Paillier equation failed")
	}

	// Verify: s_j^z1 * t_j^z3 == C * S^e mod N_j.
	leftRP, err := RPCommit(statement.VerifierAux, proof.Z1, proof.Z3)
	if err != nil {
		return fmt.Errorf("EncProof: RP commit(z1, z3): %w", err)
	}
	se, err := ExpSignedMod(proof.S, e, Nj)
	if err != nil {
		return fmt.Errorf("EncProof: S^e: %w", err)
	}
	rightRP := new(big.Int).Mul(proof.C, se)
	rightRP.Mod(rightRP, Nj)
	if leftRP.Cmp(rightRP) != 0 {
		return errors.New("EncProof: Ring-Pedersen equation failed")
	}

	return nil
}

// MarshalBinary encodes the EncProof using the object-level wire codec.
func (p *EncProof) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil EncProof")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalEncProof decodes a canonical TLV EncProof.
func UnmarshalEncProof(in []byte) (*EncProof, error) {
	var p EncProof
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(zkFieldLimits())); err != nil {
		return nil, err
	}
	return &p, nil
}

func validateEncStatement(params SecurityParams, stmt EncStatement, w EncWitness) error {
	if stmt.ProverPaillierN == nil {
		return errors.New("nil prover Paillier key")
	}
	if err := stmt.ProverPaillierN.Validate(); err != nil {
		return err
	}
	if err := params.CheckPaillierModulus(stmt.ProverPaillierN); err != nil {
		return err
	}
	if stmt.CiphertextK == nil {
		return errors.New("nil ciphertext K")
	}
	if err := stmt.ProverPaillierN.ValidateCiphertext(stmt.CiphertextK); err != nil {
		return fmt.Errorf("invalid ciphertext K: %w", err)
	}
	if err := validateRPParamsForCommit(stmt.VerifierAux); err != nil {
		return fmt.Errorf("invalid verifier aux: %w", err)
	}
	if w.K == nil || w.Rho == nil {
		return errors.New("nil witness")
	}
	if !InSignedPowerOfTwo(w.K, params.Ell) {
		return errors.New("witness k out of range")
	}
	if !IsZNStar(w.Rho, stmt.ProverPaillierN.N) {
		return errors.New("witness rho not in Z*_N")
	}
	// Verify K == Enc(k; rho).
	expectedK, err := EncRandom(stmt.ProverPaillierN, w.K, w.Rho)
	if err != nil {
		return fmt.Errorf("cannot verify witness encryption: %w", err)
	}
	if expectedK.Cmp(stmt.CiphertextK) != 0 {
		return errors.New("witness does not open ciphertext K")
	}
	return nil
}

func buildEncTranscript(params SecurityParams, state []byte, stmt EncStatement, S, A, C *big.Int) *Transcript {
	t := NewTranscript("cggmp-paillier-zk")
	t.AppendBytes("curve", []byte("secp256k1"))
	t.AppendBytes("proof", []byte("enc"))
	t.AppendUint16("version", 1)
	t.AppendUint32("ell", uint32(params.Ell))
	t.AppendUint32("epsilon", uint32(params.Epsilon))
	t.AppendUint32("challenge_bits", uint32(params.ChallengeBits))
	t.AppendBytes("state", state)

	// Statement.
	niBytes := stmt.ProverPaillierN.N.Bytes()
	t.AppendBytes("prover_N", niBytes)
	njLen := modulusBytes(stmt.VerifierAux.N)
	t.AppendBytes("verifier_N", fixedModNBytes(stmt.VerifierAux.N, njLen))
	t.AppendBytes("verifier_S", fixedModNBytes(stmt.VerifierAux.S, njLen))
	t.AppendBytes("verifier_T", fixedModNBytes(stmt.VerifierAux.T, njLen))
	t.AppendBigInt("K", stmt.CiphertextK)

	// Commitments.
	t.AppendBigInt("S", S)
	t.AppendBigInt("A", A)
	t.AppendBigInt("C", C)

	return t
}
