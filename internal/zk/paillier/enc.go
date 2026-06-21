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
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

// Proof version for the new CGGMP-compatible proofs.
const encProofVersion = 1

const encProofType = "zk.paillier.enc-proof"

// EncStatement is the public input for a Πenc proof: the prover's Paillier
// modulus, the ciphertext, and the verifier's Ring-Pedersen auxiliary parameters.
type EncStatement struct {
	ProverPaillierN *pai.PublicKey
	CiphertextK     *big.Int
	VerifierAux     RingPedersenParams
}

// EncWitness is the secret witness for a Πenc proof.
type EncWitness struct {
	K   *secret.Scalar // plaintext scalar, in [0, 2^Ell)
	Rho *secret.Scalar // Paillier encryption randomness for K
}

// EncProof is a CGGMP-compatible Πenc proof that a Paillier ciphertext
// encrypts a plaintext in the range ±2^Ell. It uses Ring-Pedersen commitments
// and large integer masks for statistical zero-knowledge.
type EncProof struct {
	S  *big.Int `wire:"1,bigpos,max_bytes=paillier_modulus"` // RP commitment: s_j^k * t_j^mu mod N_j
	A  *big.Int `wire:"2,bigpos,max_bytes=paillier_modulus"` // Paillier encryption: Enc_Ni(alpha; r)
	C  *big.Int `wire:"3,bigpos,max_bytes=paillier_modulus"` // RP commitment: s_j^alpha * t_j^gamma mod N_j
	Z1 *big.Int `wire:"4,bigint,max_bytes=signed_response"`  // alpha + e*k (signed integer)
	Z2 *big.Int `wire:"5,bigpos,max_bytes=paillier_signed"`  // r * rho^e mod N_i
	Z3 *big.Int `wire:"6,bigint,max_bytes=signed_response"`  // gamma + e*mu (signed integer)

	TranscriptHash []byte `wire:"7,bytes"`
}

// WireType returns the canonical wire type identifier for EncProof.
func (EncProof) WireType() string { return encProofType }

// WireVersion returns the wire format version for EncProof.
func (EncProof) WireVersion() uint16 { return encProofVersion }

// Clone returns a deep copy of the EncProof.
func (p *EncProof) Clone() *EncProof {
	if p == nil {
		return nil
	}
	return &EncProof{
		S:              new(big.Int).Set(p.S),
		A:              new(big.Int).Set(p.A),
		C:              new(big.Int).Set(p.C),
		Z1:             new(big.Int).Set(p.Z1),
		Z2:             new(big.Int).Set(p.Z2),
		Z3:             new(big.Int).Set(p.Z3),
		TranscriptHash: append([]byte(nil), p.TranscriptHash...),
	}
}

// Validate checks that the EncProof is structurally complete.
func (p *EncProof) Validate() error {
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
	alpha, err := sampleSignedSecret(rng, params.EncRange())
	if err != nil {
		return nil, err
	}
	defer alpha.Destroy()
	// mu ← ±(2^Ell * N_j)
	mu, err := sampleMultRangeSecret(rng, params.Ell, Nj)
	if err != nil {
		return nil, err
	}
	defer mu.Destroy()
	r, err := sampleZNStarSecret(rng, Ni.N)
	if err != nil {
		return nil, err
	}
	defer r.Destroy()
	// gamma ← ±(2^(Ell + Epsilon) * N_j)
	gamma, err := sampleMultRangeSecret(rng, params.EncRange(), Nj)
	if err != nil {
		return nil, err
	}
	defer gamma.Destroy()

	// Commitments.
	secretCommitLen := max(signedPowerOfTwoBytes(params.Ell), multRangeBytes(Nj, params.Ell))
	kSigned, err := signedSecretFromScalar(witness.K, secretCommitLen)
	if err != nil {
		return nil, err
	}
	defer kSigned.Destroy()
	muPadded, err := resizeSignedSecret(mu, secretCommitLen)
	if err != nil {
		return nil, err
	}
	defer muPadded.Destroy()
	S, err := RPCommitCT(statement.VerifierAux, kSigned, muPadded, secretCommitLen)
	if err != nil {
		return nil, err
	}
	A, err := encRandomSecrets(Ni, alpha, r)
	if err != nil {
		return nil, err
	}
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
	C, err := RPCommitCT(statement.VerifierAux, alphaPadded, gammaPadded, maskCommitLen)
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
	kBig, err := secretScalarBig(witness.K)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(kBig)
	alphaBig, err := signedSecretBig(alpha)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(alphaBig)
	// z1 = alpha + e*k
	z1 := new(big.Int).Mul(e, kBig)
	z1.Add(z1, alphaBig)

	// z2 = r * rho^e mod N_i
	rBig, err := secretScalarBig(r)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rBig)
	rhoBig, err := secretScalarBig(witness.Rho)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rhoBig)
	rhoExp := new(big.Int).Exp(rhoBig, e, Ni.N)
	defer secret.ClearBigInt(rhoExp)
	z2 := new(big.Int).Mul(rBig, rhoExp)
	z2.Mod(z2, Ni.N)

	// z3 = gamma + e*mu
	muBig, err := signedSecretBig(mu)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(muBig)
	gammaBig, err := signedSecretBig(gamma)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(gammaBig)
	z3 := new(big.Int).Mul(e, muBig)
	z3.Add(z3, gammaBig)

	return &EncProof{
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

// UnmarshalBinary decodes a canonical TLV EncProof.
func (p *EncProof) UnmarshalBinary(in []byte) error {
	var decoded EncProof
	if err := wire.Unmarshal(in, &decoded, wire.WithFieldLimits(zkFieldLimits())); err != nil {
		return err
	}
	*p = decoded
	return nil
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
	if w.K.FixedLen() != secp.ScalarSize {
		return errors.New("witness k has invalid width")
	}
	kBytes := w.K.FixedBytes()
	if _, err := secp.ScalarFromBytesAllowZero(kBytes); err != nil {
		clear(kBytes)
		return errors.New("witness k is not canonical")
	}
	clear(kBytes)
	if w.Rho.FixedLen() != modulusBytes(stmt.ProverPaillierN.N) {
		return errors.New("witness rho has invalid width")
	}
	k, err := secretScalarBig(w.K)
	if err != nil {
		return errors.New("invalid witness k")
	}
	defer secret.ClearBigInt(k)
	if !InUnsignedPowerOfTwo(k, params.Ell) {
		return errors.New("witness k out of range")
	}
	rho, err := secretScalarBig(w.Rho)
	if err != nil {
		return errors.New("invalid witness rho")
	}
	defer secret.ClearBigInt(rho)
	if !IsZNStar(rho, stmt.ProverPaillierN.N) {
		return errors.New("witness rho not in Z*_N")
	}
	// Verify K == Enc(k; rho).
	expectedK, err := stmt.ProverPaillierN.EncryptWithSecretRandomness(w.K, w.Rho)
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
	t.AppendUint32("ell", params.Ell)
	t.AppendUint32("epsilon", params.Epsilon)
	t.AppendUint32("challenge_bits", params.ChallengeBits)
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
