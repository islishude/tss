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
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const factorProofTranscriptLabel = "cggmp21-paillier-factor-proof-v1"

// FactorStatement is the public Pi-fac statement. ProverPaillierN is the
// modulus whose factors are bounded; VerifierAux belongs to the recipient.
type FactorStatement struct {
	ProverPaillierN *pai.PublicKey
	VerifierAux     *RingPedersenParams
}

// ProveFactor creates a receiver-specific CGGMP Pi-fac proof.
func ProveFactor(params SecurityParams, state []byte, sk *pai.PrivateKey, verifierAux *RingPedersenParams, rng io.Reader) (*FactorProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, errors.New("nil Paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	if err := validateRPParamsForProof(params, verifierAux); err != nil {
		return nil, fmt.Errorf("invalid verifier Ring-Pedersen parameters: %w", err)
	}
	p, q, err := paillierFactors(sk)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(p)
	defer secret.ClearBigInt(q)
	if err := validateFactorWitness(params, sk.N, p, q); err != nil {
		return nil, err
	}
	var lastErr error
	for range maxChallengeRetries {
		proof, err := proveFactorOnce(params, state, sk.N, verifierAux, p, q, rng)
		if errors.Is(err, errZeroChallenge) {
			lastErr = err
			continue
		}
		return proof, err
	}
	if lastErr == nil {
		lastErr = errZeroChallenge
	}
	return nil, lastErr
}

func proveFactorOnce(params SecurityParams, state []byte, ni *big.Int, aux *RingPedersenParams, p, q *big.Int, rng io.Reader) (*FactorProof, error) {
	sqrtN := new(big.Int).Sqrt(new(big.Int).Set(ni))
	bonus := max(params.Epsilon, params.ChallengeBits)
	// Use one public, worst-case exponent width for every secret exponent in
	// this proof. Deriving the width from p, q, or sampled masks would leak
	// their exact bit lengths even though the modular exponentiation itself is
	// constant-time.
	secretExpLen := (int(params.Ell+bonus) + ni.BitLen() + aux.N.BitLen() + 9) / 8
	maskFactor := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell+bonus))
	maskFactor.Mul(maskFactor, sqrtN)
	alpha, err := sampleSignedBound(rng, maskFactor)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(alpha)
	beta, err := sampleSignedBound(rng, maskFactor)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(beta)
	muBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell))
	muBound.Mul(muBound, aux.N)
	mu, err := sampleSignedBound(rng, muBound)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(mu)
	nu, err := sampleSignedBound(rng, muBound)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(nu)
	sigmaBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell))
	sigmaBound.Mul(sigmaBound, ni).Mul(sigmaBound, aux.N)
	sigma, err := sampleSignedBound(rng, sigmaBound)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(sigma)
	rBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell+bonus))
	rBound.Mul(rBound, ni).Mul(rBound, aux.N)
	r, err := sampleSignedBound(rng, rBound)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(r)
	xBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell+bonus))
	xBound.Mul(xBound, aux.N)
	x, err := sampleSignedBound(rng, xBound)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(x)
	y, err := sampleSignedBound(rng, xBound)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(y)

	P, err := rpCommitSecretBig(aux, p, mu, secretExpLen)
	if err != nil {
		return nil, err
	}
	Q, err := rpCommitSecretBig(aux, q, nu, secretExpLen)
	if err != nil {
		return nil, err
	}
	A, err := rpCommitSecretBig(aux, alpha, x, secretExpLen)
	if err != nil {
		return nil, err
	}
	B, err := rpCommitSecretBig(aux, beta, y, secretExpLen)
	if err != nil {
		return nil, err
	}
	T, err := multiExpSecretBig(aux.N, Q, alpha, aux.T, r, secretExpLen)
	if err != nil {
		return nil, err
	}

	proof := &FactorProof{P: P, Q: Q, A: A, B: B, T: T, Sigma: new(big.Int).Set(sigma)}
	tr, err := factorTranscript(params, state, FactorStatement{ProverPaillierN: &pai.PublicKey{N: new(big.Int).Set(ni)}, VerifierAux: aux}, proof)
	if err != nil {
		return nil, err
	}
	proof.TranscriptHash = tr.Sum()
	e, err := tr.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(e)
	proof.Z1 = new(big.Int).Mul(e, p)
	proof.Z1.Add(proof.Z1, alpha)
	proof.Z2 = new(big.Int).Mul(e, q)
	proof.Z2.Add(proof.Z2, beta)
	proof.W1 = new(big.Int).Mul(e, mu)
	proof.W1.Add(proof.W1, x)
	proof.W2 = new(big.Int).Mul(e, nu)
	proof.W2.Add(proof.W2, y)
	nup := new(big.Int).Mul(nu, p)
	defer secret.ClearBigInt(nup)
	term := new(big.Int).Sub(sigma, nup)
	defer secret.ClearBigInt(term)
	proof.V = new(big.Int).Mul(e, term)
	proof.V.Add(proof.V, r)
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	return proof, nil
}

// VerifyFactor verifies a receiver-specific Pi-fac proof.
func VerifyFactor(params SecurityParams, state []byte, statement FactorStatement, proof *FactorProof) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if statement.ProverPaillierN == nil || statement.ProverPaillierN.N == nil {
		return errors.New("nil prover Paillier key")
	}
	if err := statement.ProverPaillierN.Validate(); err != nil {
		return err
	}
	if err := validateRPParamsForProof(params, statement.VerifierAux); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	for name, value := range map[string]*big.Int{"P": proof.P, "Q": proof.Q, "A": proof.A, "B": proof.B, "T": proof.T} {
		if err := validateUnit(name, value, statement.VerifierAux.N); err != nil {
			return err
		}
	}
	sigmaBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell))
	sigmaBound.Mul(sigmaBound, statement.ProverPaillierN.N).Mul(sigmaBound, statement.VerifierAux.N)
	if !inSignedBound(proof.Sigma, sigmaBound) {
		return errors.New("factor proof sigma out of range")
	}
	bonus := max(params.Epsilon, params.ChallengeBits)
	// w = mask + e*commitment-randomness. Both terms are bounded by the
	// verifier modulus and the public mask/challenge widths.
	wBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell+bonus+1))
	wBound.Mul(wBound, statement.VerifierAux.N)
	if !inSignedBound(proof.W1, wBound) || !inSignedBound(proof.W2, wBound) {
		return errors.New("factor proof commitment response out of range")
	}
	// v = r + e*(sigma-nu*p). Since p < N_i, the parenthesized term is
	// strictly below twice 2^ell*N_i*N_j. Reject before any public modular
	// exponentiation so a malformed proof cannot become a CPU-amplification
	// vector through an attacker-selected exponent width.
	vBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell+bonus+2))
	vBound.Mul(vBound, statement.ProverPaillierN.N).Mul(vBound, statement.VerifierAux.N)
	if !inSignedBound(proof.V, vBound) {
		return errors.New("factor proof product response out of range")
	}
	tr, err := factorTranscript(params, state, statement, proof)
	if err != nil {
		return err
	}
	if !bytes.Equal(tr.Sum(), proof.TranscriptHash) {
		return errors.New("factor proof transcript mismatch")
	}
	e, err := tr.ChallengeSigned(params.ChallengeBits)
	if err != nil {
		return err
	}
	responseBound := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell+max(params.Epsilon, params.ChallengeBits)+2))
	responseBound.Mul(responseBound, new(big.Int).Sqrt(new(big.Int).Set(statement.ProverPaillierN.N)))
	if !inSignedBound(proof.Z1, responseBound) || !inSignedBound(proof.Z2, responseBound) {
		return errors.New("factor proof factor response out of range")
	}
	left1, err := RPCommit(statement.VerifierAux, proof.Z1, proof.W1)
	if err != nil {
		return err
	}
	right1, err := mulPow(statement.VerifierAux.N, proof.A, proof.P, e)
	if err != nil {
		return err
	}
	if left1.Cmp(right1) != 0 {
		return errors.New("factor proof first equation failed")
	}
	left2, err := RPCommit(statement.VerifierAux, proof.Z2, proof.W2)
	if err != nil {
		return err
	}
	right2, err := mulPow(statement.VerifierAux.N, proof.B, proof.Q, e)
	if err != nil {
		return err
	}
	if left2.Cmp(right2) != 0 {
		return errors.New("factor proof second equation failed")
	}
	left3, err := MultiExpSignedMod(proof.Q, proof.Z1, statement.VerifierAux.T, proof.V, statement.VerifierAux.N)
	if err != nil {
		return err
	}
	base, err := RPCommit(statement.VerifierAux, statement.ProverPaillierN.N, proof.Sigma)
	if err != nil {
		return err
	}
	right3, err := mulPow(statement.VerifierAux.N, proof.T, base, e)
	if err != nil {
		return err
	}
	if left3.Cmp(right3) != 0 {
		return errors.New("factor proof product equation failed")
	}
	return nil
}

func validateFactorWitness(params SecurityParams, n, p, q *big.Int) error {
	if n == nil || p == nil || q == nil || new(big.Int).Mul(new(big.Int).Set(p), q).Cmp(n) != 0 {
		return errors.New("invalid Paillier factor witness")
	}
	lower := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell))
	upper := new(big.Int).Mul(new(big.Int).Set(lower), new(big.Int).Sqrt(new(big.Int).Set(n)))
	if p.Cmp(lower) <= 0 || q.Cmp(lower) <= 0 || p.Cmp(upper) >= 0 || q.Cmp(upper) >= 0 {
		return errors.New("paillier factors do not satisfy Pi-fac bounds")
	}
	return nil
}

// ValidateFactorPrivateKey checks the Pi-fac factor bounds directly for a
// locally owned Paillier private key.
func ValidateFactorPrivateKey(params SecurityParams, sk *pai.PrivateKey) error {
	if sk == nil {
		return errors.New("nil Paillier private key")
	}
	p, q, err := paillierFactors(sk)
	if err != nil {
		return err
	}
	defer secret.ClearBigInt(p)
	defer secret.ClearBigInt(q)
	return validateFactorWitness(params, sk.N, p, q)
}

func factorTranscript(params SecurityParams, state []byte, statement FactorStatement, proof *FactorProof) (*Transcript, error) {
	if statement.ProverPaillierN == nil || statement.VerifierAux == nil || proof == nil {
		return nil, errors.New("incomplete factor transcript")
	}
	t := NewTranscript(factorProofTranscriptLabel)
	appendSecurityParams(t, params)
	t.AppendBytes("state", state)
	if err := t.AppendBigInt("prover_n", statement.ProverPaillierN.N); err != nil {
		return nil, err
	}
	if err := t.AppendBigInt("verifier_n", statement.VerifierAux.N); err != nil {
		return nil, err
	}
	if err := t.AppendBigInt("verifier_s", statement.VerifierAux.S); err != nil {
		return nil, err
	}
	if err := t.AppendBigInt("verifier_t", statement.VerifierAux.T); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		name  string
		value *big.Int
	}{{"P", proof.P}, {"Q", proof.Q}, {"A", proof.A}, {"B", proof.B}, {"T", proof.T}} {
		if err := t.AppendBigInt(item.name, item.value); err != nil {
			return nil, err
		}
	}
	if err := t.AppendSigned("sigma", proof.Sigma); err != nil {
		return nil, err
	}
	return t, nil
}

func sampleSignedBound(rng io.Reader, bound *big.Int) (*big.Int, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if bound == nil || bound.Sign() <= 0 {
		return nil, errors.New("invalid signed sampling bound")
	}
	size := new(big.Int).Lsh(new(big.Int).Set(bound), 1)
	size.Add(size, big.NewInt(1))
	v, err := rand.Int(rng, size)
	if err != nil {
		return nil, err
	}
	return v.Sub(v, bound), nil
}

func rpCommitSecretBig(params *RingPedersenParams, a, b *big.Int, width int) (*big.Int, error) {
	if width <= 0 {
		return nil, errors.New("invalid secret exponent width")
	}
	sa, err := signedSecretFromBig(a, width)
	if err != nil {
		return nil, err
	}
	defer sa.Destroy()
	sb, err := signedSecretFromBig(b, width)
	if err != nil {
		return nil, err
	}
	defer sb.Destroy()
	return RPCommitCT(params, sa, sb, width)
}

func multiExpSecretBig(modulus, base1 *big.Int, exp1 *big.Int, base2 *big.Int, exp2 *big.Int, width int) (*big.Int, error) {
	if width <= 0 {
		return nil, errors.New("invalid secret exponent width")
	}
	s1, err := signedSecretFromBig(exp1, width)
	if err != nil {
		return nil, err
	}
	defer s1.Destroy()
	s2, err := signedSecretFromBig(exp2, width)
	if err != nil {
		return nil, err
	}
	defer s2.Destroy()
	r1, err := ExpSignedModCT(modulus, base1, s1, modulusBytes(modulus), width)
	if err != nil {
		return nil, err
	}
	r2, err := ExpSignedModCT(modulus, base2, s2, modulusBytes(modulus), width)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(new(big.Int).Mul(r1, r2), modulus), nil
}

func validateUnit(name string, x, n *big.Int) error {
	if x == nil || n == nil || x.Sign() <= 0 || x.Cmp(n) >= 0 || new(big.Int).GCD(nil, nil, x, n).Cmp(big.NewInt(1)) != 0 {
		return fmt.Errorf("factor proof %s is not in Z*_N", name)
	}
	return nil
}

func inSignedBound(x, bound *big.Int) bool {
	if x == nil || bound == nil {
		return false
	}
	return new(big.Int).Abs(new(big.Int).Set(x)).Cmp(bound) <= 0
}

func mulPow(modulus, first, base, exponent *big.Int) (*big.Int, error) {
	pow, err := ExpSignedMod(base, exponent, modulus)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(new(big.Int).Mul(first, pow), modulus), nil
}

// MarshalBinary encodes a factor proof canonically.
func (p *FactorProof) MarshalBinary() ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes a canonical factor proof.
func (p *FactorProof) UnmarshalBinary(in []byte) error {
	var decoded FactorProof
	if err := wire.Unmarshal(in, &decoded, wire.WithFrameLimits(zkFrameLimits(tss.DefaultMaxPaillierProofBytes)), wire.WithFieldLimits(zkFieldLimits())); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the structural completeness of a factor proof.
func (p *FactorProof) Validate() error {
	if p == nil {
		return errors.New("nil factor proof")
	}
	if p.P == nil || p.Q == nil || p.A == nil || p.B == nil || p.T == nil || p.Sigma == nil || p.Z1 == nil || p.Z2 == nil || p.W1 == nil || p.W2 == nil || p.V == nil {
		return errors.New("incomplete factor proof")
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("invalid factor proof transcript hash")
	}
	return nil
}
