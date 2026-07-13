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

// ModulusPreparation owns a one-use Paillier factorization and the already
// published first-message commitment for Πmod. Its fields are intentionally
// opaque.
type ModulusPreparation struct {
	sk     *pai.PrivateKey
	party  uint32
	w      []byte
	staged bool
}

// ModulusFinalization is a caller-owned staged Πmod proof. Commit consumes
// the source preparation; Destroy cancels the stage before any effect is
// emitted.
type ModulusFinalization struct {
	owner *ModulusPreparation
	proof *ModulusProof
}

// PrepareModulus samples the public first-message commitment for Πmod before
// the final proof domain is known.
func PrepareModulus(reader io.Reader, sk *pai.PrivateKey, party uint32) (*ModulusPreparation, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if sk == nil {
		return nil, errors.New("nil paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	p, q, err := paillierFactors(sk)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(p)
	defer secret.ClearBigInt(q)
	if err := validateBlumFactors(p, q); err != nil {
		return nil, err
	}
	w, err := randomJacobiMinusOne(reader, sk.N)
	if err != nil {
		return nil, err
	}
	wBytes, err := fixedModNBytes(w, modulusBytes(sk.N))
	if err != nil {
		return nil, fmt.Errorf("encode modulus proof w: %w", err)
	}
	return &ModulusPreparation{sk: sk.Clone(), party: party, w: wBytes}, nil
}

// Commitment returns a defensive copy of the prepared public W commitment.
func (p *ModulusPreparation) Commitment() []byte {
	if p == nil || p.sk == nil {
		return nil
	}
	return bytes.Clone(p.w)
}

// Destroy clears the retained factorization and releases the public first
// message.
func (p *ModulusPreparation) Destroy() {
	if p == nil {
		return
	}
	if p.sk != nil {
		p.sk.Destroy()
	}
	clear(p.w)
	*p = ModulusPreparation{}
}

// Finalize consumes the preparation and constructs a Πmod proof under the
// final domain while reusing the exact published W commitment.
func (p *ModulusPreparation) Finalize(domain []byte) (*ModulusProof, error) {
	finalization, err := p.PrepareFinalize(domain)
	if err != nil {
		return nil, err
	}
	proof := finalization.Proof()
	if err := finalization.Commit(); err != nil {
		finalization.Destroy()
		return nil, err
	}
	return proof, nil
}

// PrepareFinalize computes a staged Πmod proof without consuming the source
// preparation. Call Commit after the state transition is durable, or Destroy
// before any staged proof is emitted.
func (p *ModulusPreparation) PrepareFinalize(domain []byte) (*ModulusFinalization, error) {
	if p == nil || p.sk == nil || len(p.w) == 0 || p.staged {
		return nil, errors.New("destroyed, consumed, or already staged modulus preparation")
	}
	proof, err := finalizeModulus(domain, p.sk, p.party, p.w)
	if err != nil {
		p.Destroy()
		return nil, err
	}
	p.staged = true
	return &ModulusFinalization{owner: p, proof: proof}, nil
}

// Proof returns a defensive copy of the staged public Πmod proof.
func (f *ModulusFinalization) Proof() *ModulusProof {
	if f == nil || f.owner == nil || f.proof == nil {
		return nil
	}
	return f.proof.Clone()
}

// Commit consumes the source preparation after the caller commits the state
// transition that makes the staged proof visible.
func (f *ModulusFinalization) Commit() error {
	if f == nil || f.owner == nil || f.proof == nil || !f.owner.staged {
		return errors.New("destroyed or committed modulus finalization")
	}
	owner := f.owner
	f.proof.Destroy()
	*f = ModulusFinalization{}
	owner.Destroy()
	return nil
}

// Destroy cancels a staged finalization without consuming the source
// preparation. It is safe only before the staged proof has been emitted.
func (f *ModulusFinalization) Destroy() {
	if f == nil {
		return
	}
	if f.owner != nil && f.owner.sk != nil {
		f.owner.staged = false
	}
	if f.proof != nil {
		f.proof.Destroy()
	}
	*f = ModulusFinalization{}
}

// ProveModulus creates the CGGMP24 Πmod proof for a Paillier-Blum modulus.
func ProveModulus(reader io.Reader, domain []byte, sk *pai.PrivateKey, party uint32) (*ModulusProof, error) {
	preparation, err := PrepareModulus(reader, sk, party)
	if err != nil {
		return nil, err
	}
	return preparation.Finalize(domain)
}

func finalizeModulus(domain []byte, sk *pai.PrivateKey, party uint32, wBytes []byte) (*ModulusProof, error) {
	if sk == nil {
		return nil, errors.New("nil paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	p, q, err := paillierFactors(sk)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(p)
	defer secret.ClearBigInt(q)
	if err := validateBlumFactors(p, q); err != nil {
		return nil, err
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nLen := modulusBytes(sk.N)
	phi, err := paillierPhi(sk)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(phi)
	invN := new(big.Int).ModInverse(new(big.Int).Mod(sk.N, phi), phi)
	if invN == nil {
		return nil, errors.New("paillier modulus is not invertible modulo phi(N)")
	}
	defer secret.ClearBigInt(invN)

	w, err := decodeFixedUnit("modulus proof w", wBytes, sk.N, nLen)
	if err != nil || big.Jacobi(w, sk.N) != -1 {
		return nil, errors.New("invalid prepared modulus proof commitment")
	}
	wBytes = bytes.Clone(wBytes)
	transcript := proofTranscript(modulusProofTag, domain, [][]byte{partyBytes(party), raw}, [][]byte{wBytes})

	xs := make([][]byte, modulusProofRounds)
	zs := make([][]byte, modulusProofRounds)
	aBits := make([]byte, modulusProofRounds)
	bBits := make([]byte, modulusProofRounds)
	for i := range modulusProofRounds {
		y, err := deriveModulusY(sk.N, transcript, i)
		if err != nil {
			return nil, err
		}
		z, err := expSecretMod(sk.N, y, invN, nLen, nLen)
		if err != nil {
			return nil, fmt.Errorf("modulus proof z round %d: %w", i, err)
		}
		a, b, x, err := fourthRootForModulusProof(sk, p, q, phi, w, y)
		if err != nil {
			return nil, fmt.Errorf("modulus proof fourth root round %d: %w", i, err)
		}
		xBytes, err := fixedModNBytes(x, nLen)
		if err != nil {
			return nil, fmt.Errorf("encode modulus proof x round %d: %w", i, err)
		}
		zBytes, err := fixedModNBytes(z, nLen)
		if err != nil {
			return nil, fmt.Errorf("encode modulus proof z round %d: %w", i, err)
		}
		xs[i] = xBytes
		zs[i] = zBytes
		aBits[i] = byte(a)
		bBits[i] = byte(b)
	}
	return &ModulusProof{
		W:              wBytes,
		TranscriptHash: transcript,
		X:              xs,
		A:              aBits,
		B:              bBits,
		Z:              zs,
	}, nil
}

// VerifyModulus checks the CGGMP24 Πmod proof against a public key and domain.
func VerifyModulus(domain []byte, pk *pai.PublicKey, party uint32, proof *ModulusProof) bool {
	if validateModulusProof(proof) != nil || pk == nil {
		return false
	}
	if err := pk.Validate(); err != nil {
		return false
	}
	if pk.N.ProbablyPrime(64) || pk.N.Bit(0) == 0 {
		return false
	}
	raw, err := pk.MarshalBinary()
	if err != nil {
		return false
	}
	nLen := modulusBytes(pk.N)
	w, err := decodeFixedUnit("modulus proof w", proof.W, pk.N, nLen)
	if err != nil {
		return false
	}
	if big.Jacobi(w, pk.N) != -1 {
		return false
	}
	expectedTranscript := proofTranscript(modulusProofTag, domain, [][]byte{partyBytes(party), raw}, [][]byte{proof.W})
	if !bytes.Equal(expectedTranscript, proof.TranscriptHash) {
		return false
	}
	for i := range modulusProofRounds {
		x, err := decodeFixedUnit("modulus proof x", proof.X[i], pk.N, nLen)
		if err != nil {
			return false
		}
		z, err := decodeFixedUnit("modulus proof z", proof.Z[i], pk.N, nLen)
		if err != nil {
			return false
		}
		y, err := deriveModulusY(pk.N, expectedTranscript, i)
		if err != nil {
			return false
		}
		leftZ := new(big.Int).Exp(z, pk.N, pk.N)
		if leftZ.Cmp(y) != 0 {
			return false
		}
		leftX := new(big.Int).Exp(x, big.NewInt(4), pk.N)
		right := new(big.Int).Set(y)
		if proof.B[i] == 1 {
			right.Mul(right, w)
			right.Mod(right, pk.N)
		}
		if proof.A[i] == 1 {
			right.Neg(right)
			right.Mod(right, pk.N)
		}
		if leftX.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

// MarshalBinary encodes a modulus proof canonically.
func (p *ModulusProof) MarshalBinary() ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes and structurally validates a modulus proof.
func (p *ModulusProof) UnmarshalBinary(in []byte) error {
	var decoded ModulusProof
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(zkFrameLimits(tss.DefaultMaxPaillierProofBytes)),
		wire.WithFieldLimits(zkFieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// Validate checks the modulus proof structure.
func (p *ModulusProof) Validate() error {
	return validateModulusProof(p)
}

func validateModulusProof(p *ModulusProof) error {
	if p == nil {
		return errors.New("nil modulus proof")
	}
	if len(p.W) == 0 || len(p.TranscriptHash) != sha256.Size {
		return errors.New("incomplete modulus proof")
	}
	if len(p.X) != modulusProofRounds || len(p.Z) != modulusProofRounds || len(p.A) != modulusProofRounds || len(p.B) != modulusProofRounds {
		return errors.New("invalid modulus proof round count")
	}
	for i := range modulusProofRounds {
		if len(p.X[i]) == 0 || len(p.Z[i]) == 0 {
			return fmt.Errorf("incomplete modulus proof round %d", i)
		}
		if p.A[i] != 0 && p.A[i] != 1 {
			return fmt.Errorf("invalid modulus proof a bit %d", i)
		}
		if p.B[i] != 0 && p.B[i] != 1 {
			return fmt.Errorf("invalid modulus proof b bit %d", i)
		}
	}
	return nil
}

// --- Modulus-proof-specific helpers ---

const modulusChallengeCounterLimit = 256

func deriveModulusY(n *big.Int, transcript []byte, round int) (*big.Int, error) {
	if n == nil || n.Cmp(big.NewInt(1)) <= 0 || n.Bit(0) == 0 {
		return nil, errors.New("invalid modulus")
	}
	if round < 0 || uint64(round) > uint64(^uint32(0)) {
		return nil, errors.New("invalid modulus proof round")
	}
	nLen := modulusBytes(n)
	limit, err := modulusRejectionLimit(n, nLen)
	if err != nil {
		return nil, err
	}
	for counter := range uint32(modulusChallengeCounterLimit) {
		candidateBytes := expandHash(nLen, []byte(modulusYLabel), transcript, wire.Uint32(uint32(round)), wire.Uint32(counter))
		candidate, ok := reduceUniformModulusCandidate(candidateBytes, n, limit)
		if ok {
			return candidate, nil
		}
	}
	return nil, errors.New("modulus proof challenge rejection counter exhausted")
}

func modulusRejectionLimit(n *big.Int, nLen int) (*big.Int, error) {
	if n == nil || n.Cmp(big.NewInt(1)) <= 0 || nLen <= 0 {
		return nil, errors.New("invalid modulus rejection parameters")
	}
	space := new(big.Int).Lsh(big.NewInt(1), uint(8*nLen))
	if n.Cmp(space) > 0 {
		return nil, errors.New("modulus exceeds candidate space")
	}
	quotient := new(big.Int).Quo(space, n)
	if quotient.Sign() == 0 {
		return nil, errors.New("empty modulus rejection quotient")
	}
	return quotient.Mul(quotient, n), nil
}

func reduceUniformModulusCandidate(encoded []byte, n, limit *big.Int) (*big.Int, bool) {
	if len(encoded) == 0 || n == nil || limit == nil {
		return nil, false
	}
	candidate := new(big.Int).SetBytes(encoded)
	if candidate.Cmp(limit) >= 0 {
		return nil, false
	}
	candidate.Mod(candidate, n)
	if _, err := requireUnit(candidate, n); err != nil {
		return nil, false
	}
	return candidate, true
}

func randomJacobiMinusOne(reader io.Reader, n *big.Int) (*big.Int, error) {
	for {
		w, err := randomCoprime(reader, n)
		if err != nil {
			return nil, err
		}
		if big.Jacobi(w, n) == -1 {
			return w, nil
		}
	}
}

func fourthRootForModulusProof(sk *pai.PrivateKey, p, q, phi, w, y *big.Int) (int, int, *big.Int, error) {
	for a := 0; a <= 1; a++ {
		for b := 0; b <= 1; b++ {
			target := new(big.Int).Set(y)
			if b == 1 {
				target.Mul(target, w)
				target.Mod(target, sk.N)
			}
			if a == 1 {
				target.Neg(target)
				target.Mod(target, sk.N)
			}
			if !isQuadraticResidueComposite(target, p, q) {
				continue
			}
			root, err := fourthRootBlum(sk, phi, target)
			if err != nil {
				return 0, 0, nil, err
			}
			check := new(big.Int).Exp(root, big.NewInt(4), sk.N)
			if check.Cmp(target) != 0 {
				continue
			}
			return a, b, root, nil
		}
	}
	return 0, 0, nil, errors.New("no quadratic-residue adjustment found")
}

func fourthRootBlum(sk *pai.PrivateKey, phi, target *big.Int) (*big.Int, error) {
	sqrtExp := new(big.Int).Add(phi, big.NewInt(4))
	defer secret.ClearBigInt(sqrtExp)
	sqrtExp.Rsh(sqrtExp, 3)
	fourthExp := new(big.Int).Mul(sqrtExp, sqrtExp)
	defer secret.ClearBigInt(fourthExp)
	nLen := modulusBytes(sk.N)
	return expSecretMod(sk.N, target, fourthExp, nLen, 2*nLen)
}

func isQuadraticResidueComposite(x, p, q *big.Int) bool {
	return big.Jacobi(new(big.Int).Mod(x, p), p) == 1 && big.Jacobi(new(big.Int).Mod(x, q), q) == 1
}
