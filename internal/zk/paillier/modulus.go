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

// ProveModulus creates the CGGMP24 Πmod proof for a Paillier-Blum modulus.
func ProveModulus(reader io.Reader, domain []byte, sk *pai.PrivateKey, party uint32) (*ModulusProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if sk == nil {
		return nil, errors.New("nil paillier private key")
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	if err := validateBlumFactors(sk.P, sk.Q); err != nil {
		return nil, err
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nLen := modulusBytes(sk.N)
	phi := paillierPhi(sk)
	invN := new(big.Int).ModInverse(new(big.Int).Mod(sk.N, phi), phi)
	if invN == nil {
		return nil, errors.New("paillier modulus is not invertible modulo phi(N)")
	}

	w, err := randomJacobiMinusOne(reader, sk.N)
	if err != nil {
		return nil, err
	}
	wBytes := fixedModNBytes(w, nLen)
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
		a, b, x, err := fourthRootForModulusProof(sk, w, y)
		if err != nil {
			return nil, fmt.Errorf("modulus proof fourth root round %d: %w", i, err)
		}
		xs[i] = fixedModNBytes(x, nLen)
		zs[i] = fixedModNBytes(z, nLen)
		aBits[i] = byte(a)
		bBits[i] = byte(b)
	}
	return &ModulusProof{
		Version:        proofVersion,
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

func marshalModulusProof(p *ModulusProof) ([]byte, error) {
	if err := validateModulusProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

// UnmarshalModulusProof decodes and structurally validates a modulus proof.
func UnmarshalModulusProof(in []byte) (*ModulusProof, error) {
	var p ModulusProof
	if err := wire.Unmarshal(in, &p); err != nil {
		return nil, err
	}
	p.Version = proofVersion
	if err := validateModulusProof(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func validateModulusProof(p *ModulusProof) error {
	if p == nil {
		return errors.New("nil modulus proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected modulus proof version %d", p.Version)
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

func deriveModulusY(n *big.Int, transcript []byte, round int) (*big.Int, error) {
	if n == nil || n.Cmp(big.NewInt(1)) <= 0 || n.Bit(0) == 0 {
		return nil, errors.New("invalid modulus")
	}
	nLen := modulusBytes(n)
	for counter := uint32(0); ; counter++ {
		candidate := new(big.Int).SetBytes(expandHash(nLen, []byte(modulusYLabel), transcript, wire.Uint32(uint32(round)), wire.Uint32(counter)))
		candidate.Mod(candidate, n)
		if _, err := requireUnit(candidate, n); err != nil {
			continue
		}
		return candidate, nil
	}
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

func fourthRootForModulusProof(sk *pai.PrivateKey, w, y *big.Int) (int, int, *big.Int, error) {
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
			if !isQuadraticResidueComposite(target, sk.P, sk.Q) {
				continue
			}
			root, err := fourthRootBlum(sk, target)
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

func fourthRootBlum(sk *pai.PrivateKey, target *big.Int) (*big.Int, error) {
	phi := paillierPhi(sk)
	sqrtExp := new(big.Int).Add(phi, big.NewInt(4))
	sqrtExp.Rsh(sqrtExp, 3)
	fourthExp := new(big.Int).Mul(sqrtExp, sqrtExp)
	nLen := modulusBytes(sk.N)
	return expSecretMod(sk.N, target, fourthExp, nLen, 2*nLen)
}

func isQuadraticResidueComposite(x, p, q *big.Int) bool {
	return big.Jacobi(new(big.Int).Mod(x, p), p) == 1 && big.Jacobi(new(big.Int).Mod(x, q), q) == 1
}
