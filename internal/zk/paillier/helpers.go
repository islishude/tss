package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/transcript"
)

// --- Transcript / hash helpers ---

func proofTranscript(tag string, domain []byte, statementParts, commitmentParts [][]byte) []byte {
	t := transcript.New(proofTranscriptLabel)
	t.AppendUint32("proof_version", uint32(proofVersion))
	t.AppendString("curve", "secp256k1")
	t.AppendString("proof_tag", tag)
	t.AppendBytes("outer_domain", domain)
	t.AppendBytesList("statement_parts", statementParts)
	t.AppendBytesList("commitment_parts", commitmentParts)
	return t.Sum()
}

// challenge returns the full 256-bit SHA-256 hash output as a Fiat-Shamir
// challenge without modular reduction. Used by EncryptionProof, MTAResponseProof,
// and LogProof where a ~256-bit challenge combined with a large mask α ∈ [0,2^384)
// provides statistical zero-knowledge (~2^128 candidate witnesses).
func challenge(domain, transcriptHash []byte) *big.Int {
	t := transcript.New(string(domain))
	t.AppendBytes("transcript_hash", transcriptHash)
	return new(big.Int).SetBytes(t.Sum())
}

func expandHash(size int, domain, transcriptHash, round, attempt []byte) []byte {
	if size <= 0 {
		return nil
	}
	out := make([]byte, 0, size)
	for counter := uint32(0); len(out) < size; counter++ {
		t := transcript.New(string(domain))
		t.AppendBytes("transcript_hash", transcriptHash)
		t.AppendBytes("round", round)
		t.AppendBytes("attempt", attempt)
		t.AppendUint32("block_counter", counter)
		out = append(out, t.Sum()...)
	}
	return out[:size]
}

// --- Paillier helpers ---

func expSecretMod(modulus, base, exponent *big.Int, modLen, expLen int) (*big.Int, error) {
	out, err := paillierct.ExpCT(
		paillierct.FixedEncode(modulus, modLen),
		paillierct.FixedEncode(new(big.Int).Mod(base, modulus), modLen),
		paillierct.FixedEncode(exponent, expLen),
	)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(out), nil
}

func paillierPhi(sk *pai.PrivateKey) *big.Int {
	p1 := new(big.Int).Sub(sk.P, big.NewInt(1))
	q1 := new(big.Int).Sub(sk.Q, big.NewInt(1))
	return new(big.Int).Mul(p1, q1)
}

func validateBlumFactors(p, q *big.Int) error {
	if p == nil || q == nil || p.Sign() <= 0 || q.Sign() <= 0 {
		return errors.New("invalid Paillier factors")
	}
	if p.Cmp(q) == 0 {
		return errors.New("paillier factors must differ")
	}
	three := big.NewInt(3)
	four := big.NewInt(4)
	if new(big.Int).Mod(p, four).Cmp(three) != 0 || new(big.Int).Mod(q, four).Cmp(three) != 0 {
		return errors.New("paillier factors must be Blum primes")
	}
	return nil
}

func modulusBytes(n *big.Int) int {
	if n == nil || n.Sign() <= 0 {
		return 0
	}
	return (n.BitLen() + 7) / 8
}

// --- Fixed-width encoding helpers ---

func fixedModNBytes(x *big.Int, nLen int) []byte {
	return paillierct.FixedEncode(x, nLen)
}

func fixedModN2Bytes(x *big.Int, pk *pai.PublicKey) []byte {
	if pk == nil || pk.N == nil {
		return nil
	}
	return paillierct.FixedEncode(x, 2*modulusBytes(pk.N))
}

func fixedScalarBytes(x *big.Int) []byte {
	return paillierct.FixedEncode(x, 32)
}

// --- Validation helpers ---

func validateFixedCiphertextBytes(name string, in []byte, pk *pai.PublicKey) error {
	if pk == nil || pk.N == nil {
		return errors.New("nil Paillier public key")
	}
	if len(in) != 2*modulusBytes(pk.N) {
		return fmt.Errorf("%s has invalid width", name)
	}
	c := new(big.Int).SetBytes(in)
	return pk.ValidateCiphertext(c)
}

func decodeFixedUnit(name string, in []byte, n *big.Int, nLen int) (*big.Int, error) {
	if len(in) != nLen {
		return nil, fmt.Errorf("%s has invalid width", name)
	}
	x := new(big.Int).SetBytes(in)
	return requireUnit(x, n)
}

func validateFixedResponse(name string, in []byte, n *big.Int, nLen int) error {
	if len(in) != nLen {
		return fmt.Errorf("%s has invalid width", name)
	}
	x := new(big.Int).SetBytes(in)
	if x.Cmp(n) >= 0 {
		return fmt.Errorf("%s out of range", name)
	}
	return nil
}

func requireUnit(x, n *big.Int) (*big.Int, error) {
	if x == nil || n == nil || x.Sign() <= 0 || x.Cmp(n) >= 0 {
		return nil, errors.New("integer out of range")
	}
	if new(big.Int).GCD(nil, nil, x, n).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("integer is not in the multiplicative group")
	}
	return x, nil
}

func validateCurvePointBytes(name string, in []byte) error {
	if _, err := secp.PointFromBytes(in); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}

func validatePositiveIntBytes(name string, in []byte) error {
	if len(in) == 0 {
		return fmt.Errorf("%s is empty", name)
	}
	if in[0] == 0 {
		return fmt.Errorf("%s is not minimally encoded", name)
	}
	return nil
}

// --- Random helpers ---

// randomLargeMask returns a uniform mask in [0, 2^{l+ε}) for statistical
// zero-knowledge. With l=256 and ε=128, the mask range (~2^384) provides
// ~128 bits of statistical hiding against witness recovery from
// z = α + e·x.
func randomLargeMask(reader io.Reader) (*big.Int, error) {
	return rand.Int(reader, twoToThe(maskBits))
}

func randomCoprime(reader io.Reader, n *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	for {
		x, err := rand.Int(reader, n)
		if err != nil {
			return nil, err
		}
		if x.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, x, n).Cmp(one) == 0 {
			return x, nil
		}
	}
}

// --- Misc helpers ---

func intBytes(x *big.Int) []byte {
	if x == nil {
		return nil
	}
	return x.Bytes()
}

// twoToThe returns 2^n as a *big.Int.
func twoToThe(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

// zkRangeBound returns the maximum allowed Fiat-Shamir response for the
// statistical ZK range: 2^{l+ε} + e·q. With l=256, ε=128, and e ∈ [0,2^256),
// z = α + e·m must satisfy z < 2^{l+ε} + e·q.
func zkRangeBound(e *big.Int) *big.Int {
	maxZ := twoToThe(maskBits)
	maxZ.Add(maxZ, new(big.Int).Mul(e, secp.Order()))
	return maxZ
}

func partyBytes(party uint32) []byte {
	return []byte{byte(party >> 24), byte(party >> 16), byte(party >> 8), byte(party)}
}

func mod(x, m *big.Int) *big.Int {
	out := new(big.Int).Mod(x, m)
	if out.Sign() < 0 {
		out.Add(out, m)
	}
	return out
}
