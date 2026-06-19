package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
)

// --- Transcript / hash helpers ---

func proofTranscript(tag string, domain []byte, statementParts, commitmentParts [][]byte) []byte {
	t := transcript.New(proofTranscriptLabel)
	t.AppendUint32("proof_version", uint32(proofTranscriptVersion))
	t.AppendString("curve", "secp256k1")
	t.AppendString("proof_tag", tag)
	t.AppendBytes("outer_domain", domain)
	t.AppendBytesList("statement_parts", statementParts)
	t.AppendBytesList("commitment_parts", commitmentParts)
	return t.Sum()
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
	modulusBytes := paillierct.FixedEncode(modulus, modLen)
	baseMod := new(big.Int).Mod(base, modulus)
	baseBytes := paillierct.FixedEncode(baseMod, modLen)
	exponentBytes := paillierct.FixedEncode(exponent, expLen)
	defer secret.ClearBigInt(baseMod)
	defer clear(exponentBytes)
	out, err := paillierct.ExpCT(
		modulusBytes,
		baseBytes,
		exponentBytes,
	)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(out), nil
}

func expSecretScalarMod(modulus, base *big.Int, exponent *secret.Scalar, modLen int) (*big.Int, error) {
	if exponent == nil || exponent.FixedLen() != modLen {
		return nil, errors.New("invalid fixed-width secret exponent")
	}
	expBytes := exponent.FixedBytes()
	defer clear(expBytes)
	out, err := paillierct.ExpCT(
		paillierct.FixedEncode(modulus, modLen),
		paillierct.FixedEncode(new(big.Int).Mod(base, modulus), modLen),
		expBytes,
	)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(out), nil
}

func paillierFactors(sk *pai.PrivateKey) (*big.Int, *big.Int, error) {
	if sk == nil {
		return nil, nil, errors.New("nil Paillier private key")
	}
	p, err := secretScalarBig(sk.P)
	if err != nil {
		return nil, nil, errors.New("invalid Paillier factor p")
	}
	q, err := secretScalarBig(sk.Q)
	if err != nil {
		secret.ClearBigInt(p)
		return nil, nil, errors.New("invalid Paillier factor q")
	}
	return p, q, nil
}

func paillierPhi(sk *pai.PrivateKey) (*big.Int, error) {
	p, q, err := paillierFactors(sk)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(p)
	defer secret.ClearBigInt(q)
	p1 := new(big.Int).Sub(p, big.NewInt(1))
	q1 := new(big.Int).Sub(q, big.NewInt(1))
	return new(big.Int).Mul(p1, q1), nil
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

// --- Validation helpers ---

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

// --- Random helpers ---

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

func partyBytes(party uint32) []byte {
	return []byte{byte(party >> 24), byte(party >> 16), byte(party >> 8), byte(party)}
}
