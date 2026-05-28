// Package paillierct provides constant-time modular exponentiation for Paillier
// private-key operations. It wraps filippo.io/bigmod to avoid the variable-time
// math/big.Int.Exp when the exponent is a Paillier secret (λ, μ) or an MtA
// responder secret scalar.
//
// All functions require fixed-length encodings. Variable-length big-endian
// encodings (like big.Int.Bytes()) must be padded before calling into this
// package.
package paillierct

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"filippo.io/bigmod"
)

// PrivateModExp is a pre-constructed constant-time modular exponentiator for
// Paillier n² modulus and a fixed secret exponent width.
type PrivateModExp struct {
	mod        *bigmod.Modulus // n²
	modSize    int             // len(n²) in bytes
	nSquaredBs []byte          // n² as big-endian bytes
	expSize    int             // fixed byte length of the secret exponent
}

// NewPrivateModExp creates a PrivateModExp from the n² modulus bytes and the
// expected secret exponent byte length. All ExpSecret calls must provide
// ciphertext bytes of length modSize and exponent bytes of length expSize.
func NewPrivateModExp(nSquared []byte, expSize int) (*PrivateModExp, error) {
	if len(nSquared) == 0 || expSize <= 0 {
		return nil, errors.New("invalid parameter size")
	}
	mod, err := bigmod.NewModulus(nSquared)
	if err != nil {
		return nil, err
	}
	nSquaredBs := make([]byte, len(nSquared))
	copy(nSquaredBs, nSquared)
	return &PrivateModExp{
		mod:        mod,
		modSize:    len(nSquared),
		nSquaredBs: nSquaredBs,
		expSize:    expSize,
	}, nil
}

// ExpSecret computes ciphertext^lambda mod n² in constant time.
// The ciphertext must be len(n²) bytes and lambda must be expSize bytes.
func (p *PrivateModExp) ExpSecret(ciphertext []byte, lambda []byte) ([]byte, error) {
	if len(ciphertext) != p.modSize {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), p.modSize)
	}
	if len(lambda) != p.expSize {
		return nil, fmt.Errorf("invalid exponent length: got %d, want %d", len(lambda), p.expSize)
	}
	base, err := bigmod.NewNat().SetBytes(ciphertext, p.mod)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	out := bigmod.NewNat()
	out.Exp(base, lambda, p.mod)
	return out.Bytes(p.mod), nil
}

// ExpSecretBlinded computes ciphertext^lambda mod n² in constant time with
// ciphertext blinding: c' = c * r^n mod n² where r is random ∈ Z*_n.
// The n parameter is the Paillier modulus.
func (p *PrivateModExp) ExpSecretBlinded(reader io.Reader, ciphertext, lambda, n []byte) ([]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if len(ciphertext) != p.modSize {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), p.modSize)
	}
	if len(lambda) != p.expSize {
		return nil, fmt.Errorf("invalid exponent length: got %d, want %d", len(lambda), p.expSize)
	}

	// Ciphertext blinding: c' = c * r^n mod n².
	// r^n encrypts zero, so decrypting c' yields the same plaintext as c.
	r, err := randomCoprimeFixed(reader, n)
	if err != nil {
		return nil, fmt.Errorf("blinding randomness: %w", err)
	}

	// r^n mod n² using math/big is acceptable: n is the public modulus.
	nBig := new(big.Int).SetBytes(n)
	nSquaredBig := new(big.Int).SetBytes(p.nSquaredBs)
	rBig := new(big.Int).SetBytes(r)
	rn := new(big.Int).Exp(rBig, nBig, nSquaredBig)

	cBig := new(big.Int).SetBytes(ciphertext)
	cPrime := new(big.Int).Mul(cBig, rn)
	cPrime.Mod(cPrime, nSquaredBig)

	cPrimeBytes := padFixed(cPrime.Bytes(), p.modSize)

	base, err := bigmod.NewNat().SetBytes(cPrimeBytes, p.mod)
	if err != nil {
		return nil, fmt.Errorf("blinded ciphertext: %w", err)
	}

	out := bigmod.NewNat()
	out.Exp(base, lambda, p.mod)
	return out.Bytes(p.mod), nil
}

// ExpCT performs constant-time modular exponentiation base^exp mod modulus.
// All inputs must be fixed-length big-endian encodings. The result has the
// same byte length as modulus.
func ExpCT(modulus, base, exp []byte) ([]byte, error) {
	if len(modulus) == 0 || len(base) == 0 || len(exp) == 0 {
		return nil, errors.New("empty input")
	}
	if len(base) != len(modulus) {
		return nil, fmt.Errorf("base length %d does not match modulus length %d", len(base), len(modulus))
	}
	mod, err := bigmod.NewModulus(modulus)
	if err != nil {
		return nil, err
	}
	nat, err := bigmod.NewNat().SetBytes(base, mod)
	if err != nil {
		return nil, fmt.Errorf("invalid base: %w", err)
	}
	out := bigmod.NewNat()
	out.Exp(nat, exp, mod)
	return out.Bytes(mod), nil
}

// FixedEncode encodes x as fixedLen big-endian bytes (padded with leading zeros).
func FixedEncode(x *big.Int, fixedLen int) []byte {
	b := x.Bytes()
	if len(b) >= fixedLen {
		return b[len(b)-fixedLen:]
	}
	out := make([]byte, fixedLen)
	copy(out[fixedLen-len(b):], b)
	return out
}

// padFixed pads b to fixedLen with leading zeros. If b is already longer, it
// is truncated from the left.
func padFixed(b []byte, fixedLen int) []byte {
	if len(b) >= fixedLen {
		return b[len(b)-fixedLen:]
	}
	out := make([]byte, fixedLen)
	copy(out[fixedLen-len(b):], b)
	return out
}

// randomCoprimeFixed generates a random value r < n that is coprime to n.
// Both input and output use fixed-length big-endian encoding.
func randomCoprimeFixed(reader io.Reader, n []byte) ([]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	nBig := new(big.Int).SetBytes(n)
	one := big.NewInt(1)
	nLen := len(n)
	for {
		r, err := rand.Int(reader, nBig)
		if err != nil {
			return nil, err
		}
		if r.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, r, nBig).Cmp(one) == 0 {
			return padFixed(r.Bytes(), nLen), nil
		}
	}
}
