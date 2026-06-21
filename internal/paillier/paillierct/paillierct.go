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
	nBytes     []byte          // n as big-endian bytes
	nSize      int             // len(n) in bytes
	nSquaredBs []byte          // n² as big-endian bytes
	expSize    int             // fixed byte length of the secret exponent
}

// NewPrivateModExp creates a PrivateModExp from the Paillier modulus n, n²
// modulus bytes, and expected secret exponent byte length. The constructor
// binds n to n² so blinded exponentiation cannot mix randomness for one
// modulus with exponentiation under another.
func NewPrivateModExp(n, nSquared []byte, expSize int) (*PrivateModExp, error) {
	if len(n) == 0 || len(nSquared) == 0 || expSize <= 0 {
		return nil, errors.New("invalid parameter size")
	}
	nBig := new(big.Int).SetBytes(n)
	if nBig.Cmp(big.NewInt(1)) <= 0 {
		return nil, errors.New("invalid Paillier modulus")
	}
	nSquaredBig := new(big.Int).SetBytes(nSquared)
	wantNSquared := new(big.Int).Mul(nBig, nBig)
	if nSquaredBig.Cmp(wantNSquared) != 0 {
		return nil, errors.New("n squared does not match modulus")
	}
	mod, err := bigmod.NewModulus(nSquared)
	if err != nil {
		return nil, err
	}
	nBytes := make([]byte, len(n))
	copy(nBytes, n)
	nSquaredBs := make([]byte, len(nSquared))
	copy(nSquaredBs, nSquared)
	return &PrivateModExp{
		mod:        mod,
		modSize:    len(nSquared),
		nBytes:     nBytes,
		nSize:      len(n),
		nSquaredBs: nSquaredBs,
		expSize:    expSize,
	}, nil
}

// ExpSecret computes ciphertext^lambda mod n² in constant time.
// The ciphertext must be len(n²) bytes and lambda must be expSize bytes.
func (p *PrivateModExp) ExpSecret(ciphertext []byte, lambda []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil PrivateModExp")
	}
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
func (p *PrivateModExp) ExpSecretBlinded(reader io.Reader, ciphertext, lambda []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil PrivateModExp")
	}
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
	r, err := randomCoprimeFixed(reader, p.nBytes)
	if err != nil {
		return nil, fmt.Errorf("blinding randomness: %w", err)
	}

	// r^n mod n² using math/big is acceptable: n is the public modulus.
	nBig := new(big.Int).SetBytes(p.nBytes)
	nSquaredBig := new(big.Int).SetBytes(p.nSquaredBs)
	rBig := new(big.Int).SetBytes(r)
	rn := new(big.Int).Exp(rBig, nBig, nSquaredBig)

	cBig := new(big.Int).SetBytes(ciphertext)
	cPrime := new(big.Int).Mul(cBig, rn)
	cPrime.Mod(cPrime, nSquaredBig)

	cPrimeBytes, err := padFixedStrict(cPrime.Bytes(), p.modSize)
	if err != nil {
		return nil, fmt.Errorf("blinded ciphertext encoding: %w", err)
	}

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

// FixedEncodeStrict encodes x as exactly fixedLen big-endian bytes, padding
// with leading zeroes. Oversized, negative, nil, or zero-length inputs are
// rejected so distinct integers cannot silently collapse to the same encoding.
func FixedEncodeStrict(x *big.Int, fixedLen int) ([]byte, error) {
	if x == nil {
		return nil, errors.New("nil integer")
	}
	if fixedLen <= 0 {
		return nil, errors.New("invalid fixed length")
	}
	if x.Sign() < 0 {
		return nil, errors.New("negative integer")
	}
	b := x.Bytes()
	if len(b) > fixedLen {
		return nil, fmt.Errorf("integer encoding too long: got %d, want at most %d", len(b), fixedLen)
	}
	out := make([]byte, fixedLen)
	copy(out[fixedLen-len(b):], b)
	return out, nil
}

// FixedEncodeReduced encodes the low fixedLen bytes of x. Callers must only use
// this after an explicit modular reduction or in tests that intentionally cover
// truncation semantics.
func FixedEncodeReduced(x *big.Int, fixedLen int) []byte {
	b := x.Bytes()
	if len(b) >= fixedLen {
		return b[len(b)-fixedLen:]
	}
	out := make([]byte, fixedLen)
	copy(out[fixedLen-len(b):], b)
	return out
}

// FixedEncode encodes the low fixedLen bytes of x.
//
// Deprecated: use FixedEncodeStrict for security-sensitive fixed-width
// encodings, or FixedEncodeReduced when the input was explicitly reduced and
// low-byte extraction is intended.
func FixedEncode(x *big.Int, fixedLen int) []byte {
	return FixedEncodeReduced(x, fixedLen)
}

// padFixedStrict pads b to fixedLen with leading zeros. Oversized inputs are
// rejected instead of truncated.
func padFixedStrict(b []byte, fixedLen int) ([]byte, error) {
	if fixedLen <= 0 {
		return nil, errors.New("invalid fixed length")
	}
	if len(b) > fixedLen {
		return nil, fmt.Errorf("input encoding too long: got %d, want at most %d", len(b), fixedLen)
	}
	out := make([]byte, fixedLen)
	copy(out[fixedLen-len(b):], b)
	return out, nil
}

// randomCoprimeFixed generates a random value r < n that is coprime to n.
// Both input and output use fixed-length big-endian encoding.
func randomCoprimeFixed(reader io.Reader, n []byte) ([]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	nBig := new(big.Int).SetBytes(n)
	if nBig.Cmp(big.NewInt(1)) <= 0 {
		return nil, errors.New("invalid modulus")
	}
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
			return padFixedStrict(r.Bytes(), nLen)
		}
	}
}
