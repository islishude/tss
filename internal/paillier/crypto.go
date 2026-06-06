package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss/internal/paillier/paillierct"
)

// Encrypt encrypts message with fresh random invertible Paillier randomness.
func (pk PublicKey) Encrypt(reader io.Reader, message *big.Int) (*big.Int, *big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, nil, err
	}
	if message == nil {
		return nil, nil, errors.New("nil message")
	}
	// r must be invertible modulo n; otherwise encryption is not in Z*_n^2.
	r, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, nil, err
	}
	c, err := pk.EncryptWithRandomness(message, r)
	if err != nil {
		return nil, nil, err
	}
	return c, r, nil
}

// EncryptWithRandomness encrypts message using caller-provided randomness r.
func (pk PublicKey) EncryptWithRandomness(message, r *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if message == nil || r == nil {
		return nil, errors.New("nil encryption input")
	}
	if new(big.Int).GCD(nil, nil, r, pk.N).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("paillier randomness is not invertible")
	}
	m := mod(message, pk.N)
	gm := new(big.Int).Exp(pk.G, m, pk.NSquared)
	rn := new(big.Int).Exp(r, pk.N, pk.NSquared)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.NSquared)
	return c, nil
}

// Decrypt recovers a plaintext representative from a Paillier ciphertext.
// The ciphertext must be a member of Z*_{n^2} — callers that have not already
// validated the ciphertext through a proof or explicit check should use
// ValidateCiphertext first. The c^λ mod n² step uses constant-time modular
// exponentiation via filippo.io/bigmod with ciphertext blinding to defeat
// side-channel attacks on the secret exponent λ.
func (sk PrivateKey) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return nil, errors.New("invalid private key")
	}
	if err := sk.ValidateCiphertext(ciphertext); err != nil {
		return nil, fmt.Errorf("invalid ciphertext for decryption: %w", err)
	}

	nLen := (sk.N.BitLen() + 7) / 8
	nBytes := paillierct.FixedEncode(sk.N, nLen)
	nSquaredBytes := paillierct.FixedEncode(sk.NSquared, 2*nLen)

	// u = c^λ mod n² via constant-time exponentiation with ciphertext blinding.
	ct, err := paillierct.NewPrivateModExp(nSquaredBytes, nLen)
	if err != nil {
		return nil, fmt.Errorf("paillierct init: %w", err)
	}
	cBytes := paillierct.FixedEncode(ciphertext, len(nSquaredBytes))
	lambdaBytes := sk.Lambda.FixedBytes()
	uBytes, err := ct.ExpSecretBlinded(rand.Reader, cBytes, lambdaBytes, nBytes)
	if err != nil {
		return nil, fmt.Errorf("paillier decryption: %w", err)
	}

	// L(u) = (u - 1) / n. The division is exact for valid Paillier ciphertexts
	// and only depends on the public modulus n.
	u := new(big.Int).SetBytes(uBytes)
	l := L(u, sk.N)

	// m = L(u) * μ mod n using math/big. The exponentiation is already
	// constant-time and ciphertext-blinded; the marginal timing variation
	// from a single multiplication is not practically exploitable.
	muBig := scalarToBig(sk.Mu)
	m := new(big.Int).Mul(l, muBig)
	m.Mod(m, sk.N)
	return m, nil
}

// ValidateCiphertext checks ciphertext membership in Z*_{n^2}.
func (pk PublicKey) ValidateCiphertext(ciphertext *big.Int) error {
	if err := pk.Validate(); err != nil {
		return err
	}
	if ciphertext == nil || ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return errors.New("ciphertext out of range")
	}
	if new(big.Int).GCD(nil, nil, ciphertext, pk.NSquared).Cmp(big.NewInt(1)) != 0 {
		return errors.New("ciphertext is not in Z*_{n^2}")
	}
	return nil
}

// AddCiphertexts homomorphically adds two encrypted plaintexts.
// Both inputs must be in Z*_{n^2}; use AddCiphertextsUnchecked when
// membership has already been verified upstream.
func (pk PublicKey) AddCiphertexts(a, b *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if a == nil || b == nil {
		return nil, errors.New("nil ciphertext")
	}
	if err := pk.ValidateCiphertext(a); err != nil {
		return nil, err
	}
	if err := pk.ValidateCiphertext(b); err != nil {
		return nil, err
	}
	return pk.AddCiphertextsUnchecked(a, b)
}

// AddCiphertextsUnchecked homomorphically adds two encrypted plaintexts
// without validating ciphertext membership in Z*_{n^2}. Callers must ensure
// both inputs have been validated through upstream proof checks. Basic
// range checks are still enforced to catch nil, zero, and out-of-range values.
func (pk PublicKey) AddCiphertextsUnchecked(a, b *big.Int) (*big.Int, error) {
	if a == nil || b == nil {
		return nil, errors.New("nil ciphertext")
	}
	if a.Sign() <= 0 || a.Cmp(pk.NSquared) >= 0 || b.Sign() <= 0 || b.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	out := new(big.Int).Mul(a, b)
	out.Mod(out, pk.NSquared)
	return out, nil
}

// AddPlaintext homomorphically adds plaintext to an encrypted value.
// The ciphertext must be in Z*_{n^2}; use AddPlaintextUnchecked when
// membership has already been verified upstream.
func (pk PublicKey) AddPlaintext(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, err
	}
	return pk.AddPlaintextUnchecked(ciphertext, plaintext)
}

// AddPlaintextUnchecked homomorphically adds plaintext to an encrypted value
// without validating ciphertext membership in Z*_{n^2}. Callers must ensure
// the ciphertext has been validated through upstream proof checks. Basic
// range checks are still enforced to catch nil, zero, and out-of-range values.
func (pk PublicKey) AddPlaintextUnchecked(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	gm := new(big.Int).Exp(pk.G, mod(plaintext, pk.N), pk.NSquared)
	out := new(big.Int).Mul(ciphertext, gm)
	out.Mod(out, pk.NSquared)
	return out, nil
}

// MulPlaintext homomorphically multiplies an encrypted value by public plaintext.
// The plaintext argument must not contain secret scalar or nonce material; this
// helper uses variable-time public exponentiation and is not a secret-exponent
// protocol primitive. The ciphertext must be in Z*_{n^2}; use
// MulPlaintextUnchecked when membership has already been verified upstream.
func (pk PublicKey) MulPlaintext(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, err
	}
	return pk.MulPlaintextUnchecked(ciphertext, plaintext)
}

// MulPlaintextUnchecked homomorphically multiplies an encrypted value by public
// plaintext without validating ciphertext membership in Z*_{n^2}. Callers must
// ensure the ciphertext has been validated through upstream proof checks. Basic
// range checks are still enforced to catch nil, zero, and out-of-range values.
func (pk PublicKey) MulPlaintextUnchecked(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	out := new(big.Int).Exp(ciphertext, mod(plaintext, pk.N), pk.NSquared)
	return out, nil
}

// L computes Paillier's L(u) = (u - 1) / n helper.
func L(u, n *big.Int) *big.Int {
	// L(u) = (u - 1) / n in Paillier decryption.
	out := new(big.Int).Sub(u, big.NewInt(1))
	out.Div(out, n)
	return out
}

func randomCoprime(reader io.Reader, n *big.Int) (*big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	one := big.NewInt(1)
	for {
		r, err := rand.Int(reader, n)
		if err != nil {
			return nil, err
		}
		if r.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, r, n).Cmp(one) == 0 {
			return r, nil
		}
	}
}

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	out := new(big.Int).Div(new(big.Int).Mul(a, b), g)
	return out.Abs(out)
}

func mod(x, m *big.Int) *big.Int {
	out := new(big.Int).Mod(x, m)
	if out.Sign() < 0 {
		out.Add(out, m)
	}
	return out
}
