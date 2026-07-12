package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
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

// EncryptSecret encrypts a fixed-width non-negative secret message and returns
// the Paillier randomness as fixed-width secret material.
func (pk PublicKey) EncryptSecret(reader io.Reader, message *secret.Scalar) (*big.Int, *secret.Scalar, error) {
	if message == nil {
		return nil, nil, errors.New("nil message")
	}
	messageBig := scalarToBig(message)
	defer secret.ClearBigInt(messageBig)
	ciphertext, randomness, err := pk.Encrypt(reader, messageBig)
	if err != nil {
		return nil, nil, err
	}
	defer secret.ClearBigInt(randomness)
	nLen := (pk.N.BitLen() + 7) / 8
	randomnessBytes, err := paillierct.FixedEncodeStrict(randomness, nLen)
	if err != nil {
		return nil, nil, fmt.Errorf("encode randomness: %w", err)
	}
	defer clear(randomnessBytes)
	randomnessSecret, err := secret.NewScalar(randomnessBytes, nLen)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, randomnessSecret, nil
}

// EncryptSignedSecret encrypts a fixed-width signed secret message and returns
// the Paillier randomness as fixed-width secret material. Negative messages are
// represented by their canonical residue modulo N.
func (pk PublicKey) EncryptSignedSecret(reader io.Reader, message *secret.SignedInt) (*big.Int, *secret.Scalar, error) {
	if message == nil || message.FixedLen() == 0 {
		return nil, nil, errors.New("nil or destroyed signed secret message")
	}
	messageBig, err := signedSecretToBig(message)
	if err != nil {
		return nil, nil, err
	}
	defer secret.ClearBigInt(messageBig)
	ciphertext, randomness, err := pk.Encrypt(reader, messageBig)
	if err != nil {
		return nil, nil, err
	}
	defer secret.ClearBigInt(randomness)
	nLen := (pk.N.BitLen() + 7) / 8
	randomnessBytes, err := paillierct.FixedEncodeStrict(randomness, nLen)
	if err != nil {
		return nil, nil, fmt.Errorf("encode randomness: %w", err)
	}
	defer clear(randomnessBytes)
	randomnessSecret, err := secret.NewScalar(randomnessBytes, nLen)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, randomnessSecret, nil
}

// EncryptWithSecretRandomness encrypts a fixed-width non-negative secret
// message using fixed-width secret Paillier randomness.
func (pk PublicKey) EncryptWithSecretRandomness(message, randomness *secret.Scalar) (*big.Int, error) {
	if message == nil || randomness == nil {
		return nil, errors.New("nil encryption input")
	}
	messageBig := scalarToBig(message)
	defer secret.ClearBigInt(messageBig)
	randomnessBig := scalarToBig(randomness)
	defer secret.ClearBigInt(randomnessBig)
	return pk.EncryptWithRandomness(messageBig, randomnessBig)
}

// EncryptSignedWithSecretRandomness encrypts a fixed-width signed secret
// message using fixed-width secret Paillier randomness.
func (pk PublicKey) EncryptSignedWithSecretRandomness(message *secret.SignedInt, randomness *secret.Scalar) (*big.Int, error) {
	if message == nil || message.FixedLen() == 0 || randomness == nil {
		return nil, errors.New("nil or destroyed signed encryption input")
	}
	messageBig, err := signedSecretToBig(message)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(messageBig)
	randomnessBig := scalarToBig(randomness)
	defer secret.ClearBigInt(randomnessBig)
	return pk.EncryptWithRandomness(messageBig, randomnessBig)
}

func signedSecretToBig(value *secret.SignedInt) (*big.Int, error) {
	if value == nil || value.FixedLen() == 0 {
		return nil, errors.New("nil or destroyed signed secret integer")
	}
	magnitude := value.FixedMagnitude()
	defer clear(magnitude)
	out := new(big.Int).SetBytes(magnitude)
	sign, err := value.SelectBySign([]byte{0}, []byte{1})
	if err != nil {
		secret.ClearBigInt(out)
		return nil, err
	}
	defer clear(sign)
	if sign[0] == 1 {
		out.Neg(out)
	}
	return out, nil
}

// EncryptWithRandomness encrypts message using caller-provided randomness r.
//
// The G^m mod N² step uses constant-time modular exponentiation because the
// message m is a secret scalar in protocol paths (MtA, keygen, refresh,
// reshare). The r^n mod N² step uses variable-time exponentiation because
// the exponent n is the public Paillier modulus.
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
	defer secret.ClearBigInt(m)

	// G^m mod N² via constant-time exponentiation.
	nLen := (pk.N.BitLen() + 7) / 8
	nSquaredBytes, err := paillierct.FixedEncodeStrict(pk.NSquared, 2*nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier encrypt: encode n squared: %w", err)
	}
	gBytes, err := paillierct.FixedEncodeStrict(pk.G, 2*nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier encrypt: encode generator: %w", err)
	}
	mBytes, err := paillierct.FixedEncodeStrict(m, nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier encrypt: encode message: %w", err)
	}
	defer clear(mBytes)
	gmBytes, err := paillierct.ExpCT(nSquaredBytes, gBytes, mBytes)
	if err != nil {
		return nil, fmt.Errorf("paillier encrypt: %w", err)
	}
	defer clear(gmBytes)
	gm := new(big.Int).SetBytes(gmBytes)
	defer secret.ClearBigInt(gm)

	// r^n mod N² — exponent n is the public modulus, so variable-time is acceptable.
	rn := new(big.Int).Exp(r, pk.N, pk.NSquared)
	defer secret.ClearBigInt(rn)
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
	if err := sk.validateDecryptKey(); err != nil {
		return nil, err
	}
	if err := sk.ValidateCiphertext(ciphertext); err != nil {
		return nil, fmt.Errorf("invalid ciphertext for decryption: %w", err)
	}

	nLen := (sk.N.BitLen() + 7) / 8
	nBytes, err := paillierct.FixedEncodeStrict(sk.N, nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier decryption: encode n: %w", err)
	}
	nSquaredBytes, err := paillierct.FixedEncodeStrict(sk.NSquared, 2*nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier decryption: encode n squared: %w", err)
	}

	// u = c^λ mod n² via constant-time exponentiation with ciphertext blinding.
	ct, err := paillierct.NewPrivateModExp(nBytes, nSquaredBytes, nLen)
	if err != nil {
		return nil, fmt.Errorf("paillierct init: %w", err)
	}
	cBytes, err := paillierct.FixedEncodeStrict(ciphertext, len(nSquaredBytes))
	if err != nil {
		return nil, fmt.Errorf("paillier decryption: encode ciphertext: %w", err)
	}
	lambdaBytes := sk.Lambda.FixedBytes()
	defer clear(lambdaBytes)
	uBytes, err := ct.ExpSecretBlinded(rand.Reader, cBytes, lambdaBytes)
	if err != nil {
		return nil, fmt.Errorf("paillier decryption: %w", err)
	}
	defer clear(uBytes)

	// L(u) = (u - 1) / n. The division is exact for valid Paillier ciphertexts
	// and only depends on the public modulus n.
	u := new(big.Int).SetBytes(uBytes)
	l := L(u, sk.N)

	// m = L(u) * μ mod n using math/big. The exponentiation is already
	// constant-time and ciphertext-blinded; the marginal timing variation
	// from a single multiplication is not practically exploitable.
	muBig := scalarToBig(sk.Mu)
	defer secret.ClearBigInt(muBig)
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
// without validating ciphertext membership in Z*_{n^2}. Callers must provide a
// structurally valid PublicKey and ciphertexts already validated through
// upstream proof checks. Basic range checks are still enforced to catch nil,
// zero, and out-of-range values.
func (pk PublicKey) AddCiphertextsUnchecked(a, b *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
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
// without validating ciphertext membership in Z*_{n^2}. Callers must provide a
// structurally valid PublicKey and a ciphertext already validated through
// upstream proof checks. Basic range checks are still enforced to catch nil,
// zero, and out-of-range values.
//
// The G^plaintext mod N² step uses constant-time modular exponentiation because
// the plaintext exponent may be a secret scalar in some protocol paths.
func (pk PublicKey) AddPlaintextUnchecked(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	nLen := (pk.N.BitLen() + 7) / 8
	nSquaredBytes, err := paillierct.FixedEncodeStrict(pk.NSquared, 2*nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier add plaintext: encode n squared: %w", err)
	}
	gBytes, err := paillierct.FixedEncodeStrict(pk.G, 2*nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier add plaintext: encode generator: %w", err)
	}
	p := mod(plaintext, pk.N)
	defer secret.ClearBigInt(p)
	pBytes, err := paillierct.FixedEncodeStrict(p, nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier add plaintext: encode plaintext: %w", err)
	}
	defer clear(pBytes)
	gmBytes, err := paillierct.ExpCT(nSquaredBytes, gBytes, pBytes)
	if err != nil {
		return nil, fmt.Errorf("paillier add plaintext: %w", err)
	}
	defer clear(gmBytes)
	gm := new(big.Int).SetBytes(gmBytes)
	defer secret.ClearBigInt(gm)
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
// provide a structurally valid PublicKey and a ciphertext already validated
// through upstream proof checks. Basic range checks are still enforced to catch
// nil, zero, and out-of-range values.
func (pk PublicKey) MulPlaintextUnchecked(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	nLen := (pk.N.BitLen() + 7) / 8
	nSquaredBytes, err := paillierct.FixedEncodeStrict(pk.NSquared, 2*nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier multiply plaintext: encode n squared: %w", err)
	}
	ciphertextBytes, err := paillierct.FixedEncodeStrict(ciphertext, 2*nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier multiply plaintext: encode ciphertext: %w", err)
	}
	p := mod(plaintext, pk.N)
	defer secret.ClearBigInt(p)
	exponentBytes, err := paillierct.FixedEncodeStrict(p, nLen)
	if err != nil {
		return nil, fmt.Errorf("paillier multiply plaintext: encode plaintext: %w", err)
	}
	defer clear(exponentBytes)
	out, err := paillierct.ExpCT(nSquaredBytes, ciphertextBytes, exponentBytes)
	if err != nil {
		return nil, err
	}
	defer clear(out)
	return new(big.Int).SetBytes(out), nil
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

func (sk PrivateKey) validateDecryptKey() error {
	if err := sk.PublicKey.Validate(); err != nil {
		return err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return errors.New("invalid private key")
	}
	nLen := (sk.N.BitLen() + 7) / 8
	if sk.Lambda.FixedLen() != nLen || sk.Mu.FixedLen() != nLen {
		return errors.New("invalid private key exponent width")
	}
	return nil
}
