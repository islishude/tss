package paillier

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

// DefaultMinModulusBits is the minimum modulus size accepted outside tests.
const DefaultMinModulusBits = 2048

var minModulusBits = DefaultMinModulusBits

// PublicKey contains Paillier public parameters and cached n^2.
type PublicKey struct {
	N        *big.Int
	NSquared *big.Int
	G        *big.Int
}

// PrivateKey contains Paillier secret factors and decryption exponents.
// Lambda and Mu use fixed-length secret.Scalar to prevent accidental logging,
// variable-length encoding, and non-constant-time conversion of secret material.
type PrivateKey struct {
	PublicKey
	Lambda *secret.Scalar
	Mu     *secret.Scalar
	P      *big.Int
	Q      *big.Int
}

// MarshalJSON rejects default JSON encoding of Paillier private keys.
func (sk PrivateKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("paillier private key contains secret material; use MarshalBinary")
}

// Destroy clears Paillier private exponents and factors in place.
func (sk *PrivateKey) Destroy() {
	if sk == nil {
		return
	}
	sk.Lambda.Destroy()
	sk.Mu.Destroy()
	clearBigInt(sk.P)
	clearBigInt(sk.Q)
}

const paillierWireVersion = 1

const (
	publicKeyWireType  = "paillier.public-key"
	privateKeyWireType = "paillier.private-key"
)

const (
	publicKeyFieldN uint16 = iota + 1
	publicKeyFieldG
)

const (
	privateKeyFieldN uint16 = iota + 1
	privateKeyFieldG
	privateKeyFieldLambda
	privateKeyFieldMu
	privateKeyFieldP
	privateKeyFieldQ
)

// GenerateKey creates a Paillier key using safe primes (Sophie Germain primes)
// where p = 2p' + 1, q = 2q' + 1 with p', q' also prime, and the g=n+1 variant.
// Safe primes ensure the Blum condition p ≡ q ≡ 3 (mod 4) automatically.
// The context is checked in each prime-search iteration to support cancellation.
func GenerateKey(ctx context.Context, reader io.Reader, bits int) (*PrivateKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if bits < 512 {
		return nil, errors.New("paillier modulus must be at least 512 bits")
	}

	type primeResult struct {
		prime *big.Int
		err   error
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		searchCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		pCh := make(chan primeResult, 1)
		qCh := make(chan primeResult, 1)

		go func() {
			p, err := safePrime(searchCtx, reader, bits/2)
			pCh <- primeResult{prime: p, err: err}
		}()
		go func() {
			q, err := safePrime(searchCtx, reader, bits-bits/2)
			qCh <- primeResult{prime: q, err: err}
		}()

		pRes := <-pCh
		if pRes.err != nil {
			return nil, pRes.err
		}
		qRes := <-qCh
		if qRes.err != nil {
			return nil, qRes.err
		}

		p, q := pRes.prime, qRes.prime
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		nSquared := new(big.Int).Mul(n, n)
		// g = n + 1 gives the common simplified Paillier variant.
		g := new(big.Int).Add(n, big.NewInt(1))
		lambdaBig := lcm(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		// (n+1)^λ ≡ 1 + λ·n (mod n²) via the binomial theorem when g = n+1.
		// This avoids math/big.Int.Exp with the secret exponent λ.
		u := new(big.Int).Mul(lambdaBig, n)
		u.Add(u, big.NewInt(1))
		u.Mod(u, nSquared)
		lu := L(u, n)
		muBig := new(big.Int).ModInverse(lu, n)
		if muBig == nil {
			continue
		}
		nLen := (n.BitLen() + 7) / 8
		lambdaSec, err := secret.NewScalar(lambdaBig.Bytes(), nLen)
		if err != nil {
			continue
		}
		muSec, err := secret.NewScalar(muBig.Bytes(), nLen)
		if err != nil {
			continue
		}
		return &PrivateKey{
			PublicKey: PublicKey{
				N:        n,
				NSquared: nSquared,
				G:        g,
			},
			Lambda: lambdaSec,
			Mu:     muSec,
			P:      p,
			Q:      q,
		}, nil
	}
}

// safePrime generates a safe prime p = 2p' + 1 where p' is also prime.
// For bits >= 1024, safe primes are enforced because they are required for
// the CGGMP21 security proof. For smaller sizes (tests), a random Blum prime
// is returned directly for speed — the modulus will still be validated against
// safe-prime structural constraints by ValidateBits.
func safePrime(ctx context.Context, reader io.Reader, bits int) (*big.Int, error) {
	four := big.NewInt(4)
	three := big.NewInt(3)
	if bits < 1024 {
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			p, err := rand.Prime(reader, bits)
			if err != nil {
				return nil, err
			}
			if new(big.Int).Mod(p, four).Cmp(three) == 0 {
				return p, nil
			}
		}
	}
	two := big.NewInt(2)
	one := big.NewInt(1)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Generate a Sophie Germain prime p' of bits-1 bits.
		pPrime, err := rand.Prime(reader, bits-1)
		if err != nil {
			return nil, err
		}
		// p = 2*p' + 1
		p := new(big.Int).Mul(pPrime, two)
		p.Add(p, one)
		// p must have exactly 'bits' bits and be prime.
		if p.BitLen() != bits || !p.ProbablyPrime(64) {
			continue
		}
		return p, nil
	}
}

// SetMinimumModulusBitsForTesting overrides validation policy for tests.
func SetMinimumModulusBitsForTesting(bits int) func() {
	old := minModulusBits
	minModulusBits = bits
	return func() { minModulusBits = old }
}

// Validate checks the public key against the package minimum modulus size.
func (pk PublicKey) Validate() error {
	return pk.ValidateBits(minModulusBits)
}

// ValidateBits checks public key structure against an explicit minimum size.
func (pk PublicKey) ValidateBits(minBits int) error {
	if pk.N == nil || pk.N.Sign() <= 0 {
		return errors.New("invalid modulus")
	}
	if pk.N.Bit(0) == 0 {
		return errors.New("paillier modulus must be odd")
	}
	if minBits > 0 && pk.N.BitLen() < minBits {
		return fmt.Errorf("paillier modulus has %d bits, need at least %d", pk.N.BitLen(), minBits)
	}
	if pk.N.ProbablyPrime(64) {
		return errors.New("paillier modulus must be composite")
	}
	// Safe-prime structural checks: for p = 2p'+1, q = 2q'+1, we have
	// N ≡ 1 (mod 4) and N mod 3 ≠ 0 (excludes p=3 or q=3 which makes
	// (p-1)/2 = 1 not prime).
	four := big.NewInt(4)
	three := big.NewInt(3)
	if new(big.Int).Mod(pk.N, four).Cmp(big.NewInt(1)) != 0 {
		return errors.New("paillier modulus must be ≡ 1 mod 4 for safe primes")
	}
	if new(big.Int).Mod(pk.N, three).Sign() == 0 {
		return errors.New("paillier modulus must not be divisible by 3")
	}
	if pk.NSquared == nil || pk.NSquared.Cmp(new(big.Int).Mul(pk.N, pk.N)) != 0 {
		return errors.New("invalid n squared")
	}
	if pk.G == nil || pk.G.Sign() <= 0 || pk.G.Cmp(pk.NSquared) >= 0 {
		return errors.New("invalid generator")
	}
	return nil
}

// Validate checks both public Paillier parameters and private CRT material.
func (sk PrivateKey) Validate() error {
	if err := sk.PublicKey.Validate(); err != nil {
		return err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return errors.New("invalid secret scalar")
	}
	for name, value := range map[string]*big.Int{
		"p": sk.P,
		"q": sk.Q,
	} {
		if value == nil || value.Sign() <= 0 {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if sk.P.Cmp(sk.Q) == 0 {
		return errors.New("paillier factors must differ")
	}
	if new(big.Int).Mul(sk.P, sk.Q).Cmp(sk.N) != 0 {
		return errors.New("paillier factors do not multiply to modulus")
	}
	if !sk.P.ProbablyPrime(64) || !sk.Q.ProbablyPrime(64) {
		return errors.New("paillier factors must be prime")
	}
	lambdaBig := scalarToBig(sk.Lambda)
	wantLambda := lcm(new(big.Int).Sub(sk.P, big.NewInt(1)), new(big.Int).Sub(sk.Q, big.NewInt(1)))
	if lambdaBig.Cmp(wantLambda) != 0 {
		return errors.New("invalid paillier lambda")
	}
	u := new(big.Int).Exp(sk.G, lambdaBig, sk.NSquared)
	lu := L(u, sk.N)
	wantMu := new(big.Int).ModInverse(lu, sk.N)
	if wantMu == nil || scalarToBig(sk.Mu).Cmp(wantMu) != 0 {
		return errors.New("invalid paillier mu")
	}
	return nil
}

// scalarToBig converts a fixed-length secret.Scalar to a *big.Int.
// This is unexported; callers outside the paillier package must use
// the constant-time paths provided by paillierct.
func scalarToBig(s *secret.Scalar) *big.Int {
	if s == nil {
		return nil
	}
	return new(big.Int).SetBytes(s.FixedBytes())
}

func clearBigInt(x *big.Int) {
	if x == nil {
		return
	}
	clear(x.Bits())
	x.SetInt64(0)
}

// MarshalBinary returns a deterministic TLV public-key record.
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	n, err := encodePositiveInt(pk.N)
	if err != nil {
		return nil, err
	}
	g, err := encodePositiveInt(pk.G)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(paillierWireVersion, publicKeyWireType, []wire.Field{
		{Tag: publicKeyFieldN, Value: n},
		{Tag: publicKeyFieldG, Value: g},
	})
}

// UnmarshalPublicKey decodes and rejects non-canonical public-key encodings.
func UnmarshalPublicKey(in []byte) (*PublicKey, error) {
	version, fields, err := wire.Unmarshal(in, publicKeyWireType)
	if err != nil {
		return nil, err
	}
	if version != paillierWireVersion {
		return nil, fmt.Errorf("unexpected Paillier public-key version %d", version)
	}
	if err := requireExactKeyTags(fields, publicKeyFieldN, publicKeyFieldG); err != nil {
		return nil, err
	}
	n, err := decodePositiveIntField(fields, publicKeyFieldN)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntField(fields, publicKeyFieldG)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	pk := &PublicKey{
		N:        n,
		NSquared: new(big.Int).Mul(n, n),
		G:        g,
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	return pk, nil
}

// MarshalBinary returns a deterministic TLV private-key record.
func (sk PrivateKey) MarshalBinary() ([]byte, error) {
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	n, err := encodePositiveInt(sk.N)
	if err != nil {
		return nil, err
	}
	g, err := encodePositiveInt(sk.G)
	if err != nil {
		return nil, err
	}
	lambda, err := encodePositiveInt(scalarToBig(sk.Lambda))
	if err != nil {
		return nil, err
	}
	mu, err := encodePositiveInt(scalarToBig(sk.Mu))
	if err != nil {
		return nil, err
	}
	p, err := encodePositiveInt(sk.P)
	if err != nil {
		return nil, err
	}
	q, err := encodePositiveInt(sk.Q)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(paillierWireVersion, privateKeyWireType, []wire.Field{
		{Tag: privateKeyFieldN, Value: n},
		{Tag: privateKeyFieldG, Value: g},
		{Tag: privateKeyFieldLambda, Value: lambda},
		{Tag: privateKeyFieldMu, Value: mu},
		{Tag: privateKeyFieldP, Value: p},
		{Tag: privateKeyFieldQ, Value: q},
	})
}

// UnmarshalPrivateKey decodes and rejects non-canonical private-key encodings.
func UnmarshalPrivateKey(in []byte) (*PrivateKey, error) {
	version, fields, err := wire.Unmarshal(in, privateKeyWireType)
	if err != nil {
		return nil, err
	}
	if version != paillierWireVersion {
		return nil, fmt.Errorf("unexpected Paillier private-key version %d", version)
	}
	if err := requireExactKeyTags(fields, privateKeyFieldN, privateKeyFieldG, privateKeyFieldLambda, privateKeyFieldMu, privateKeyFieldP, privateKeyFieldQ); err != nil {
		return nil, err
	}
	n, err := decodePositiveIntField(fields, privateKeyFieldN)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntField(fields, privateKeyFieldG)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	lambdaBig, err := decodePositiveIntField(fields, privateKeyFieldLambda)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	muBig, err := decodePositiveIntField(fields, privateKeyFieldMu)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	p, err := decodePositiveIntField(fields, privateKeyFieldP)
	if err != nil {
		return nil, fmt.Errorf("invalid p: %w", err)
	}
	q, err := decodePositiveIntField(fields, privateKeyFieldQ)
	if err != nil {
		return nil, fmt.Errorf("invalid q: %w", err)
	}
	nLen := (n.BitLen() + 7) / 8
	lambdaSec, err := secret.NewScalar(lambdaBig.Bytes(), nLen)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	muSec, err := secret.NewScalar(muBig.Bytes(), nLen)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	sk := &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        g,
		},
		Lambda: lambdaSec,
		Mu:     muSec,
		P:      p,
		Q:      q,
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	return sk, nil
}

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
// The c^λ mod n² step uses constant-time modular exponentiation via
// filippo.io/bigmod with ciphertext blinding to defeat side-channel attacks
// on the secret exponent λ.
func (sk PrivateKey) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return nil, errors.New("invalid private key")
	}
	if ciphertext == nil || ciphertext.Sign() <= 0 || ciphertext.Cmp(sk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
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
func (pk PublicKey) AddCiphertexts(a, b *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if a == nil || b == nil {
		return nil, errors.New("nil ciphertext")
	}
	out := new(big.Int).Mul(a, b)
	out.Mod(out, pk.NSquared)
	return out, nil
}

// AddPlaintext homomorphically adds plaintext to an encrypted value.
func (pk PublicKey) AddPlaintext(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	gm := new(big.Int).Exp(pk.G, mod(plaintext, pk.N), pk.NSquared)
	out := new(big.Int).Mul(ciphertext, gm)
	out.Mod(out, pk.NSquared)
	return out, nil
}

// MulPlaintext homomorphically multiplies an encrypted value by plaintext.
func (pk PublicKey) MulPlaintext(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
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

func requireExactKeyTags(fields []wire.Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("got %d fields, want %d", len(fields), len(tags))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected field tag %d at index %d", fields[i].Tag, i)
		}
	}
	return nil
}

func encodePositiveInt(x *big.Int) ([]byte, error) {
	if x == nil || x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x.Bytes(), nil
}

func decodePositiveIntField(fields []wire.Field, tag uint16) (*big.Int, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty integer")
	}
	if raw[0] == 0 {
		return nil, errors.New("non-minimal integer encoding")
	}
	x := new(big.Int).SetBytes(raw)
	if x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x, nil
}
