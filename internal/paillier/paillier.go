package paillier

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const DefaultMinModulusBits = 2048

var minModulusBits = DefaultMinModulusBits

type PublicKey struct {
	N        *big.Int
	NSquared *big.Int
	G        *big.Int
}

type PrivateKey struct {
	PublicKey
	Lambda *big.Int
	Mu     *big.Int
	P      *big.Int
	Q      *big.Int
}

type publicKeyWire struct {
	N string `json:"n"`
	G string `json:"g"`
}

type privateKeyWire struct {
	PublicKey publicKeyWire `json:"public_key"`
	Lambda    string        `json:"lambda"`
	Mu        string        `json:"mu"`
	P         string        `json:"p"`
	Q         string        `json:"q"`
}

func GenerateKey(reader io.Reader, bits int) (*PrivateKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if bits < 512 {
		return nil, errors.New("paillier modulus must be at least 512 bits")
	}
	for {
		p, err := rand.Prime(reader, bits/2)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(reader, bits-bits/2)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		nSquared := new(big.Int).Mul(n, n)
		// g = n + 1 gives the common simplified Paillier variant.
		g := new(big.Int).Add(n, big.NewInt(1))
		lambda := lcm(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		u := new(big.Int).Exp(g, lambda, nSquared)
		lu := L(u, n)
		mu := new(big.Int).ModInverse(lu, n)
		if mu == nil {
			continue
		}
		return &PrivateKey{
			PublicKey: PublicKey{
				N:        n,
				NSquared: nSquared,
				G:        g,
			},
			Lambda: lambda,
			Mu:     mu,
			P:      p,
			Q:      q,
		}, nil
	}
}

func SetMinimumModulusBitsForTesting(bits int) func() {
	old := minModulusBits
	minModulusBits = bits
	return func() { minModulusBits = old }
}

func (pk PublicKey) Validate() error {
	return pk.ValidateBits(minModulusBits)
}

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
	if pk.NSquared == nil || pk.NSquared.Cmp(new(big.Int).Mul(pk.N, pk.N)) != 0 {
		return errors.New("invalid n squared")
	}
	if pk.G == nil || pk.G.Sign() <= 0 || pk.G.Cmp(pk.NSquared) >= 0 {
		return errors.New("invalid generator")
	}
	return nil
}

func (pk PublicKey) MarshalBinary() ([]byte, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(publicKeyWire{
		N: pk.N.Text(16),
		G: pk.G.Text(16),
	})
}

func UnmarshalPublicKey(in []byte) (*PublicKey, error) {
	var w publicKeyWire
	if err := json.Unmarshal(in, &w); err != nil {
		return nil, err
	}
	n, err := parseHex(w.N)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := parseHex(w.G)
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
	canonical, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(in, canonical) {
		return nil, errors.New("non-canonical public key encoding")
	}
	return pk, nil
}

func (sk PrivateKey) MarshalBinary() ([]byte, error) {
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(privateKeyWire{
		PublicKey: publicKeyWire{
			N: sk.N.Text(16),
			G: sk.G.Text(16),
		},
		Lambda: sk.Lambda.Text(16),
		Mu:     sk.Mu.Text(16),
		P:      sk.P.Text(16),
		Q:      sk.Q.Text(16),
	})
}

func UnmarshalPrivateKey(in []byte) (*PrivateKey, error) {
	var w privateKeyWire
	if err := json.Unmarshal(in, &w); err != nil {
		return nil, err
	}
	n, err := parseHex(w.PublicKey.N)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := parseHex(w.PublicKey.G)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	lambda, err := parseHex(w.Lambda)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	mu, err := parseHex(w.Mu)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	p, err := parseHex(w.P)
	if err != nil {
		return nil, fmt.Errorf("invalid p: %w", err)
	}
	q, err := parseHex(w.Q)
	if err != nil {
		return nil, fmt.Errorf("invalid q: %w", err)
	}
	sk := &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        g,
		},
		Lambda: lambda,
		Mu:     mu,
		P:      p,
		Q:      q,
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	canonical, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(in, canonical) {
		return nil, errors.New("non-canonical private key encoding")
	}
	return sk, nil
}

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
	u := new(big.Int).Exp(ciphertext, sk.Lambda, sk.NSquared)
	m := L(u, sk.N)
	m.Mul(m, sk.Mu)
	m.Mod(m, sk.N)
	return m, nil
}

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

func parseHex(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty integer")
	}
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, errors.New("invalid hex integer")
	}
	if x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x, nil
}
