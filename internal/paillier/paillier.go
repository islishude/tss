package paillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

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

func (pk PublicKey) Validate() error {
	if pk.N == nil || pk.N.Sign() <= 0 {
		return errors.New("invalid modulus")
	}
	if pk.NSquared == nil || pk.NSquared.Cmp(new(big.Int).Mul(pk.N, pk.N)) != 0 {
		return errors.New("invalid n squared")
	}
	if pk.G == nil || pk.G.Sign() <= 0 || pk.G.Cmp(pk.NSquared) >= 0 {
		return errors.New("invalid generator")
	}
	return nil
}

func (pk PublicKey) Encrypt(reader io.Reader, message *big.Int) (*big.Int, *big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, nil, err
	}
	if message == nil {
		return nil, nil, errors.New("nil message")
	}
	m := mod(message, pk.N)
	// r must be invertible modulo n; otherwise encryption is not in Z*_n^2.
	r, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, nil, err
	}
	gm := new(big.Int).Exp(pk.G, m, pk.NSquared)
	rn := new(big.Int).Exp(r, pk.N, pk.NSquared)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.NSquared)
	return c, r, nil
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
