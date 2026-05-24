package schnorr

import (
	"crypto/sha256"
	"errors"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// Proof is a Schnorr proof of knowledge over secp256k1.
type Proof struct {
	Commitment []byte
	Response   []byte
}

// Prove creates a Fiat-Shamir Schnorr proof for secret and returns its public key.
func Prove(domain []byte, secret *big.Int) (*Proof, []byte, error) {
	if secret == nil || secret.Sign() == 0 {
		return nil, nil, errors.New("secret must be non-zero")
	}
	nonce, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	public, err := secp.PointBytes(secp.ScalarBaseMult(secret))
	if err != nil {
		return nil, nil, err
	}
	commitment, err := secp.PointBytes(secp.ScalarBaseMult(nonce))
	if err != nil {
		return nil, nil, err
	}
	challenge := challenge(domain, public, commitment)
	// Fiat-Shamir Schnorr response: s = k + e*x mod q.
	response := new(big.Int).Mul(challenge, secret)
	response.Add(response, nonce)
	response.Mod(response, secp.Order())
	return &Proof{Commitment: commitment, Response: secp.ScalarBytes(response)}, public, nil
}

// Verify checks a Fiat-Shamir Schnorr proof against public key bytes.
func Verify(domain, public []byte, proof *Proof) bool {
	if proof == nil {
		return false
	}
	publicPoint, err := secp.PointFromBytes(public)
	if err != nil {
		return false
	}
	commitmentPoint, err := secp.PointFromBytes(proof.Commitment)
	if err != nil {
		return false
	}
	response, err := secp.ParseScalar(proof.Response)
	if err != nil {
		return false
	}
	challenge := challenge(domain, public, proof.Commitment)
	left := secp.ScalarBaseMult(response)
	// Verification checks [s]G = R + [e]X.
	right := secp.Add(commitmentPoint, secp.ScalarMult(publicPoint, challenge))
	return secp.Equal(left, right)
}

func challenge(domain, public, commitment []byte) *big.Int {
	h := sha256.New()
	writePart(h, []byte("github.com/islishude/tss/internal/zk/schnorr/v1"))
	writePart(h, domain)
	writePart(h, public)
	writePart(h, commitment)
	out := new(big.Int).SetBytes(h.Sum(nil))
	out.Mod(out, secp.Order())
	return out
}

func writePart(h interface{ Write([]byte) (int, error) }, part []byte) {
	_, _ = h.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
	_, _ = h.Write(part)
}
