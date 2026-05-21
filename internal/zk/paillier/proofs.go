package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
)

type ModulusProof struct {
	Digest []byte `json:"digest"`
}

type EncryptedScalarProof struct {
	ScalarCommitment []byte `json:"scalar_commitment"`
	CipherCommitment []byte `json:"cipher_commitment"`
	PointCommitment  []byte `json:"point_commitment"`
	Response         []byte `json:"response"`
	Randomness       []byte `json:"randomness"`
}

type MTAResponseProof struct {
	BetaCommitment   []byte `json:"beta_commitment"`
	CipherCommitment []byte `json:"cipher_commitment"`
	BCommitment      []byte `json:"b_commitment"`
	BetaNonce        []byte `json:"beta_nonce"`
	BResponse        []byte `json:"b_response"`
	BetaResponse     []byte `json:"beta_response"`
	Randomness       []byte `json:"randomness"`
}

func ProveModulus(domain []byte, pk *pai.PublicKey, party uint32) (*ModulusProof, error) {
	if pk == nil {
		return nil, errors.New("nil paillier public key")
	}
	raw, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &ModulusProof{Digest: hashParts([]byte("paillier-modulus-proof-v1"), domain, partyBytes(party), raw)}, nil
}

func VerifyModulus(domain []byte, pk *pai.PublicKey, party uint32, proof *ModulusProof) bool {
	if proof == nil || len(proof.Digest) != sha256.Size || pk == nil {
		return false
	}
	want, err := ProveModulus(domain, pk, party)
	if err != nil {
		return false
	}
	return bytes.Equal(want.Digest, proof.Digest)
}

func Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func UnmarshalModulusProof(in []byte) (*ModulusProof, error) {
	var p ModulusProof
	if err := json.Unmarshal(in, &p); err != nil {
		return nil, err
	}
	if len(p.Digest) != sha256.Size {
		return nil, errors.New("invalid modulus proof")
	}
	return &p, nil
}

func UnmarshalEncryptedScalarProof(in []byte) (*EncryptedScalarProof, error) {
	var p EncryptedScalarProof
	if err := json.Unmarshal(in, &p); err != nil {
		return nil, err
	}
	if len(p.ScalarCommitment) == 0 || len(p.CipherCommitment) == 0 || len(p.PointCommitment) == 0 || len(p.Response) == 0 || len(p.Randomness) == 0 {
		return nil, errors.New("incomplete encrypted scalar proof")
	}
	return &p, nil
}

func UnmarshalMTAResponseProof(in []byte) (*MTAResponseProof, error) {
	var p MTAResponseProof
	if err := json.Unmarshal(in, &p); err != nil {
		return nil, err
	}
	if len(p.BetaCommitment) == 0 || len(p.CipherCommitment) == 0 || len(p.BCommitment) == 0 || len(p.BetaNonce) == 0 || len(p.BResponse) == 0 || len(p.BetaResponse) == 0 || len(p.Randomness) == 0 {
		return nil, errors.New("incomplete MtA response proof")
	}
	return &p, nil
}

func ProveEncryptedScalar(reader io.Reader, domain []byte, pk *pai.PublicKey, ciphertext, scalar, randomness *big.Int) (*EncryptedScalarProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, err
	}
	if scalar == nil || scalar.Sign() <= 0 || scalar.Cmp(secp.Order()) >= 0 {
		return nil, errors.New("scalar out of range")
	}
	scalarCommitment, err := secp.PointBytes(secp.ScalarBaseMult(scalar))
	if err != nil {
		return nil, err
	}
	alpha, err := randomScalar(reader)
	if err != nil {
		return nil, err
	}
	rho, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, err
	}
	cipherCommitment, err := pk.EncryptWithRandomness(alpha, rho)
	if err != nil {
		return nil, err
	}
	pointCommitment, err := secp.PointBytes(secp.ScalarBaseMult(alpha))
	if err != nil {
		return nil, err
	}
	e := encryptedScalarChallenge(domain, pk, ciphertext, scalarCommitment, cipherCommitment, pointCommitment)
	z := new(big.Int).Mul(e, scalar)
	z.Add(z, alpha)
	u := new(big.Int).Exp(randomness, e, pk.N)
	u.Mul(u, rho)
	u.Mod(u, pk.N)
	return &EncryptedScalarProof{
		ScalarCommitment: scalarCommitment,
		CipherCommitment: intBytes(cipherCommitment),
		PointCommitment:  pointCommitment,
		Response:         intBytes(z),
		Randomness:       intBytes(u),
	}, nil
}

func VerifyEncryptedScalar(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, proof *EncryptedScalarProof) bool {
	if proof == nil || pk == nil || pk.ValidateCiphertext(ciphertext) != nil {
		return false
	}
	scalarCommitment, err := secp.PointFromBytes(proof.ScalarCommitment)
	if err != nil {
		return false
	}
	cipherCommitment := new(big.Int).SetBytes(proof.CipherCommitment)
	pointCommitment, err := secp.PointFromBytes(proof.PointCommitment)
	if err != nil {
		return false
	}
	z := new(big.Int).SetBytes(proof.Response)
	u := new(big.Int).SetBytes(proof.Randomness)
	if z.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	e := encryptedScalarChallenge(domain, pk, ciphertext, proof.ScalarCommitment, cipherCommitment, proof.PointCommitment)
	encZ, err := pk.EncryptWithRandomness(z, u)
	if err != nil {
		return false
	}
	rightCipher := new(big.Int).Exp(ciphertext, e, pk.NSquared)
	rightCipher.Mul(rightCipher, cipherCommitment)
	rightCipher.Mod(rightCipher, pk.NSquared)
	if encZ.Cmp(rightCipher) != 0 {
		return false
	}
	leftPoint := secp.ScalarBaseMult(z)
	rightPoint := secp.Add(pointCommitment, secp.ScalarMult(scalarCommitment, e))
	return secp.Equal(leftPoint, rightPoint)
}

func ProveMTAResponse(reader io.Reader, domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment []byte, b, beta, betaRandomness *big.Int) (*MTAResponseProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if err := pk.ValidateCiphertext(encA); err != nil {
		return nil, fmt.Errorf("invalid input ciphertext: %w", err)
	}
	if err := pk.ValidateCiphertext(response); err != nil {
		return nil, fmt.Errorf("invalid response ciphertext: %w", err)
	}
	if b == nil || b.Sign() <= 0 || b.Cmp(secp.Order()) >= 0 {
		return nil, errors.New("b out of range")
	}
	if beta == nil {
		return nil, errors.New("nil beta")
	}
	betaMod := mod(beta, secp.Order())
	expectedBCommit, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bCommitment, expectedBCommit) {
		return nil, errors.New("b commitment mismatch")
	}
	betaCommitment, err := secp.PointBytes(secp.ScalarBaseMult(betaMod))
	if err != nil {
		return nil, err
	}
	mu, err := randomScalar(reader)
	if err != nil {
		return nil, err
	}
	nu, err := randomScalar(reader)
	if err != nil {
		return nil, err
	}
	rho, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, err
	}
	encNu, err := pk.EncryptWithRandomness(nu, rho)
	if err != nil {
		return nil, err
	}
	cipherCommitment := new(big.Int).Exp(encA, mu, pk.NSquared)
	cipherCommitment.Mul(cipherCommitment, encNu)
	cipherCommitment.Mod(cipherCommitment, pk.NSquared)
	bNonce, err := secp.PointBytes(secp.ScalarBaseMult(mu))
	if err != nil {
		return nil, err
	}
	betaNonce, err := secp.PointBytes(secp.ScalarBaseMult(nu))
	if err != nil {
		return nil, err
	}
	e := mtaChallenge(domain, pk, encA, response, expectedBCommit, betaCommitment, cipherCommitment, bNonce, betaNonce)
	zB := new(big.Int).Mul(e, b)
	zB.Add(zB, mu)
	zBeta := new(big.Int).Mul(e, betaMod)
	zBeta.Add(zBeta, nu)
	u := new(big.Int).Exp(betaRandomness, e, pk.N)
	u.Mul(u, rho)
	u.Mod(u, pk.N)
	return &MTAResponseProof{
		BetaCommitment:   betaCommitment,
		CipherCommitment: intBytes(cipherCommitment),
		BCommitment:      bNonce,
		BetaNonce:        betaNonce,
		BResponse:        intBytes(zB),
		BetaResponse:     intBytes(zBeta),
		Randomness:       intBytes(u),
	}, nil
}

func VerifyMTAResponse(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitmentBytes []byte, proof *MTAResponseProof) bool {
	if proof == nil || pk == nil || pk.ValidateCiphertext(encA) != nil || pk.ValidateCiphertext(response) != nil {
		return false
	}
	bCommitment, err := secp.PointFromBytes(bCommitmentBytes)
	if err != nil {
		return false
	}
	betaCommitment, err := secp.PointFromBytes(proof.BetaCommitment)
	if err != nil {
		return false
	}
	bNonce, err := secp.PointFromBytes(proof.BCommitment)
	if err != nil {
		return false
	}
	betaNonce, err := secp.PointFromBytes(proof.BetaNonce)
	if err != nil {
		return false
	}
	cipherCommitment := new(big.Int).SetBytes(proof.CipherCommitment)
	zB := new(big.Int).SetBytes(proof.BResponse)
	zBeta := new(big.Int).SetBytes(proof.BetaResponse)
	u := new(big.Int).SetBytes(proof.Randomness)
	if zB.Sign() <= 0 || zBeta.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	e := mtaChallenge(domain, pk, encA, response, bCommitmentBytes, proof.BetaCommitment, cipherCommitment, proof.BCommitment, proof.BetaNonce)

	encZBeta, err := pk.EncryptWithRandomness(zBeta, u)
	if err != nil {
		return false
	}
	leftCipher := new(big.Int).Exp(encA, zB, pk.NSquared)
	leftCipher.Mul(leftCipher, encZBeta)
	leftCipher.Mod(leftCipher, pk.NSquared)
	rightCipher := new(big.Int).Exp(response, e, pk.NSquared)
	rightCipher.Mul(rightCipher, cipherCommitment)
	rightCipher.Mod(rightCipher, pk.NSquared)
	if leftCipher.Cmp(rightCipher) != 0 {
		return false
	}
	leftB := secp.ScalarBaseMult(zB)
	rightB := secp.Add(bNonce, secp.ScalarMult(bCommitment, e))
	if !secp.Equal(leftB, rightB) {
		return false
	}
	leftBeta := secp.ScalarBaseMult(zBeta)
	rightBeta := secp.Add(betaNonce, secp.ScalarMult(betaCommitment, e))
	return secp.Equal(leftBeta, rightBeta)
}

func encryptedScalarChallenge(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, scalarCommitment []byte, cipherCommitment *big.Int, pointCommitment []byte) *big.Int {
	pkBytes, _ := pk.MarshalBinary()
	return challenge([]byte("paillier-encrypted-scalar-v1"), domain, pkBytes, intBytes(ciphertext), scalarCommitment, intBytes(cipherCommitment), pointCommitment)
}

func mtaChallenge(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment, betaCommitment []byte, cipherCommitment *big.Int, bNonce, betaNonce []byte) *big.Int {
	pkBytes, _ := pk.MarshalBinary()
	return challenge([]byte("paillier-mta-response-v1"), domain, pkBytes, intBytes(encA), intBytes(response), bCommitment, betaCommitment, intBytes(cipherCommitment), bNonce, betaNonce)
}

func challenge(parts ...[]byte) *big.Int {
	out := new(big.Int).SetBytes(hashParts(parts...))
	out.Mod(out, secp.Order())
	if out.Sign() == 0 {
		out.SetInt64(1)
	}
	return out
}

func hashParts(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

func randomScalar(reader io.Reader) (*big.Int, error) {
	for {
		x, err := rand.Int(reader, secp.Order())
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
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

func intBytes(x *big.Int) []byte {
	if x == nil {
		return nil
	}
	return x.Bytes()
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
