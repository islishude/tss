package schnorr

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const schnorrChallengeLabel = "github.com/islishude/tss/internal/zk/schnorr/v1"

const proofVersion = 1

const proofWireType = "zk.schnorr.proof"

const (
	proofFieldCommitment uint16 = iota + 1
	proofFieldResponse
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
	sec := secp.ScalarFromBigInt(secret)
	nonce, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	public, err := secp.PointBytes(secp.ScalarBaseMult(sec))
	if err != nil {
		return nil, nil, err
	}
	commitment, err := secp.PointBytes(secp.ScalarBaseMult(nonce))
	if err != nil {
		return nil, nil, err
	}
	challenge := challenge(domain, public, commitment)
	// Fiat-Shamir Schnorr response: s = k + e*x mod q.
	challengeScalar := secp.ScalarFromBigInt(challenge)
	response := secp.ScalarAdd(secp.ScalarMul(challengeScalar, sec), nonce)
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
	right := secp.Add(commitmentPoint, secp.ScalarMult(publicPoint, secp.ScalarFromBigInt(challenge)))
	return secp.Equal(left, right)
}

// MarshalBinary encodes the proof as a deterministic TLV record.
func (p *Proof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, proofWireType, []wire.Field{
		{Tag: proofFieldCommitment, Value: p.Commitment},
		{Tag: proofFieldResponse, Value: p.Response},
	})
}

// UnmarshalProof decodes a deterministic TLV Schnorr proof record.
func UnmarshalProof(in []byte) (*Proof, error) {
	version, fields, err := wire.Unmarshal(in, proofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected Schnorr proof version %d", version)
	}
	if len(fields) != 2 || fields[0].Tag != proofFieldCommitment || fields[1].Tag != proofFieldResponse {
		return nil, errors.New("unexpected Schnorr proof field set")
	}
	proof := &Proof{
		Commitment: fields[0].Value,
		Response:   fields[1].Value,
	}
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	return proof, nil
}

// Validate checks the canonical curve point and scalar encodings in the proof.
func (p *Proof) Validate() error {
	if p == nil {
		return errors.New("nil Schnorr proof")
	}
	if _, err := secp.PointFromBytes(p.Commitment); err != nil {
		return fmt.Errorf("invalid Schnorr commitment: %w", err)
	}
	if _, err := secp.ParseScalar(p.Response); err != nil {
		return fmt.Errorf("invalid Schnorr response: %w", err)
	}
	return nil
}

func challenge(domain, public, commitment []byte) *big.Int {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(schnorrChallengeLabel))
	wire.WriteHashPart(h, domain)
	wire.WriteHashPart(h, public)
	wire.WriteHashPart(h, commitment)
	out := new(big.Int).SetBytes(h.Sum(nil))
	out.Mod(out, secp.Order())
	return out
}
