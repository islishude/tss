package schnorr

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const schnorrChallengeLabel = "github.com/islishude/tss/internal/zk/schnorr/v1"

const proofVersion = 1

const proofWireType = "zk.schnorr.proof"

// Proof is a Schnorr proof of knowledge over secp256k1.
type Proof struct {
	Commitment []byte `wire:"1,bytes"`
	Response   []byte `wire:"2,bytes"`
}

// Clone returns a copy of Proof
func (in *Proof) Clone() *Proof {
	return &Proof{
		Commitment: slices.Clone(in.Commitment),
		Response:   slices.Clone(in.Response),
	}
}

// WireType returns the canonical wire type identifier for Proof.
func (Proof) WireType() string { return proofWireType }

// WireVersion returns the wire format version for Proof.
func (Proof) WireVersion() uint16 { return proofVersion }

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
	return &Proof{Commitment: commitment, Response: response.Bytes()}, public, nil
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
	response, err := secp.ScalarFromBytes(proof.Response)
	if err != nil {
		return false
	}
	challenge := challenge(domain, public, proof.Commitment)
	left := secp.ScalarBaseMult(response)
	// Verification checks [s]G = R + [e]X.
	right := secp.Add(commitmentPoint, secp.ScalarMult(publicPoint, secp.ScalarFromBigInt(challenge)))
	return secp.Equal(left, right)
}

// MarshalBinary encodes the proof using the object-level wire codec.
func (p *Proof) MarshalBinary() ([]byte, error) {
	return wire.Marshal(p)
}

// UnmarshalProof decodes a TLV Schnorr proof record using the object-level wire codec.
func UnmarshalProof(in []byte) (*Proof, error) {
	var proof Proof
	if err := wire.Unmarshal(in, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// Validate checks the canonical curve point and scalar encodings in the proof.
func (p *Proof) Validate() error {
	if p == nil {
		return errors.New("nil Schnorr proof")
	}
	if _, err := secp.PointFromBytes(p.Commitment); err != nil {
		return fmt.Errorf("invalid Schnorr commitment: %w", err)
	}
	if _, err := secp.ScalarFromBytes(p.Response); err != nil {
		return fmt.Errorf("invalid Schnorr response: %w", err)
	}
	return nil
}

func challenge(domain, public, commitment []byte) *big.Int {
	t := transcript.New(schnorrChallengeLabel)
	t.AppendBytes("outer_domain", domain)
	t.AppendBytes("public_key", public)
	t.AppendBytes("commitment", commitment)
	out := new(big.Int).SetBytes(t.Sum())
	out.Mod(out, secp.Order())
	return out
}
