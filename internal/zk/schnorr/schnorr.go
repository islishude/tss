package schnorr

import (
	"errors"
	"fmt"
	"slices"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const schnorrChallengeLabel = "github.com/islishude/tss/internal/zk/schnorr/v1"

const proofWireVersion = 1

const proofWireType = "zk.schnorr.proof"

const (
	proofMaxBytes      = 256
	proofMaxPointBytes = 65
)

// Proof is a Schnorr proof of knowledge over secp256k1.
type Proof struct {
	Commitment []byte `wire:"1,bytes,max_bytes=point"`
	Response   []byte `wire:"2,bytes,max_bytes=scalar"`
}

// Clone returns a copy of Proof
func (in *Proof) Clone() *Proof {
	if in == nil {
		return nil
	}
	return &Proof{
		Commitment: slices.Clone(in.Commitment),
		Response:   slices.Clone(in.Response),
	}
}

// WireType returns the canonical wire type identifier for Proof.
func (Proof) WireType() string { return proofWireType }

// WireVersion returns the wire format version for Proof.
func (Proof) WireVersion() uint16 { return proofWireVersion }

// Prove creates a Fiat-Shamir Schnorr proof for secret and returns its public key.
func Prove(domain []byte, secretScalar *secret.Scalar) (*Proof, []byte, error) {
	if secretScalar == nil || secretScalar.FixedLen() != secp.ScalarSize {
		return nil, nil, errors.New("secret must be non-zero")
	}
	secretBytes := secretScalar.FixedBytes()
	defer clear(secretBytes)
	sec, err := secp.ScalarFromBytes(secretBytes)
	if err != nil {
		return nil, nil, errors.New("secret must be a canonical non-zero secp256k1 scalar")
	}
	defer sec.Set(secp.ScalarZero())
	nonce, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	defer nonce.Set(secp.ScalarZero())
	public, err := secp.PointBytes(secp.ScalarBaseMult(sec))
	if err != nil {
		return nil, nil, err
	}
	commitment, err := secp.PointBytes(secp.ScalarBaseMult(nonce))
	if err != nil {
		return nil, nil, err
	}
	// Fiat-Shamir Schnorr response: s = k + e*x mod q.
	challengeScalar := challenge(domain, public, commitment)
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
	right := secp.Add(commitmentPoint, secp.ScalarMult(publicPoint, challenge))
	return secp.Equal(left, right)
}

// MarshalBinary encodes the proof using the object-level wire codec.
func (p *Proof) MarshalBinary() ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(proofFieldLimits()))
}

// MarshalWireValue encodes the proof as a canonical TLV value for custom wire
// fields.
func (p *Proof) MarshalWireValue() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil Schnorr proof")
	}
	return p.MarshalBinary()
}

// UnmarshalBinary decodes a TLV Schnorr proof record.
func (p *Proof) UnmarshalBinary(in []byte) error {
	var decoded Proof
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.FrameLimits{
			MaxTotalBytes: proofMaxBytes,
			MaxFields:     2,
			MaxFieldBytes: proofMaxPointBytes,
		}),
		wire.WithFieldLimits(proofFieldLimits()),
	); err != nil {
		return err
	}
	*p = decoded
	return nil
}

func proofFieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"point":  proofMaxPointBytes,
		"scalar": secp.ScalarSize,
	}
}

// UnmarshalWireValue decodes the proof from a canonical custom wire field
// value.
func (p *Proof) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil Schnorr proof")
	}
	return p.UnmarshalBinary(in)
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

func challenge(domain, public, commitment []byte) secp.Scalar {
	t := transcript.New(schnorrChallengeLabel)
	t.AppendBytes("outer_domain", domain)
	t.AppendBytes("public_key", public)
	t.AppendBytes("commitment", commitment)
	out, err := secp.ScalarFromBytesModOrder(t.Sum())
	if err != nil {
		panic("schnorr: SHA-256 challenge has invalid width")
	}
	return out
}
