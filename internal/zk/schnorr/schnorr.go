package schnorr

import (
	"errors"
	"fmt"
	"io"
	"slices"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	zkchallenge "github.com/islishude/tss/internal/zk/challenge"
)

const schnorrChallengeLabel = "github.com/islishude/tss/internal/zk/schnorr/v1"
const schnorrChallengeDerivationLabel = "github.com/islishude/tss/internal/zk/schnorr/challenge/v1"
const schnorrChallengeCounterLimit = 256

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

// Preparation owns a one-use Schnorr nonce and its already-published first
// message. Its fields are intentionally opaque.
type Preparation struct {
	nonce      *secret.Scalar
	public     []byte
	commitment []byte
	staged     bool
}

// Finalization is a caller-owned staged Schnorr proof. Commit consumes the
// source Preparation; Destroy cancels the stage and leaves it available for a
// retry that has not emitted the staged proof.
type Finalization struct {
	owner *Preparation
	proof *Proof
}

// Prepare samples a one-use Schnorr nonce for public and returns the public
// first-message commitment before the final proof domain is known.
func Prepare(reader io.Reader, public []byte) (*Preparation, error) {
	if _, err := secp.PointFromBytes(public); err != nil {
		return nil, fmt.Errorf("invalid Schnorr public key: %w", err)
	}
	nonce, err := secp.RandomScalar(reader)
	if err != nil {
		return nil, err
	}
	commitment, err := secp.PointBytes(secp.ScalarBaseMult(nonce))
	if err != nil {
		nonce.Set(secp.ScalarZero())
		return nil, err
	}
	nonceSecret, err := secret.NewScalar(nonce.Bytes(), secp.ScalarSize)
	nonce.Set(secp.ScalarZero())
	if err != nil {
		return nil, err
	}
	return &Preparation{
		nonce:      nonceSecret,
		public:     slices.Clone(public),
		commitment: commitment,
	}, nil
}

// Commitment returns a defensive copy of the prepared public first message.
func (p *Preparation) Commitment() []byte {
	if p == nil || p.nonce == nil {
		return nil
	}
	return slices.Clone(p.commitment)
}

// Destroy clears the prepared nonce and releases the public first message.
func (p *Preparation) Destroy() {
	if p == nil {
		return
	}
	if p.nonce != nil {
		p.nonce.Destroy()
	}
	clear(p.public)
	clear(p.commitment)
	*p = Preparation{}
}

// Finalize consumes the preparation and creates a proof under the final
// domain. secretScalar must open the public key supplied to Prepare.
func (p *Preparation) Finalize(domain []byte, secretScalar *secret.Scalar) (*Proof, error) {
	finalization, err := p.PrepareFinalize(domain, secretScalar)
	if err != nil {
		return nil, err
	}
	proof := finalization.Proof()
	if err := finalization.Commit(); err != nil {
		finalization.Destroy()
		return nil, err
	}
	return proof, nil
}

// PrepareFinalize computes a caller-owned staged proof without consuming the
// source Preparation. The caller must call Commit only after every outbound
// effect has been prepared, or Destroy to cancel before any effect is emitted.
func (p *Preparation) PrepareFinalize(domain []byte, secretScalar *secret.Scalar) (*Finalization, error) {
	if p == nil || p.nonce == nil || p.staged {
		return nil, errors.New("destroyed, consumed, or already staged Schnorr preparation")
	}
	proof, err := p.finalizeProof(domain, secretScalar)
	if err != nil {
		p.Destroy()
		return nil, err
	}
	p.staged = true
	return &Finalization{owner: p, proof: proof}, nil
}

func (p *Preparation) finalizeProof(domain []byte, secretScalar *secret.Scalar) (*Proof, error) {
	sec, err := scalarFromSecret(secretScalar)
	if err != nil {
		return nil, err
	}
	defer sec.Set(secp.ScalarZero())
	public, err := secp.PointBytes(secp.ScalarBaseMult(sec))
	if err != nil {
		return nil, err
	}
	if !slices.Equal(public, p.public) {
		return nil, errors.New("schnorr secret does not open prepared public key")
	}
	nonce, err := scalarFromSecret(p.nonce)
	if err != nil {
		return nil, errors.New("invalid prepared Schnorr nonce")
	}
	defer nonce.Set(secp.ScalarZero())
	challengeScalar, err := challenge(domain, p.public, p.commitment)
	if err != nil {
		return nil, err
	}
	response := secp.ScalarAdd(secp.ScalarMul(challengeScalar, sec), nonce)
	return &Proof{Commitment: slices.Clone(p.commitment), Response: response.Bytes()}, nil
}

// Proof returns a defensive copy of the staged public proof.
func (f *Finalization) Proof() *Proof {
	if f == nil || f.owner == nil || f.proof == nil {
		return nil
	}
	return f.proof.Clone()
}

// Commit consumes the source Preparation after the caller has committed the
// state transition that makes the staged proof visible.
func (f *Finalization) Commit() error {
	if f == nil || f.owner == nil || f.proof == nil || !f.owner.staged {
		return errors.New("destroyed or committed Schnorr finalization")
	}
	owner := f.owner
	clear(f.proof.Commitment)
	clear(f.proof.Response)
	*f = Finalization{}
	owner.Destroy()
	return nil
}

// Destroy cancels a staged finalization without consuming its source
// Preparation. It is safe only before the staged proof has been emitted.
func (f *Finalization) Destroy() {
	if f == nil {
		return
	}
	if f.owner != nil && f.owner.nonce != nil {
		f.owner.staged = false
	}
	if f.proof != nil {
		clear(f.proof.Commitment)
		clear(f.proof.Response)
	}
	*f = Finalization{}
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
	sec, err := scalarFromSecret(secretScalar)
	if err != nil {
		return nil, nil, err
	}
	defer sec.Set(secp.ScalarZero())
	public, err := secp.PointBytes(secp.ScalarBaseMult(sec))
	if err != nil {
		return nil, nil, err
	}
	preparation, err := Prepare(nil, public)
	if err != nil {
		return nil, nil, err
	}
	proof, err := preparation.Finalize(domain, secretScalar)
	return proof, public, err
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
	challenge, err := challenge(domain, public, proof.Commitment)
	if err != nil {
		return false
	}
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

func challenge(domain, public, commitment []byte) (secp.Scalar, error) {
	t := transcript.New(schnorrChallengeLabel)
	t.AppendBytes("outer_domain", domain)
	t.AppendBytes("public_key", public)
	t.AppendBytes("commitment", commitment)
	return zkchallenge.DeriveCanonicalNonZeroSecp256k1(
		schnorrChallengeDerivationLabel,
		t.Sum(),
		schnorrChallengeCounterLimit,
	)
}

func scalarFromSecret(secretScalar *secret.Scalar) (secp.Scalar, error) {
	if secretScalar == nil || secretScalar.FixedLen() != secp.ScalarSize {
		return secp.Scalar{}, errors.New("secret must be non-zero")
	}
	secretBytes := secretScalar.FixedBytes()
	defer clear(secretBytes)
	sec, err := secp.ScalarFromBytes(secretBytes)
	if err != nil {
		return secp.Scalar{}, errors.New("secret must be a canonical non-zero secp256k1 scalar")
	}
	return sec, nil
}
