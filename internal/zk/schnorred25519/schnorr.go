package schnorred25519

import (
	"errors"
	"fmt"
	"io"
	"slices"

	fed "filippo.io/edwards25519"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	zkchallenge "github.com/islishude/tss/internal/zk/challenge"
)

const schnorrChallengeLabel = "github.com/islishude/tss/internal/zk/schnorred25519/v1"
const schnorrChallengeDerivationLabel = "github.com/islishude/tss/internal/zk/schnorred25519/challenge/v1"
const schnorrChallengeCounterLimit = 256

const proofWireVersion = 1
const proofWireType = "zk.schnorr-ed25519.proof"

const proofMaxBytes = 256

// Proof is a Schnorr proof of knowledge over the prime-order Ed25519
// subgroup. Commitment is the non-identity first message R and Response is
// the canonical scalar mu. A zero response is valid at the encoding boundary.
type Proof struct {
	Commitment []byte `wire:"1,bytes,len=32"`
	Response   []byte `wire:"2,bytes,len=32"`
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
// source Preparation. Destroy cancels the stage and also consumes the source,
// so the same nonce and first message can never be finalized again.
type Finalization struct {
	owner *Preparation
	proof *Proof
}

// Prepare samples a one-use Schnorr nonce for public and returns the public
// first-message commitment before the final proof domain is known. public must
// be a canonical, non-identity prime-order Ed25519 point.
func Prepare(reader io.Reader, public []byte) (*Preparation, error) {
	if _, err := edcurve.PointFromBytes(public); err != nil {
		return nil, fmt.Errorf("invalid Ed25519 Schnorr public key: %w", err)
	}
	nonce, err := edcurve.RandomScalar(reader)
	if err != nil {
		return nil, err
	}
	defer nonce.Set(fed.NewScalar())

	commitment := fed.NewIdentityPoint().ScalarBaseMult(nonce).Bytes()
	nonceBytes := nonce.Bytes()
	nonceSecret, err := secret.NewScalar(nonceBytes, edcurve.ScalarSize)
	clear(nonceBytes)
	if err != nil {
		clear(commitment)
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

// PrepareFinalize computes a caller-owned staged proof without immediately
// consuming the source Preparation. The caller must call Commit only after
// every outbound effect has been prepared, or Destroy to cancel and consume
// the nonce before any effect is emitted.
func (p *Preparation) PrepareFinalize(domain []byte, secretScalar *secret.Scalar) (*Finalization, error) {
	if p == nil || p.nonce == nil || p.staged {
		return nil, errors.New("destroyed, consumed, or already staged Ed25519 Schnorr preparation")
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
	defer sec.Set(fed.NewScalar())

	public := fed.NewIdentityPoint().ScalarBaseMult(sec).Bytes()
	defer clear(public)
	if !slices.Equal(public, p.public) {
		return nil, errors.New("Ed25519 Schnorr secret does not open prepared public key")
	}

	nonce, err := scalarFromSecret(p.nonce)
	if err != nil {
		return nil, errors.New("invalid prepared Ed25519 Schnorr nonce")
	}
	defer nonce.Set(fed.NewScalar())

	challengeScalar, err := challenge(domain, p.public, p.commitment)
	if err != nil {
		return nil, err
	}
	defer challengeScalar.Set(fed.NewScalar())

	response := fed.NewScalar().MultiplyAdd(challengeScalar, sec, nonce)
	defer response.Set(fed.NewScalar())
	return &Proof{
		Commitment: slices.Clone(p.commitment),
		Response:   response.Bytes(),
	}, nil
}

// Proof returns a defensive copy of the staged public proof.
func (f *Finalization) Proof() *Proof {
	if f == nil || f.owner == nil || f.owner.nonce == nil || !f.owner.staged || f.proof == nil {
		return nil
	}
	return f.proof.Clone()
}

// Commit consumes the source Preparation after the caller has committed the
// state transition that makes the staged proof visible.
func (f *Finalization) Commit() error {
	if f == nil || f.owner == nil || f.owner.nonce == nil || f.proof == nil || !f.owner.staged {
		return errors.New("destroyed or committed Ed25519 Schnorr finalization")
	}
	owner := f.owner
	clear(f.proof.Commitment)
	clear(f.proof.Response)
	*f = Finalization{}
	owner.Destroy()
	return nil
}

// Destroy cancels a staged finalization, clears its proof, and consumes the
// source Preparation. It is safe to call more than once.
func (f *Finalization) Destroy() {
	if f == nil {
		return
	}
	if f.proof != nil {
		clear(f.proof.Commitment)
		clear(f.proof.Response)
	}
	if f.owner != nil {
		f.owner.Destroy()
	}
	*f = Finalization{}
}

// Clone returns an independently owned copy of Proof.
func (p *Proof) Clone() *Proof {
	if p == nil {
		return nil
	}
	return &Proof{
		Commitment: slices.Clone(p.Commitment),
		Response:   slices.Clone(p.Response),
	}
}

// WireType returns the canonical wire type identifier for Proof.
func (Proof) WireType() string { return proofWireType }

// WireVersion returns the wire format version for Proof.
func (Proof) WireVersion() uint16 { return proofWireVersion }

// Prove creates a Fiat-Shamir Schnorr proof for secretScalar using the default
// cryptographic random source and returns its public key.
func Prove(domain []byte, secretScalar *secret.Scalar) (*Proof, []byte, error) {
	return ProveWithReader(nil, domain, secretScalar)
}

// ProveWithReader creates a Fiat-Shamir Schnorr proof using reader and returns
// the public key. It is primarily useful for deterministic tests; production
// callers must supply a cryptographically secure reader or nil.
func ProveWithReader(reader io.Reader, domain []byte, secretScalar *secret.Scalar) (*Proof, []byte, error) {
	sec, err := scalarFromSecret(secretScalar)
	if err != nil {
		return nil, nil, err
	}
	public := fed.NewIdentityPoint().ScalarBaseMult(sec).Bytes()
	sec.Set(fed.NewScalar())

	preparation, err := Prepare(reader, public)
	if err != nil {
		clear(public)
		return nil, nil, err
	}
	defer preparation.Destroy()
	proof, err := preparation.Finalize(domain, secretScalar)
	if err != nil {
		clear(public)
		return nil, nil, err
	}
	return proof, public, nil
}

// Verify checks a Fiat-Shamir Schnorr proof against a canonical,
// non-identity prime-order public key.
func Verify(domain, public []byte, proof *Proof) bool {
	if proof == nil {
		return false
	}
	publicPoint, err := edcurve.PointFromBytes(public)
	if err != nil {
		return false
	}
	commitmentPoint, err := edcurve.PointFromBytes(proof.Commitment)
	if err != nil {
		return false
	}
	response, err := edcurve.ScalarFromCanonical(proof.Response)
	if err != nil {
		return false
	}
	defer response.Set(fed.NewScalar())

	challengeScalar, err := challenge(domain, public, proof.Commitment)
	if err != nil {
		return false
	}
	defer challengeScalar.Set(fed.NewScalar())

	left := fed.NewIdentityPoint().ScalarBaseMult(response)
	challengePublic := fed.NewIdentityPoint().ScalarMult(challengeScalar, publicPoint)
	// Verification checks [mu]B = R + [c]C.
	right := fed.NewIdentityPoint().Add(commitmentPoint, challengePublic)
	return left.Equal(right) == 1
}

// MarshalBinary encodes the proof using the object-level wire codec.
func (p *Proof) MarshalBinary() ([]byte, error) {
	return wire.Marshal(p)
}

// MarshalWireValue encodes the proof as a canonical TLV value for custom wire
// fields.
func (p *Proof) MarshalWireValue() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil Ed25519 Schnorr proof")
	}
	return p.MarshalBinary()
}

// UnmarshalBinary decodes a canonical TLV Schnorr proof record.
func (p *Proof) UnmarshalBinary(in []byte) error {
	if p == nil {
		return errors.New("nil Ed25519 Schnorr proof")
	}
	var decoded Proof
	if err := wire.Unmarshal(in, &decoded, wire.WithFrameLimits(wire.FrameLimits{
		MaxTotalBytes: proofMaxBytes,
		MaxFields:     2,
		MaxFieldBytes: edcurve.ScalarSize,
	})); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// UnmarshalWireValue decodes the proof from a canonical custom wire field
// value.
func (p *Proof) UnmarshalWireValue(in []byte) error {
	if p == nil {
		return errors.New("nil Ed25519 Schnorr proof")
	}
	return p.UnmarshalBinary(in)
}

// Validate checks the canonical point and scalar encodings in the proof.
// Commitment must be non-identity and prime order; Response may be zero.
func (p *Proof) Validate() error {
	if p == nil {
		return errors.New("nil Ed25519 Schnorr proof")
	}
	if _, err := edcurve.PointFromBytes(p.Commitment); err != nil {
		return fmt.Errorf("invalid Ed25519 Schnorr commitment: %w", err)
	}
	response, err := edcurve.ScalarFromCanonical(p.Response)
	if err != nil {
		return fmt.Errorf("invalid Ed25519 Schnorr response: %w", err)
	}
	response.Set(fed.NewScalar())
	return nil
}

func challenge(domain, public, commitment []byte) (*fed.Scalar, error) {
	t := transcript.New(schnorrChallengeLabel)
	t.AppendBytes("outer_domain", domain)
	t.AppendBytes("public_key", public)
	t.AppendBytes("commitment", commitment)
	return zkchallenge.DeriveCanonicalNonZeroEd25519(
		schnorrChallengeDerivationLabel,
		t.Sum(),
		schnorrChallengeCounterLimit,
	)
}

func scalarFromSecret(secretScalar *secret.Scalar) (*fed.Scalar, error) {
	if secretScalar == nil || secretScalar.FixedLen() != edcurve.ScalarSize {
		return nil, errors.New("secret must be a canonical non-zero Ed25519 scalar")
	}
	secretBytes := secretScalar.FixedBytes()
	defer clear(secretBytes)
	sec, err := edcurve.ScalarFromCanonical(secretBytes)
	if err != nil {
		return nil, errors.New("secret must be a canonical non-zero Ed25519 scalar")
	}
	if sec.Equal(fed.NewScalar()) == 1 {
		sec.Set(fed.NewScalar())
		return nil, errors.New("secret must be a canonical non-zero Ed25519 scalar")
	}
	return sec, nil
}
