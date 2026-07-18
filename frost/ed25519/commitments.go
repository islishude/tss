package ed25519

import (
	"errors"
	"fmt"
	"math/big"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/wire"
)

const ed25519CommitmentBytes = 32

type commitmentVector struct {
	points []*fed.Point
}

type keygenCommitments commitmentVector

type reshareCommitments commitmentVector

type groupCommitments commitmentVector

func clonePoints(points []*fed.Point) []*fed.Point {
	if points == nil {
		return nil
	}
	out := make([]*fed.Point, len(points))
	for i, point := range points {
		out[i] = clonePoint(point)
	}
	return out
}

func commitmentBytesList(points []*fed.Point) [][]byte {
	if points == nil {
		return nil
	}
	out := make([][]byte, len(points))
	for i, point := range points {
		if point != nil {
			out[i] = point.Bytes()
		}
	}
	return out
}

func equalCommitmentPoints(a, b []*fed.Point) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !pointEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func parseCommitmentBytes(in [][]byte, threshold int, firstNonIdentity bool) ([]*fed.Point, error) {
	if threshold <= 0 {
		return nil, errors.New("commitment threshold must be positive")
	}
	if len(in) != threshold {
		return nil, fmt.Errorf("got %d commitments, want %d", len(in), threshold)
	}
	points := make([]*fed.Point, len(in))
	for i, encoded := range in {
		var (
			point *fed.Point
			err   error
		)
		if firstNonIdentity && i == 0 {
			point, err = edcurve.PointFromBytes(encoded)
		} else {
			point, err = edcurve.PointFromBytesAllowIdentity(encoded)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid commitment %d: %w", i, err)
		}
		points[i] = clonePoint(point)
	}
	return points, nil
}

func parseCommitmentPoints(in []*fed.Point, threshold int, firstNonIdentity bool) ([]*fed.Point, error) {
	if threshold <= 0 {
		return nil, errors.New("commitment threshold must be positive")
	}
	encoded := make([][]byte, len(in))
	for i, point := range in {
		if point == nil {
			return nil, fmt.Errorf("nil commitment %d", i)
		}
		encoded[i] = point.Bytes()
	}
	return parseCommitmentBytes(encoded, threshold, firstNonIdentity)
}

func evalCommitmentPoints(points []*fed.Point, id tss.PartyID) (*fed.Point, error) {
	if len(points) == 0 {
		return nil, errors.New("empty commitments")
	}
	x := new(big.Int).SetUint64(uint64(id))
	pow := big.NewInt(1)
	acc := fed.NewIdentityPoint()
	for i, point := range points {
		if point == nil {
			return nil, fmt.Errorf("nil commitment %d", i)
		}
		scalar, err := edcurve.ScalarFromBig(pow)
		if err != nil {
			return nil, err
		}
		term := fed.NewIdentityPoint().ScalarMult(scalar, point)
		acc.Add(acc, term)
		pow.Mul(pow, x)
		pow.Mod(pow, edcurve.Order())
	}
	return acc, nil
}

func verifyCommitmentShare(points []*fed.Point, id tss.PartyID, share *fed.Scalar) error {
	if share == nil {
		return errors.New("nil scalar share")
	}
	want, err := evalCommitmentPoints(points, id)
	if err != nil {
		return err
	}
	got := fed.NewIdentityPoint().ScalarBaseMult(share)
	if got.Equal(want) != 1 {
		return errors.New("share does not match commitments")
	}
	return nil
}

func newCommitmentVectorFromBytesList(in [][]byte, threshold int, firstNonIdentity bool) (commitmentVector, error) {
	points, err := parseCommitmentBytes(in, threshold, firstNonIdentity)
	if err != nil {
		return commitmentVector{}, err
	}
	return commitmentVector{points: points}, nil
}

func newCommitmentVectorFromPoints(in []*fed.Point, threshold int, firstNonIdentity bool) (commitmentVector, error) {
	points, err := parseCommitmentPoints(in, threshold, firstNonIdentity)
	if err != nil {
		return commitmentVector{}, err
	}
	return commitmentVector{points: points}, nil
}

func (c commitmentVector) bytesList() [][]byte { return commitmentBytesList(c.points) }

func (c commitmentVector) equal(other commitmentVector) bool {
	return equalCommitmentPoints(c.points, other.points)
}

func (c commitmentVector) clone() commitmentVector {
	return commitmentVector{points: clonePoints(c.points)}
}

func (c commitmentVector) marshalWireValue(kind string, firstNonIdentity bool) ([]byte, error) {
	if err := c.validate(firstNonIdentity); err != nil {
		return nil, fmt.Errorf("invalid %s commitments: %w", kind, err)
	}
	return wire.EncodeBytesListChecked(c.bytesList())
}

func (c *commitmentVector) unmarshalWireValue(in []byte, kind string, firstNonIdentity bool) error {
	if c == nil {
		return fmt.Errorf("nil %s commitments receiver", kind)
	}
	encoded, err := wire.DecodeBytesListWithLimit(in, 0, ed25519CommitmentBytes)
	if err != nil {
		return fmt.Errorf("decode %s commitments: %w", kind, err)
	}
	parsed, err := newCommitmentVectorFromBytesList(encoded, len(encoded), firstNonIdentity)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

func (c commitmentVector) validate(firstNonIdentity bool) error {
	_, err := parseCommitmentPoints(c.points, len(c.points), firstNonIdentity)
	return err
}

func (c commitmentVector) validateThreshold(threshold int, firstNonIdentity bool) error {
	if threshold <= 0 {
		return errors.New("commitment threshold must be positive")
	}
	if len(c.points) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(c.points), threshold)
	}
	return c.validate(firstNonIdentity)
}

func (c commitmentVector) pointAt(i int) (*fed.Point, error) {
	if i < 0 || i >= len(c.points) {
		return nil, fmt.Errorf("commitment index %d out of range", i)
	}
	return clonePoint(c.points[i]), nil
}

func (c commitmentVector) verifyShare(id tss.PartyID, share *fed.Scalar) error {
	return verifyCommitmentShare(c.points, id, share)
}

func newKeygenCommitmentsFromPoints(in []*fed.Point, threshold int) (keygenCommitments, error) {
	c, err := newCommitmentVectorFromPoints(in, threshold, true)
	return keygenCommitments(c), err
}

// BytesList returns caller-owned canonical encodings of the keygen commitments.
func (c keygenCommitments) BytesList() [][]byte { return commitmentVector(c).bytesList() }

// Equal reports whether two ordered keygen commitment sets are equal.
func (c keygenCommitments) Equal(other keygenCommitments) bool {
	return commitmentVector(c).equal(commitmentVector(other))
}

// Clone returns an independent copy of the keygen commitment set.
func (c keygenCommitments) Clone() keygenCommitments {
	return keygenCommitments(commitmentVector(c).clone())
}

// Len returns the number of keygen commitments.
func (c keygenCommitments) Len() int { return len(c.points) }

// MarshalWireValue returns the canonical encoding of the keygen commitments.
func (c keygenCommitments) MarshalWireValue() ([]byte, error) {
	return commitmentVector(c).marshalWireValue("keygen", true)
}

// UnmarshalWireValue decodes and validates canonical keygen commitments.
func (c *keygenCommitments) UnmarshalWireValue(in []byte) error {
	if c == nil {
		return errors.New("nil keygen commitments receiver")
	}
	var parsed commitmentVector
	if err := parsed.unmarshalWireValue(in, "keygen", true); err != nil {
		return err
	}
	*c = keygenCommitments(parsed)
	return nil
}

// Validate checks keygen commitment length-independent point invariants.
func (c keygenCommitments) Validate() error { return commitmentVector(c).validate(true) }

// ValidateThreshold checks the exact threshold and all point invariants.
func (c keygenCommitments) ValidateThreshold(threshold int) error {
	return commitmentVector(c).validateThreshold(threshold, true)
}

// IsZero reports whether the commitment set has not been initialized.
func (c keygenCommitments) IsZero() bool { return c.points == nil }

// PointAt returns an independent copy of the commitment at index i.
func (c keygenCommitments) PointAt(i int) (*fed.Point, error) {
	return commitmentVector(c).pointAt(i)
}

// VerifyShare checks a scalar share against the commitment polynomial.
func (c keygenCommitments) VerifyShare(id tss.PartyID, share *fed.Scalar) error {
	return commitmentVector(c).verifyShare(id, share)
}

func newReshareCommitmentsFromPoints(in []*fed.Point, threshold int) (reshareCommitments, error) {
	c, err := newCommitmentVectorFromPoints(in, threshold, false)
	return reshareCommitments(c), err
}

// BytesList returns caller-owned canonical encodings of the reshare commitments.
func (c reshareCommitments) BytesList() [][]byte { return commitmentVector(c).bytesList() }

// Equal reports whether two ordered reshare commitment sets are equal.
func (c reshareCommitments) Equal(other reshareCommitments) bool {
	return commitmentVector(c).equal(commitmentVector(other))
}

// Clone returns an independent copy of the reshare commitment set.
func (c reshareCommitments) Clone() reshareCommitments {
	return reshareCommitments(commitmentVector(c).clone())
}

// Len returns the number of reshare commitments.
func (c reshareCommitments) Len() int { return len(c.points) }

// MarshalWireValue returns the canonical encoding of the reshare commitments.
func (c reshareCommitments) MarshalWireValue() ([]byte, error) {
	return commitmentVector(c).marshalWireValue("reshare", false)
}

// UnmarshalWireValue decodes and validates canonical reshare commitments.
func (c *reshareCommitments) UnmarshalWireValue(in []byte) error {
	if c == nil {
		return errors.New("nil reshare commitments receiver")
	}
	var parsed commitmentVector
	if err := parsed.unmarshalWireValue(in, "reshare", false); err != nil {
		return err
	}
	*c = reshareCommitments(parsed)
	return nil
}

// Validate checks reshare commitment length-independent point invariants.
func (c reshareCommitments) Validate() error { return commitmentVector(c).validate(false) }

// ValidateThreshold checks the exact threshold and all point invariants.
func (c reshareCommitments) ValidateThreshold(threshold int) error {
	return commitmentVector(c).validateThreshold(threshold, false)
}

// PointAt returns an independent copy of the commitment at index i.
func (c reshareCommitments) PointAt(i int) (*fed.Point, error) {
	return commitmentVector(c).pointAt(i)
}

// VerifyShare checks a scalar share against the commitment polynomial.
func (c reshareCommitments) VerifyShare(id tss.PartyID, share *fed.Scalar) error {
	return commitmentVector(c).verifyShare(id, share)
}

func newGroupCommitmentsFromBytesList(in [][]byte, threshold int) (groupCommitments, error) {
	c, err := newCommitmentVectorFromBytesList(in, threshold, true)
	return groupCommitments(c), err
}

func newGroupCommitmentsFromPoints(in []*fed.Point, threshold int) (groupCommitments, error) {
	c, err := newCommitmentVectorFromPoints(in, threshold, true)
	return groupCommitments(c), err
}

// BytesList returns caller-owned canonical encodings of the group commitments.
func (c groupCommitments) BytesList() [][]byte { return commitmentVector(c).bytesList() }

// Equal reports whether two ordered group commitment sets are equal.
func (c groupCommitments) Equal(other groupCommitments) bool {
	return commitmentVector(c).equal(commitmentVector(other))
}

// Clone returns an independent copy of the group commitment set.
func (c groupCommitments) Clone() groupCommitments {
	return groupCommitments(commitmentVector(c).clone())
}

// Len returns the number of group commitments.
func (c groupCommitments) Len() int { return len(c.points) }

// MarshalWireValue returns the canonical encoding of the group commitments.
func (c groupCommitments) MarshalWireValue() ([]byte, error) {
	return commitmentVector(c).marshalWireValue("group", true)
}

// UnmarshalWireValue decodes and validates canonical group commitments.
func (c *groupCommitments) UnmarshalWireValue(in []byte) error {
	if c == nil {
		return errors.New("nil group commitments receiver")
	}
	var parsed commitmentVector
	if err := parsed.unmarshalWireValue(in, "group", true); err != nil {
		return err
	}
	*c = groupCommitments(parsed)
	return nil
}

// Validate checks group commitment length-independent point invariants.
func (c groupCommitments) Validate() error { return commitmentVector(c).validate(true) }

// ValidateThreshold checks the exact threshold and all point invariants.
func (c groupCommitments) ValidateThreshold(threshold int) error {
	return commitmentVector(c).validateThreshold(threshold, true)
}

// PointAtAllowIdentity returns an independent copy of the commitment at index i.
func (c groupCommitments) PointAtAllowIdentity(i int) (*fed.Point, error) {
	if i < 0 || i >= len(c.points) {
		return nil, fmt.Errorf("commitment index %d out of range", i)
	}
	point := clonePoint(c.points[i])
	if point == nil {
		return nil, fmt.Errorf("nil commitment %d", i)
	}
	if _, err := edcurve.PointFromBytesAllowIdentity(point.Bytes()); err != nil {
		return nil, err
	}
	return point, nil
}

// PublicKey returns the constant-term group public key.
func (c groupCommitments) PublicKey() PublicKeyPoint {
	if len(c.points) == 0 {
		return PublicKeyPoint{}
	}
	return PublicKeyPoint{p: clonePoint(c.points[0])}
}

// Eval evaluates the group commitment polynomial for a participant.
func (c groupCommitments) Eval(id tss.PartyID) (VerificationSharePoint, error) {
	point, err := evalCommitmentPoints(c.points, id)
	if err != nil {
		return VerificationSharePoint{}, err
	}
	return newVerificationSharePointFromPoint(point)
}
