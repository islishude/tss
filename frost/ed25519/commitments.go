package ed25519

import (
	"errors"
	"fmt"
	"math/big"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

type keygenCommitments struct {
	points []*fed.Point
}

type reshareCommitments struct {
	points []*fed.Point
}

type groupCommitments struct {
	points []*fed.Point
}

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

func newKeygenCommitmentsFromBytesList(in [][]byte, threshold int) (keygenCommitments, error) {
	points, err := parseCommitmentBytes(in, threshold, true)
	if err != nil {
		return keygenCommitments{}, err
	}
	return keygenCommitments{points: points}, nil
}

func newKeygenCommitmentsFromPoints(in []*fed.Point, threshold int) (keygenCommitments, error) {
	points, err := parseCommitmentPoints(in, threshold, true)
	if err != nil {
		return keygenCommitments{}, err
	}
	return keygenCommitments{points: points}, nil
}

// BytesList returns caller-owned canonical encodings of the keygen commitments.
func (c keygenCommitments) BytesList() [][]byte {
	return commitmentBytesList(c.points)
}

// Equal reports whether two ordered keygen commitment sets are equal.
func (c keygenCommitments) Equal(other keygenCommitments) bool {
	return equalCommitmentPoints(c.points, other.points)
}

// Clone returns an independent copy of the keygen commitment set.
func (c keygenCommitments) Clone() keygenCommitments {
	return keygenCommitments{points: clonePoints(c.points)}
}

// Len returns the number of keygen commitments.
func (c keygenCommitments) Len() int {
	return len(c.points)
}

// IsZero reports whether the keygen commitment set has not been initialized.
func (c keygenCommitments) IsZero() bool {
	return c.points == nil
}

// PointAt returns an independent copy of the commitment at index i.
func (c keygenCommitments) PointAt(i int) (*fed.Point, error) {
	if i < 0 || i >= len(c.points) {
		return nil, fmt.Errorf("commitment index %d out of range", i)
	}
	return clonePoint(c.points[i]), nil
}

// VerifyShare checks a scalar share against the keygen commitment polynomial.
func (c keygenCommitments) VerifyShare(id tss.PartyID, share *fed.Scalar) error {
	return verifyCommitmentShare(c.points, id, share)
}

func newReshareCommitmentsFromBytesList(in [][]byte, threshold int) (reshareCommitments, error) {
	points, err := parseCommitmentBytes(in, threshold, false)
	if err != nil {
		return reshareCommitments{}, err
	}
	return reshareCommitments{points: points}, nil
}

func newReshareCommitmentsFromPoints(in []*fed.Point, threshold int) (reshareCommitments, error) {
	points, err := parseCommitmentPoints(in, threshold, false)
	if err != nil {
		return reshareCommitments{}, err
	}
	return reshareCommitments{points: points}, nil
}

// BytesList returns caller-owned canonical encodings of the reshare commitments.
func (c reshareCommitments) BytesList() [][]byte {
	return commitmentBytesList(c.points)
}

// Equal reports whether two ordered reshare commitment sets are equal.
func (c reshareCommitments) Equal(other reshareCommitments) bool {
	return equalCommitmentPoints(c.points, other.points)
}

// Clone returns an independent copy of the reshare commitment set.
func (c reshareCommitments) Clone() reshareCommitments {
	return reshareCommitments{points: clonePoints(c.points)}
}

// Len returns the number of reshare commitments.
func (c reshareCommitments) Len() int {
	return len(c.points)
}

// PointAt returns an independent copy of the commitment at index i.
func (c reshareCommitments) PointAt(i int) (*fed.Point, error) {
	if i < 0 || i >= len(c.points) {
		return nil, fmt.Errorf("commitment index %d out of range", i)
	}
	return clonePoint(c.points[i]), nil
}

// VerifyShare checks a scalar share against the reshare commitment polynomial.
func (c reshareCommitments) VerifyShare(id tss.PartyID, share *fed.Scalar) error {
	return verifyCommitmentShare(c.points, id, share)
}

func newGroupCommitmentsFromBytesList(in [][]byte, threshold int) (groupCommitments, error) {
	points, err := parseCommitmentBytes(in, threshold, true)
	if err != nil {
		return groupCommitments{}, err
	}
	return groupCommitments{points: points}, nil
}

func newGroupCommitmentsFromPoints(in []*fed.Point, threshold int) (groupCommitments, error) {
	points, err := parseCommitmentPoints(in, threshold, true)
	if err != nil {
		return groupCommitments{}, err
	}
	return groupCommitments{points: points}, nil
}

// BytesList returns caller-owned canonical encodings of the group commitments.
func (c groupCommitments) BytesList() [][]byte {
	return commitmentBytesList(c.points)
}

// Equal reports whether two ordered group commitment sets are equal.
func (c groupCommitments) Equal(other groupCommitments) bool {
	return equalCommitmentPoints(c.points, other.points)
}

// Clone returns an independent copy of the group commitment set.
func (c groupCommitments) Clone() groupCommitments {
	return groupCommitments{points: clonePoints(c.points)}
}

// Len returns the number of group commitments.
func (c groupCommitments) Len() int {
	return len(c.points)
}

// Validate checks group commitment length-independent point invariants.
func (c groupCommitments) Validate() error {
	_, err := parseCommitmentPoints(c.points, len(c.points), true)
	return err
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
func (c groupCommitments) PublicKey() publicKeyPoint {
	if len(c.points) == 0 {
		return publicKeyPoint{}
	}
	return publicKeyPoint{p: clonePoint(c.points[0])}
}

// Eval evaluates the group commitment polynomial for a participant.
func (c groupCommitments) Eval(id tss.PartyID) (verificationSharePoint, error) {
	point, err := evalCommitmentPoints(c.points, id)
	if err != nil {
		return verificationSharePoint{}, err
	}
	return newVerificationSharePointFromPoint(point)
}
