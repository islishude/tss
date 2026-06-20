package secp256k1

import "errors"

// VerifyShare checks a Shamir share against Feldman-style commitments.
func VerifyShare(commitments [][]byte, id uint32, share Scalar) error {
	left := ScalarBaseMult(share)
	points, err := CommitmentPointsFromBytes(commitments)
	if err != nil {
		return err
	}
	right, err := EvalCommitmentPoints(points, id)
	if err != nil {
		return err
	}
	if !Equal(left, right) {
		return errors.New("share does not match commitments")
	}
	return nil
}

// VerifySharePoints checks a Shamir share against already-decoded
// Feldman-style commitments. A nil commitment entry is a zero coefficient.
func VerifySharePoints(commitments []*Point, id uint32, share Scalar) error {
	left := ScalarBaseMult(share)
	right, err := EvalCommitmentPoints(commitments, id)
	if err != nil {
		return err
	}
	if !Equal(left, right) {
		return errors.New("share does not match commitments")
	}
	return nil
}

// EvalCommitments evaluates public polynomial commitments at participant id.
// A nil commitment entry represents the point at infinity (a zero coefficient).
func EvalCommitments(commitments [][]byte, id uint32) (*Point, error) {
	points, err := CommitmentPointsFromBytes(commitments)
	if err != nil {
		return nil, err
	}
	return EvalCommitmentPoints(points, id)
}

// EvalCommitmentPoints evaluates public polynomial commitments at participant
// id. A nil commitment entry represents the point at infinity (a zero
// coefficient).
func EvalCommitmentPoints(commitments []*Point, id uint32) (*Point, error) {
	x := scalarFromUint64(uint64(id))
	pow := ScalarOne()
	acc := NewInfinity()
	for _, commitment := range commitments {
		if commitment == nil {
			pow = ScalarMul(pow, x)
			continue
		}
		term := ScalarMult(commitment, pow)
		acc = Add(acc, term)
		pow = ScalarMul(pow, x)
	}
	return acc, nil
}

// CommitmentPointsFromBytes decodes commitment bytes while preserving empty
// entries as nil zero-coefficient commitments.
func CommitmentPointsFromBytes(commitments [][]byte) ([]*Point, error) {
	out := make([]*Point, len(commitments))
	for i, enc := range commitments {
		if len(enc) == 0 {
			continue
		}
		point, err := PointFromBytes(enc)
		if err != nil {
			return nil, err
		}
		out[i] = point
	}
	return out, nil
}

// CommitmentPointsBytes encodes commitment points while preserving nil entries
// as empty zero-coefficient commitments.
func CommitmentPointsBytes(commitments []*Point) ([][]byte, error) {
	out := make([][]byte, len(commitments))
	for i, commitment := range commitments {
		if commitment == nil {
			out[i] = []byte{}
			continue
		}
		enc, err := PointBytes(commitment)
		if err != nil {
			return nil, err
		}
		out[i] = enc
	}
	return out, nil
}
