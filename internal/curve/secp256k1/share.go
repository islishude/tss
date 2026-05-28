package secp256k1

import "errors"

// VerifyShare checks a Shamir share against Feldman-style commitments.
func VerifyShare(commitments [][]byte, id uint32, share Scalar) error {
	left := ScalarBaseMult(share)
	right, err := EvalCommitments(commitments, id)
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
	x := scalarFromUint64(uint64(id))
	pow := ScalarOne()
	acc := NewInfinity()
	for _, enc := range commitments {
		if len(enc) == 0 {
			pow = ScalarMul(pow, x)
			continue
		}
		c, err := PointFromBytes(enc)
		if err != nil {
			return nil, err
		}
		term := ScalarMult(c, pow)
		acc = Add(acc, term)
		pow = ScalarMul(pow, x)
	}
	return acc, nil
}
