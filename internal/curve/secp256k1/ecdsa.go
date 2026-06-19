package secp256k1

import (
	"errors"
	"io"
	"math/big"
)

const (
	// PubkeyLength is the compressed public key length
	PubkeyLength = 33
)

// SignECDSA signs a 32-byte digest with a fresh random nonce and always
// returns the canonical low-S form.
func SignECDSA(reader io.Reader, digest []byte, secret Scalar) (r, s Scalar, err error) {
	if len(digest) != 32 {
		return Scalar{}, Scalar{}, errors.New("ECDSA digest must be 32 bytes")
	}
	z, err := ScalarFromBytes(digest)
	if err != nil {
		z = scalarFromBig(new(big.Int).SetBytes(digest))
	}
	for {
		k, err := RandomScalar(reader)
		if err != nil {
			return Scalar{}, Scalar{}, err
		}
		rp := ScalarBaseMult(k)
		if rp.Inf != 0 {
			continue
		}
		r = scalarFromFieldElement(rp.X)
		if r.IsZero() {
			continue
		}
		kinv, err := ScalarInvert(k)
		if err != nil {
			continue
		}
		s = ScalarMul(ScalarAdd(ScalarMul(r, secret), z), kinv)
		if s.IsZero() {
			continue
		}
		if !IsLowS(s) {
			s = ScalarNeg(s)
		}
		return r, s, nil
	}
}

// VerifyECDSA verifies a secp256k1 ECDSA signature over a 32-byte digest.
func VerifyECDSA(public *Point, digest []byte, r, s Scalar) bool {
	if len(digest) != 32 || public == nil || public.Inf != 0 || !IsOnCurve(public) {
		return false
	}
	if r.IsZero() || s.IsZero() {
		return false
	}
	z, err := ScalarFromBytes(digest)
	if err != nil {
		z = scalarFromBig(new(big.Int).SetBytes(digest))
	}
	w, err := ScalarInvert(s)
	if err != nil {
		return false
	}
	u1 := ScalarMul(z, w)
	u2 := ScalarMul(r, w)
	p1 := ScalarBaseMult(u1)
	p2 := ScalarMult(public, u2)
	x := Add(p1, p2)
	if x.Inf != 0 {
		return false
	}
	v := scalarFromFieldElement(x.X)
	return v.Equal(r)
}
