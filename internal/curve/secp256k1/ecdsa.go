package secp256k1

import (
	"bytes"
	"errors"
	"io"
	"math/big"
)

// SignECDSA signs a 32-byte digest with a fresh random nonce.
func SignECDSA(reader io.Reader, digest []byte, secret Scalar, lowS bool) (r, s Scalar, err error) {
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
		if rp.Inf {
			continue
		}
		r = scalarFromBig(new(big.Int).Mod(rp.X.BigInt(), Order()))
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
		if lowS {
			half := halfOrder()
			if !scalarLessOrEqual(s, half) {
				s = ScalarNeg(s)
			}
		}
		return r, s, nil
	}
}

// SignECDSAWithNonce signs with caller-provided nonce material for tests only.
func SignECDSAWithNonce(digest []byte, secret, nonce Scalar, lowS bool) (r, s Scalar, err error) {
	if len(digest) != 32 {
		return Scalar{}, Scalar{}, errors.New("ECDSA digest must be 32 bytes")
	}
	if secret.IsZero() || nonce.IsZero() {
		return Scalar{}, Scalar{}, errors.New("secret and nonce must be non-zero")
	}
	z, err := ScalarFromBytes(digest)
	if err != nil {
		z = scalarFromBig(new(big.Int).SetBytes(digest))
	}
	rp := ScalarBaseMult(nonce)
	if rp.Inf {
		return Scalar{}, Scalar{}, errors.New("nonce produced infinity")
	}
	r = scalarFromBig(new(big.Int).Mod(rp.X.BigInt(), Order()))
	if r.IsZero() {
		return Scalar{}, Scalar{}, errors.New("nonce produced zero r")
	}
	kinv, err := ScalarInvert(nonce)
	if err != nil {
		return Scalar{}, Scalar{}, errors.New("nonce is not invertible")
	}
	s = ScalarMul(ScalarAdd(ScalarMul(r, secret), z), kinv)
	if s.IsZero() {
		return Scalar{}, Scalar{}, errors.New("zero s")
	}
	if lowS {
		half := halfOrder()
		if !scalarLessOrEqual(s, half) {
			s = ScalarNeg(s)
		}
	}
	return r, s, nil
}

// VerifyECDSA verifies a secp256k1 ECDSA signature over a 32-byte digest.
func VerifyECDSA(public *Point, digest []byte, r, s Scalar) bool {
	if len(digest) != 32 || public == nil || public.Inf || !IsOnCurve(public) {
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
	if x.Inf {
		return false
	}
	v := scalarFromBig(new(big.Int).Mod(x.X.BigInt(), Order()))
	return v.Equal(r)
}

func scalarLessOrEqual(a, b Scalar) bool {
	return bytes.Compare(a.Bytes(), b.Bytes()) <= 0
}
