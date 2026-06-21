package signprep

import (
	"errors"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// Verify checks a signprep proof against its statement.
func Verify(stmt Statement, proof *Proof) error {
	if proof == nil {
		return errors.New("signprep: nil proof")
	}
	if err := validateStatement(stmt); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}

	kPoint, err := secp.PointFromBytes(stmt.KPoint)
	if err != nil {
		return err
	}
	chiPoint, err := secp.PointFromBytes(stmt.ChiPoint)
	if err != nil {
		return err
	}
	// MPoint == nil represents the point at infinity (M_i = 0).
	mtaIsZero := len(proof.MPoint) == 0
	var mPoint *secp.Point
	if !mtaIsZero {
		mPoint, err = secp.PointFromBytes(proof.MPoint)
		if err != nil {
			return err
		}
	}

	kCommitPoint, err := secp.PointFromBytes(proof.KCommitment)
	if err != nil {
		return err
	}
	dleqA1Point, err := secp.PointFromBytes(proof.DLEQA1)
	if err != nil {
		return err
	}
	dleqA2Point, err := secp.PointFromBytes(proof.DLEQA2)
	if err != nil {
		return err
	}
	kResponse, err := secp.ScalarFromBytes(proof.KResponse.FixedBytes())
	if err != nil {
		return err
	}
	dleqResponse, err := secp.ScalarFromBytes(proof.DLEQResponse.FixedBytes())
	if err != nil {
		return err
	}

	// Decode M_i Schnorr fields only when M_i is non-zero.
	var mCommitPoint *secp.Point
	var mResponse secp.Scalar
	if !mtaIsZero {
		mCommitPoint, err = secp.PointFromBytes(proof.MCommitment)
		if err != nil {
			return err
		}
		mResponse, err = secp.ScalarFromBytes(proof.MResponse)
		if err != nil {
			return err
		}
	}

	xBarPoint, err := secp.PointFromBytes(stmt.XBarPoint)
	if err != nil {
		return err
	}
	combinedBase := xBarPoint
	if len(stmt.AdditiveShift) > 0 {
		shift, err := secp.ScalarFromBytesAllowZero(stmt.AdditiveShift)
		if err != nil {
			return err
		}
		if !shift.IsZero() {
			combinedBase = secp.Add(combinedBase, secp.ScalarBaseMult(shift))
		}
	}

	challengeScalar, err := transcript(stmt, proof.KCommitment, proof.MCommitment, proof.DLEQA1, proof.DLEQA2, proof.MPoint)
	if err != nil {
		return err
	}

	// Schnorr for k_i: kResponse * G == KCommit + e * KPoint.
	lhsK := secp.ScalarBaseMult(kResponse)
	rhsK := secp.Add(kCommitPoint, secp.ScalarMult(kPoint, challengeScalar))
	if !secp.Equal(lhsK, rhsK) {
		return errors.New("signprep: Schnorr verification for KPoint failed")
	}

	// Schnorr for M_i (only when M_i is non-zero).
	if !mtaIsZero {
		lhsM := secp.ScalarBaseMult(mResponse)
		rhsM := secp.Add(mCommitPoint, secp.ScalarMult(mPoint, challengeScalar))
		if !secp.Equal(lhsM, rhsM) {
			return errors.New("signprep: Schnorr verification for MPoint failed")
		}
	}

	// DLEQ: dleqResponse * G == DLEQA1 + e * KPoint.
	lhsD1 := secp.ScalarBaseMult(dleqResponse)
	rhsD1 := secp.Add(dleqA1Point, secp.ScalarMult(kPoint, challengeScalar))
	if !secp.Equal(lhsD1, rhsD1) {
		return errors.New("signprep: DLEQ G-side verification failed")
	}

	// DLEQ: dleqResponse * CombinedBase == DLEQA2 + e * (ChiPoint - MPoint).
	lhsD2 := secp.ScalarMult(combinedBase, dleqResponse)
	// When MPoint is infinity (M_i = 0), ChiPoint - MPoint = ChiPoint.
	var chiMinusM *secp.Point
	if mtaIsZero {
		chiMinusM = chiPoint
	} else {
		negMPoint := secp.Clone(mPoint)
		negMPoint.Y = secp.FieldNeg(mPoint.Y)
		chiMinusM = secp.Add(chiPoint, negMPoint)
	}
	rhsD2 := secp.Add(dleqA2Point, secp.ScalarMult(chiMinusM, challengeScalar))
	if !secp.Equal(lhsD2, rhsD2) {
		return errors.New("signprep: DLEQ combined-base verification failed")
	}

	return nil
}
