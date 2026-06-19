package signprep

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

// Prove generates a signprep proof binding KPoint and ChiPoint to the presign
// transcript described by stmt.
func Prove(rng io.Reader, stmt Statement, wit Witness) (*Proof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := validateStatement(stmt); err != nil {
		return nil, err
	}
	if err := validateWitness(wit); err != nil {
		return nil, err
	}
	kShare := new(big.Int).Set(wit.KShare)
	defer secret.ClearBigInt(kShare)
	mtaSum := new(big.Int).Set(wit.MTASum)
	defer secret.ClearBigInt(mtaSum)
	mtaIsZero := mtaSum.Sign() == 0

	// Compute MPoint = M_i * G. When M_i = 0, MPoint is the identity (point at
	// infinity) which has no compressed encoding — we represent it as nil.
	// This is common for 1-of-1 signing where there are no MTA contributions.
	var mPoint []byte
	var mScalar secp.Scalar
	if !mtaIsZero {
		var err error
		mScalar, err = secp.ScalarFromBytes(scalarFixedBytes(mtaSum))
		if err != nil {
			return nil, err
		}
		mPoint, err = secp.PointBytes(secp.ScalarBaseMult(mScalar))
		if err != nil {
			return nil, err
		}
	}

	// Generate nonces.
	kNonce, err := secp.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	dleqNonce, err := secp.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	// Only generate M nonce when M_i is non-zero.
	var mNonce secp.Scalar
	if !mtaIsZero {
		mNonce, err = secp.RandomScalar(rng)
		if err != nil {
			return nil, err
		}
	}

	// Commitments.
	kScalar, err := secp.ScalarFromBytes(scalarFixedBytes(kShare))
	if err != nil {
		return nil, err
	}
	kCommit, err := secp.PointBytes(secp.ScalarBaseMult(kNonce))
	if err != nil {
		return nil, err
	}
	var mCommit []byte
	if !mtaIsZero {
		mCommit, err = secp.PointBytes(secp.ScalarBaseMult(mNonce))
		if err != nil {
			return nil, err
		}
	}
	dleqA1, err := secp.PointBytes(secp.ScalarBaseMult(dleqNonce))
	if err != nil {
		return nil, err
	}

	// Combined base = XBarPoint + shift*G.
	xBarPoint, err := secp.PointFromBytes(stmt.XBarPoint)
	if err != nil {
		return nil, err
	}
	combinedBase := xBarPoint
	if len(stmt.AdditiveShift) > 0 {
		shift, err := secp.ScalarFromBytesAllowZero(stmt.AdditiveShift)
		if err != nil {
			return nil, err
		}
		if !shift.IsZero() {
			combinedBase = secp.Add(combinedBase, secp.ScalarBaseMult(shift))
		}
	}
	dleqA2, err := secp.PointBytes(secp.ScalarMult(combinedBase, dleqNonce))
	if err != nil {
		return nil, err
	}

	// Derive challenge. nil mCommit/mPoint are identity elements and contribute
	// the same length-prefixed zero bytes to the transcript.
	challenge, err := transcript(stmt, kCommit, mCommit, dleqA1, dleqA2, mPoint)
	if err != nil {
		return nil, err
	}
	challengeScalar, err := secp.ScalarFromBytes(scalarFixedBytes(challenge))
	if err != nil {
		return nil, err
	}

	// Responses: r = nonce + challenge * secret.
	kResponse := secp.ScalarAdd(secp.ScalarMul(challengeScalar, kScalar), kNonce)
	dleqResponse := secp.ScalarAdd(secp.ScalarMul(challengeScalar, kScalar), dleqNonce)

	var mResponse []byte
	if !mtaIsZero {
		mr := secp.ScalarAdd(secp.ScalarMul(challengeScalar, mScalar), mNonce)
		mResponse = mr.Bytes()
	}

	kRespScalar, err := newProofScalar(kResponse.Bytes())
	if err != nil {
		return nil, err
	}
	dleqRespScalar, err := newProofScalar(dleqResponse.Bytes())
	if err != nil {
		return nil, err
	}
	return &Proof{
		MPoint:       mPoint,
		KCommitment:  kCommit,
		MCommitment:  mCommit,
		DLEQA1:       dleqA1,
		DLEQA2:       dleqA2,
		KResponse:    kRespScalar,
		MResponse:    mResponse,
		DLEQResponse: dleqRespScalar,
	}, nil
}

func validateStatement(stmt Statement) error {
	if stmt.Protocol == "" {
		return errors.New("signprep: missing protocol")
	}
	if !stmt.SessionID.Valid() {
		return errors.New("signprep: missing session id")
	}
	if stmt.Party == 0 {
		return errors.New("signprep: missing party")
	}
	if len(stmt.Signers) == 0 {
		return errors.New("signprep: missing signers")
	}
	if len(stmt.PlanHash) != 0 && len(stmt.PlanHash) != 32 {
		return errors.New("signprep: plan hash must be 32 bytes")
	}
	if len(stmt.ContextHash) != 32 {
		return errors.New("signprep: context hash must be 32 bytes")
	}
	if len(stmt.PublicKey) == 0 {
		return errors.New("signprep: missing public key")
	}
	if len(stmt.KeygenTranscriptHash) != 32 {
		return errors.New("signprep: keygen transcript hash must be 32 bytes")
	}
	if len(stmt.PartiesHash) != 32 {
		return errors.New("signprep: parties hash must be 32 bytes")
	}
	if len(stmt.EncK) == 0 {
		return errors.New("signprep: missing enc k")
	}
	if len(stmt.PaillierPublicKey) == 0 {
		return errors.New("signprep: missing paillier public key")
	}
	if len(stmt.Gamma) == 0 {
		return errors.New("signprep: missing gamma")
	}
	if _, err := secp.PointFromBytes(stmt.KPoint); err != nil {
		return errors.New("signprep: invalid KPoint")
	}
	if _, err := secp.PointFromBytes(stmt.ChiPoint); err != nil {
		return errors.New("signprep: invalid ChiPoint")
	}
	if _, err := secp.PointFromBytes(stmt.XBarPoint); err != nil {
		return errors.New("signprep: invalid XBarPoint")
	}
	return nil
}

func validateWitness(wit Witness) error {
	if wit.KShare == nil || wit.KShare.Sign() == 0 {
		return errors.New("signprep: k share must be non-zero")
	}
	if wit.ChiShare == nil || wit.ChiShare.Sign() == 0 {
		return errors.New("signprep: chi share must be non-zero")
	}
	if wit.MTASum == nil {
		return errors.New("signprep: MTA sum must not be nil")
	}
	return nil
}

func scalarFixedBytes(x *big.Int) []byte {
	return secp.ScalarFromBigInt(x).Bytes()
}

func newProofScalar(data []byte) (*secret.Scalar, error) {
	s, err := secret.NewScalar(data, secp.ScalarSize)
	if err != nil {
		return nil, fmt.Errorf("signprep: invalid proof scalar: %w", err)
	}
	return s, nil
}
