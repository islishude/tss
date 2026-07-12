package signprep

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
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
	kScalar, mScalar, chiScalar, err := witnessScalars(wit)
	if err != nil {
		return nil, err
	}
	kPoint, err := secp.PointFromBytes(stmt.KPoint)
	if err != nil {
		return nil, err
	}
	if !secp.Equal(secp.ScalarBaseMult(kScalar), kPoint) {
		return nil, errors.New("signprep: k share does not match KPoint")
	}
	chiPoint, err := secp.PointFromBytes(stmt.ChiPoint)
	if err != nil {
		return nil, err
	}
	if !secp.Equal(secp.ScalarBaseMult(chiScalar), chiPoint) {
		return nil, errors.New("signprep: chi share does not match ChiPoint")
	}
	mtaIsZero := mScalar.IsZero()

	// Compute MPoint = M_i * G. When M_i = 0, MPoint is the identity (point at
	// infinity) which has no compressed encoding — we represent it as nil.
	// This is common for 1-of-1 signing where there are no MTA contributions.
	var mPoint []byte
	if !mtaIsZero {
		mPoint, err = secp.PointBytes(secp.ScalarBaseMult(mScalar))
		if err != nil {
			return nil, err
		}
	}
	mtaBase, err := optionalPointFromBytes(stmt.MTABasePoint)
	if err != nil {
		return nil, fmt.Errorf("signprep: invalid MTA base point: %w", err)
	}
	mtaOffset, err := optionalPointFromBytes(stmt.MTAOffsetPoint)
	if err != nil {
		return nil, fmt.Errorf("signprep: invalid MTA offset point: %w", err)
	}
	mPointValue := secp.NewInfinity()
	if !mtaIsZero {
		mPointValue = secp.ScalarBaseMult(mScalar)
	}
	if !secp.Equal(subtractPoints(mPointValue, mtaOffset), secp.ScalarMult(mtaBase, kScalar)) {
		return nil, errors.New("signprep: MTA sum does not match bound contributions")
	}
	deltaBase, err := optionalPointFromBytes(stmt.DeltaBasePoint)
	if err != nil {
		return nil, fmt.Errorf("signprep: invalid delta base point: %w", err)
	}
	deltaOffset, err := optionalPointFromBytes(stmt.DeltaOffsetPoint)
	if err != nil {
		return nil, fmt.Errorf("signprep: invalid delta offset point: %w", err)
	}
	deltaScalar, err := secp.ScalarFromBytesAllowZero(stmt.Delta)
	if err != nil {
		return nil, fmt.Errorf("signprep: invalid delta scalar: %w", err)
	}
	deltaTarget := subtractPoints(secp.ScalarBaseMult(deltaScalar), deltaOffset)
	if !secp.Equal(deltaTarget, secp.ScalarMult(deltaBase, kScalar)) {
		return nil, errors.New("signprep: delta share does not match bound MtA contributions")
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
	var mtaRelationCommitment []byte
	if mtaBase.Inf == 0 {
		mtaRelationCommitment, err = secp.PointBytes(secp.ScalarMult(mtaBase, dleqNonce))
		if err != nil {
			return nil, err
		}
	}
	var deltaRelationCommitment []byte
	if deltaBase.Inf == 0 {
		deltaRelationCommitment, err = secp.PointBytes(secp.ScalarMult(deltaBase, dleqNonce))
		if err != nil {
			return nil, err
		}
	}

	// Derive challenge. nil mCommit/mPoint are identity elements and contribute
	// the same length-prefixed zero bytes to the transcript.
	challengeScalar, err := transcript(stmt, kCommit, mCommit, dleqA1, dleqA2, mtaRelationCommitment, deltaRelationCommitment, mPoint)
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
		MPoint:                  mPoint,
		KCommitment:             kCommit,
		MCommitment:             mCommit,
		DLEQA1:                  dleqA1,
		DLEQA2:                  dleqA2,
		KResponse:               kRespScalar,
		MResponse:               mResponse,
		DLEQResponse:            dleqRespScalar,
		MTARelationCommitment:   mtaRelationCommitment,
		DeltaRelationCommitment: deltaRelationCommitment,
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
	if err := wire.ValidateStrictSortedIDs(stmt.Signers); err != nil {
		return fmt.Errorf("signprep: invalid signers: %w", err)
	}
	if !stmt.Signers.Contains(stmt.Party) {
		return errors.New("signprep: party is not in signer set")
	}
	if len(stmt.PlanHash) != 32 {
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
	if len(stmt.Round2CommitmentsHash) != 32 {
		return errors.New("signprep: round2 commitments hash must be 32 bytes")
	}
	if len(stmt.MTAContributionsHash) != 32 {
		return errors.New("signprep: MTA contributions hash must be 32 bytes")
	}
	if len(stmt.MTABasePoint) > 0 {
		if _, err := secp.PointFromBytes(stmt.MTABasePoint); err != nil {
			return errors.New("signprep: invalid MTA base point")
		}
	}
	if len(stmt.MTAOffsetPoint) > 0 {
		if _, err := secp.PointFromBytes(stmt.MTAOffsetPoint); err != nil {
			return errors.New("signprep: invalid MTA offset point")
		}
	}
	if len(stmt.DeltaBasePoint) > 0 {
		if _, err := secp.PointFromBytes(stmt.DeltaBasePoint); err != nil {
			return errors.New("signprep: invalid delta base point")
		}
	}
	if len(stmt.DeltaOffsetPoint) > 0 {
		if _, err := secp.PointFromBytes(stmt.DeltaOffsetPoint); err != nil {
			return errors.New("signprep: invalid delta offset point")
		}
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

func witnessScalars(wit Witness) (kShare, mtaSum, chiShare secp.Scalar, err error) {
	kShare, err = witnessScalar(wit.KShare, false, "k share")
	if err != nil {
		return secp.Scalar{}, secp.Scalar{}, secp.Scalar{}, err
	}
	mtaSum, err = witnessScalar(wit.MTASum, true, "MTA sum")
	if err != nil {
		return secp.Scalar{}, secp.Scalar{}, secp.Scalar{}, err
	}
	chiShare, err = witnessScalar(wit.ChiShare, false, "chi share")
	if err != nil {
		return secp.Scalar{}, secp.Scalar{}, secp.Scalar{}, err
	}
	return kShare, mtaSum, chiShare, nil
}

func witnessScalar(value *secret.Scalar, allowZero bool, name string) (secp.Scalar, error) {
	if value == nil {
		return secp.Scalar{}, fmt.Errorf("signprep: %s must not be nil", name)
	}
	raw := value.FixedBytes()
	defer clear(raw)
	if allowZero {
		scalar, err := secp.ScalarFromBytesAllowZero(raw)
		if err != nil {
			return secp.Scalar{}, fmt.Errorf("signprep: invalid %s: %w", name, err)
		}
		return scalar, nil
	}
	scalar, err := secp.ScalarFromBytes(raw)
	if err != nil {
		return secp.Scalar{}, fmt.Errorf("signprep: invalid %s: %w", name, err)
	}
	return scalar, nil
}

func newProofScalar(data []byte) (*secret.Scalar, error) {
	s, err := secret.NewScalar(data, secp.ScalarSize)
	if err != nil {
		return nil, fmt.Errorf("signprep: invalid proof scalar: %w", err)
	}
	return s, nil
}
