package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

// normalizedPresignCommitment is the public Figure 8 output for one signer.
// An empty point encoding is the canonical group identity; this is necessary
// because a legitimate local delta or chi field element may be zero.
type normalizedPresignCommitment struct {
	Party      tss.PartyID `wire:"1,u32"`
	DeltaTilde []byte      `wire:"2,bytes,max_bytes=point"`
	STilde     []byte      `wire:"3,bytes,max_bytes=point"`
}

func (c normalizedPresignCommitment) clone() normalizedPresignCommitment {
	return normalizedPresignCommitment{
		Party: c.Party, DeltaTilde: append([]byte(nil), c.DeltaTilde...), STilde: append([]byte(nil), c.STilde...),
	}
}

func (c *normalizedPresignCommitment) destroy() {
	if c == nil {
		return
	}
	clear(c.DeltaTilde)
	clear(c.STilde)
	*c = normalizedPresignCommitment{}
}

func encodePresignGroupElement(point *secp.Point) ([]byte, error) {
	if point == nil {
		return nil, errors.New("nil presign group element")
	}
	if point.Inf != 0 {
		return nil, nil
	}
	return secp.PointBytes(point)
}

func decodePresignGroupElement(encoded []byte) (*secp.Point, error) {
	if len(encoded) == 0 {
		return secp.NewInfinity(), nil
	}
	point, err := secp.PointFromBytes(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid presign group element: %w", err)
	}
	return point, nil
}

// validateNormalizedPresignArtifact checks the exact Figure 8 output
// invariants. kTilde must be non-zero; chiTilde may be zero. The aggregate
// commitment equations are the normalized forms of g^delta=product(Delta_i)
// and X^delta=product(S_i).
func validateNormalizedPresignArtifact(
	signers tss.PartySet,
	commitments []normalizedPresignCommitment,
	localParty tss.PartyID,
	gamma, publicKey *secp.Point,
	kTilde, chiTilde secp.Scalar,
) error {
	if len(signers) == 0 || len(commitments) != len(signers) {
		return errors.New("normalized presign commitment set mismatch")
	}
	if err := wire.ValidateStrictSortedIDs(signers); err != nil {
		return fmt.Errorf("invalid normalized presign signer set: %w", err)
	}
	if !tss.ContainsParty(signers, localParty) {
		return errors.New("normalized presign local party is not a signer")
	}
	if _, err := secp.PointBytes(gamma); err != nil {
		return fmt.Errorf("invalid normalized presign Gamma: %w", err)
	}
	if _, err := secp.PointBytes(publicKey); err != nil {
		return fmt.Errorf("invalid normalized presign public key: %w", err)
	}
	if kTilde.IsZero() {
		return errors.New("normalized presign k share is zero")
	}
	if secp.ScalarFromFieldElement(gamma.X).IsZero() {
		return errors.New("normalized presign Gamma yields zero ECDSA r")
	}

	deltaPoints := make([]*secp.Point, 0, len(commitments))
	sPoints := make([]*secp.Point, 0, len(commitments))
	var local *normalizedPresignCommitment
	for i := range commitments {
		commitment := &commitments[i]
		if commitment.Party != signers[i] {
			return fmt.Errorf("normalized presign party %d is out of signer order", commitment.Party)
		}
		deltaPoint, err := decodePresignGroupElement(commitment.DeltaTilde)
		if err != nil {
			return fmt.Errorf("party %d DeltaTilde: %w", commitment.Party, err)
		}
		sPoint, err := decodePresignGroupElement(commitment.STilde)
		if err != nil {
			return fmt.Errorf("party %d STilde: %w", commitment.Party, err)
		}
		deltaPoints = append(deltaPoints, deltaPoint)
		sPoints = append(sPoints, sPoint)
		if commitment.Party == localParty {
			local = commitment
		}
	}
	if local == nil {
		return errors.New("normalized presign local commitment is missing")
	}
	if !secp.Equal(secp.AddPoints(deltaPoints...), secp.G) {
		return errors.New("normalized presign Delta commitments do not aggregate to the generator")
	}
	if !secp.Equal(secp.AddPoints(sPoints...), publicKey) {
		return errors.New("normalized presign S commitments do not aggregate to the public key")
	}
	localDelta, err := decodePresignGroupElement(local.DeltaTilde)
	if err != nil {
		return err
	}
	if !secp.Equal(localDelta, secp.ScalarMult(gamma, kTilde)) {
		return errors.New("normalized presign local k share does not open DeltaTilde")
	}
	localS, err := decodePresignGroupElement(local.STilde)
	if err != nil {
		return err
	}
	if !secp.Equal(localS, secp.ScalarMult(gamma, chiTilde)) {
		return errors.New("normalized presign local chi share does not open STilde")
	}
	return nil
}

// verifyFigure10Partial checks Gamma^sigma_i =
// DeltaTilde_i^m * STilde_i^r in the repository's additive curve notation.
func verifyFigure10Partial(
	gamma *secp.Point,
	commitment normalizedPresignCommitment,
	message, littleR, sigma secp.Scalar,
) error {
	if _, err := secp.PointBytes(gamma); err != nil {
		return fmt.Errorf("invalid signing Gamma: %w", err)
	}
	delta, err := decodePresignGroupElement(commitment.DeltaTilde)
	if err != nil {
		return err
	}
	sPoint, err := decodePresignGroupElement(commitment.STilde)
	if err != nil {
		return err
	}
	lhs := secp.ScalarMult(gamma, sigma)
	rhs := secp.Add(secp.ScalarMult(delta, message), secp.ScalarMult(sPoint, littleR))
	if !secp.Equal(lhs, rhs) {
		return errors.New("figure 10 partial equation failed")
	}
	return nil
}
