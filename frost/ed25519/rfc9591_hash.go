package ed25519

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func rfc9591H1(input []byte) (*fed.Scalar, error) {
	h := sha512.New()
	h.Write([]byte(rfc9591ContextString))
	h.Write([]byte("rho"))
	h.Write(input)
	return fed.NewScalar().SetUniformBytes(h.Sum(nil))
}

func rfc9591H4(msg []byte) []byte {
	h := sha512.New()
	h.Write([]byte(rfc9591ContextString))
	h.Write([]byte("msg"))
	h.Write(msg)
	return h.Sum(nil)
}

func rfc9591H5(encodedCommitmentList []byte) []byte {
	h := sha512.New()
	h.Write([]byte(rfc9591ContextString))
	h.Write([]byte("com"))
	h.Write(encodedCommitmentList)
	return h.Sum(nil)
}

func partyIDScalarEncoding(id tss.PartyID) ([]byte, error) {
	s, err := edcurve.ScalarFromBig(new(big.Int).SetUint64(uint64(id)))
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

func encodeGroupCommitmentList(signers []tss.PartyID, commitments map[tss.PartyID]nonceCommitment) ([]byte, error) {
	out := make([]byte, 0, len(signers)*(32+32+32))
	for _, id := range signers {
		commitment, ok := commitments[id]
		if !ok {
			return nil, fmt.Errorf("missing commitment for %d", id)
		}
		idEnc, err := partyIDScalarEncoding(id)
		if err != nil {
			return nil, err
		}
		if _, err := edcurve.PointFromBytes(commitment.D); err != nil {
			return nil, err
		}
		if _, err := edcurve.PointFromBytes(commitment.E); err != nil {
			return nil, err
		}
		out = append(out, idEnc...)
		out = append(out, commitment.D...)
		out = append(out, commitment.E...)
	}
	return out, nil
}
