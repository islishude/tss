package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire"
)

func epochLagrangeCoefficient(epoch *EpochContext, party tss.PartyID, signers tss.PartySet) (secp.Scalar, error) {
	if epoch == nil {
		return secp.Scalar{}, errors.New("missing epoch context")
	}
	if err := wire.ValidateStrictSortedIDs(signers); err != nil {
		return secp.Scalar{}, err
	}
	identifiers := make([]shamir.Identifier, 0, len(signers))
	var target shamir.Identifier
	found := false
	for _, signer := range signers {
		encoded, ok := epoch.Identifier(signer)
		if !ok {
			return secp.Scalar{}, fmt.Errorf("missing epoch identifier for signer %d", signer)
		}
		identifier, err := shamir.IdentifierFromBytes(encoded)
		clear(encoded)
		if err != nil {
			return secp.Scalar{}, err
		}
		identifiers = append(identifiers, identifier)
		if signer == party {
			target = identifier
			found = true
		}
	}
	if !found {
		return secp.Scalar{}, fmt.Errorf("party %d is outside signer set", party)
	}
	return shamir.LagrangeCoefficientAt(target, identifiers)
}
