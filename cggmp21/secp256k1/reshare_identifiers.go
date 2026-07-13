package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const reshareProvisionalIdentifierLabel = "cggmp21-secp256k1-reshare-provisional-identifier"

func deriveReshareProvisionalIdentifiers(
	stableSID tss.SessionID,
	sourceEpochID []byte,
	runSessionID tss.SessionID,
	planHash []byte,
	parties tss.PartySet,
) (map[tss.PartyID][]byte, error) {
	if !stableSID.Valid() || !runSessionID.Valid() {
		return nil, errors.New("derive reshare provisional identifiers: invalid session binding")
	}
	if len(sourceEpochID) != 32 || len(planHash) != 32 {
		return nil, errors.New("derive reshare provisional identifiers: invalid epoch or plan hash")
	}
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return nil, fmt.Errorf("derive reshare provisional identifiers: %w", err)
	}
	out := make(map[tss.PartyID][]byte, len(parties))
	seen := make(map[[secp.ScalarSize]byte]tss.PartyID, len(parties))
	for _, party := range parties {
		identifier, err := deriveEpochIdentifierWithDigest(func(counter uint32) []byte {
			t := transcript.New(reshareProvisionalIdentifierLabel)
			t.AppendBytes("stable_sid", stableSID[:])
			t.AppendBytes("source_epoch_id", sourceEpochID)
			t.AppendBytes("run_session_id", runSessionID[:])
			t.AppendBytes("plan_hash", planHash)
			t.AppendUint32("party", party)
			t.AppendUint32("counter", counter)
			return t.Sum()
		})
		if err != nil {
			return nil, fmt.Errorf("derive provisional identifier for party %d: %w", party, err)
		}
		var key [secp.ScalarSize]byte
		copy(key[:], identifier)
		if other, ok := seen[key]; ok {
			clear(identifier)
			return nil, fmt.Errorf("provisional identifier collision between parties %d and %d", other, party)
		}
		seen[key] = party
		out[party] = identifier
	}
	return out, nil
}

func provisionalLagrangeCoefficient(identifiers map[tss.PartyID][]byte, party tss.PartyID, parties tss.PartySet) (secp.Scalar, error) {
	all := make([]shamir.Identifier, 0, len(parties))
	var target shamir.Identifier
	found := false
	for _, id := range parties {
		encoded, ok := identifiers[id]
		if !ok {
			return secp.Scalar{}, fmt.Errorf("missing provisional identifier for party %d", id)
		}
		parsed, err := shamir.IdentifierFromBytes(encoded)
		if err != nil {
			return secp.Scalar{}, err
		}
		all = append(all, parsed)
		if id == party {
			target = parsed
			found = true
		}
	}
	if !found {
		return secp.Scalar{}, fmt.Errorf("party %d is outside target committee", party)
	}
	return shamir.LagrangeCoefficientAt(target, all)
}
