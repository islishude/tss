package ed25519

import (
	"errors"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func signFROSTSimulation(message []byte, signers []*KeyShare, ctx tss.SigningContext) ([]byte, []byte, error) {
	return signFROSTSimulationWithOptions(message, signers, SignOptions{Context: ctx})
}

func signFROSTSimulationWithOptions(message []byte, signers []*KeyShare, opts SignOptions) ([]byte, []byte, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make(tss.PartySet, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.ValidateConsistency(); err != nil {
			return nil, nil, err
		}
		ids[i] = share.state.Party
		shares[share.state.Party] = share
	}
	ids = tss.SortParties(ids)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	defer func() {
		for _, session := range sessions {
			session.Destroy()
		}
	}()
	round1 := make([]tss.Envelope, 0, len(signers))
	round2 := make([]tss.Envelope, 0, len(signers))
	for _, id := range ids {
		session, out, err := startFROSTSignWithOptions(shares[id], sessionID, ids, message, opts)
		if err != nil {
			return nil, nil, err
		}
		sessions[id] = session
		for _, env := range out {
			if env.Round == signStartRound {
				round1 = append(round1, env)
			} else {
				round2 = append(round2, env)
			}
		}
	}
	for _, env := range round1 {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				return nil, nil, err
			}
			round2 = append(round2, out...)
		}
	}
	for _, env := range round2 {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			if _, err := sessions[id].Handle(testutil.DeliverEnvelope(env)); err != nil {
				return nil, nil, err
			}
		}
	}
	sig, ok := sessions[ids[0]].Signature()
	if !ok {
		return nil, nil, errors.New("signature not completed")
	}
	return sessions[ids[0]].VerificationKeyBytes(), sig, nil
}
