package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/islishude/tss"
)

// Sign runs an in-memory presign and signing exchange for a context-bound message.
func Sign(message []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	return signWithDigest(message, signers, ctx, false)
}

// SignDigestInteractive runs a full interactive signing exchange for a raw
// digest after binding ctx before nonce generation. It does not return or
// persist a reusable Presign.
func SignDigestInteractive(digest32 []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	if len(digest32) != sha256.Size {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	return signWithDigest(digest32, signers, ctx, true)
}

func signWithDigest(input []byte, signers []*KeyShare, ctx PresignContext, rawDigest bool) ([]byte, *Signature, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make([]tss.PartyID, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.requireMPCMaterial(); err != nil {
			return nil, nil, err
		}
		ids[i] = share.state.party
		shares[share.state.party] = share
	}
	ids = tss.SortParties(ids)
	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	presignSessions := make(map[tss.PartyID]*PresignSession, len(ids))
	presignQueue := make([]tss.Envelope, 0)
	simPolicies, err := simulationCGGMP21Policies()
	if err != nil {
		return nil, nil, err
	}
	for _, id := range ids {
		guard, err := tss.NewEnvelopeGuard(id, tss.PartySet(shares[id].state.parties), protocol, presignID, simPolicies, tss.NewInMemoryReplayCache())
		if err != nil {
			return nil, nil, err
		}
		session, out, err := StartPresignWithContext(shares[id], presignID, ids, ctx, guard)
		if err != nil {
			return nil, nil, err
		}
		presignSessions[id] = session
		for i := range out {
			out[i].Security.Authenticated = true
			out[i].Security.AuthenticatedParty = out[i].From
		}
		presignQueue = append(presignQueue, out...)
	}
	for len(presignQueue) > 0 {
		env := presignQueue[0]
		presignQueue = presignQueue[1:]
		for _, id := range ids {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := presignSessions[id].HandlePresignMessage(env)
			if err != nil {
				return nil, nil, err
			}
			for i := range out {
				out[i].Security.Authenticated = true
				out[i].Security.AuthenticatedParty = out[i].From
			}
			presignQueue = append(presignQueue, out...)
		}
	}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	signSessions := make(map[tss.PartyID]*SignSession, len(ids))
	signMessages := make([]tss.Envelope, 0, len(ids))
	presignStore := newSimulationPresignStore()
	for _, id := range ids {
		presign, ok := presignSessions[id].Presign()
		if !ok {
			return nil, nil, fmt.Errorf("presign not completed for %d", id)
		}
		var session *SignSession
		var out []tss.Envelope
		guard, err := tss.NewEnvelopeGuard(id, tss.PartySet(shares[id].state.parties), protocol, signID, simPolicies, tss.NewInMemoryReplayCache())
		if err != nil {
			return nil, nil, err
		}
		if rawDigest {
			session, out, err = startSignDigestBound(shares[id], presign, signID, input, presign.state.contextHash, true, presignStore, guard)
		} else {
			session, out, err = StartSign(shares[id], presign, signID, SignRequest{
				Context:      ctx,
				Message:      input,
				LowS:         true,
				PresignStore: presignStore,
			}, guard)
		}
		if err != nil {
			return nil, nil, err
		}
		signSessions[id] = session
		for i := range out {
			out[i].Security.Authenticated = true
			out[i].Security.AuthenticatedParty = out[i].From
		}
		signMessages = append(signMessages, out...)
	}
	for _, env := range signMessages {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			if _, err := signSessions[id].HandleSignMessage(env); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, id := range ids {
		if sig, ok := signSessions[id].Signature(); ok {
			return append([]byte(nil), signSessions[id].publicKey...), sig, nil
		}
	}
	return nil, nil, errors.New("signature not completed")
}

type simulationPresignStore struct {
	mu      sync.Mutex
	claimed map[string]struct{}
}

func newSimulationPresignStore() *simulationPresignStore {
	return &simulationPresignStore{claimed: make(map[string]struct{})}
}

// ClaimPresign atomically claims a presign ID for the current in-memory
// simulation. It is not durable and must not be used as a production store.
func (s *simulationPresignStore) ClaimPresign(presignID []byte) error {
	if s == nil {
		return errors.New("nil simulation presign store")
	}
	key := string(presignID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.claimed[key]; ok {
		return ErrPresignAlreadyConsumed
	}
	s.claimed[key] = struct{}{}
	return nil
}

// simulationCGGMP21Policies returns the production CGGMP21 policy set with
// broadcast consistency relaxed to None for all payload types. It is used by
// in-memory simulation helpers ([Sign], [SignDigestInteractive]) that route
// messages directly without broadcast certificate coordination.
func simulationCGGMP21Policies() (tss.PolicySet, error) {
	entries := CGGMP21Policies().Entries()
	relaxed := make([]tss.DeliveryPolicy, len(entries))
	for i, p := range entries {
		relaxed[i] = p
		relaxed[i].BroadcastConsistency = tss.BroadcastConsistencyNone
	}
	ps, err := tss.NewPolicySet(relaxed...)
	if err != nil {
		return tss.PolicySet{}, fmt.Errorf("build simulation CGGMP21 policy set: %w", err)
	}
	return ps, nil
}
