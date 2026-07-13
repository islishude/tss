package secp256k1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func signCGGMP21Simulation(input []byte, signers []*KeyShare, ctx tss.SigningContext, rawDigest bool, limits Limits) ([]byte, *Signature, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make(tss.PartySet, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.requireMPCMaterial(limits); err != nil {
			return nil, nil, err
		}
		ids[i] = share.state.Party
		shares[share.state.Party] = share
	}
	ids = tss.SortParties(ids)
	presignSessionID, err := tss.NewSessionID(nil)
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
		guard, err := tss.NewEnvelopeGuard(id, shares[id].state.Parties, tss.ProtocolCGGMP21Secp256k1, presignSessionID, simPolicies, tss.NewInMemoryReplayCache())
		if err != nil {
			return nil, nil, err
		}
		plan, err := NewPresignPlan(PresignPlanOption{
			Key:       shares[id],
			SessionID: presignSessionID,
			PresignID: presignSessionID[:],
			Signers:   ids,
			Context:   ctx,
			Limits:    &limits,
		})
		if err != nil {
			return nil, nil, err
		}
		runtime, err := prepareTestPresignRuntime(context.Background(), shares[id], plan, tss.LocalConfig{Self: id, Context: context.Background()}, guard)
		if err != nil {
			return nil, nil, err
		}
		session, out, err := StartPresign(plan, runtime)
		if err != nil {
			return nil, nil, err
		}
		presignSessions[id] = session
		presignQueue = append(presignQueue, out...)
	}
	for len(presignQueue) > 0 {
		env := presignQueue[0]
		presignQueue = presignQueue[1:]
		for _, id := range ids {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			inbound, err := openSimulationInbound(env)
			if err != nil {
				return nil, nil, err
			}
			out, err := presignSessions[id].Handle(inbound)
			if err != nil {
				return nil, nil, err
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
	for _, id := range ids {
		descriptor, ok := presignSessions[id].Presign()
		if !ok {
			return nil, nil, fmt.Errorf("presign not completed for %d", id)
		}
		var session *SignSession
		var out []tss.Envelope
		guard, err := tss.NewEnvelopeGuard(id, shares[id].state.Parties, tss.ProtocolCGGMP21Secp256k1, signID, simPolicies, tss.NewInMemoryReplayCache())
		if err != nil {
			return nil, nil, err
		}
		if rawDigest {
			presign, loadErr := loadPersistedPresignForTest(presignSessions[id])
			if loadErr != nil {
				return nil, nil, loadErr
			}
			session, out, err = StartSignDigestWithStore(shares[id], presign, signID, input, newTestLifecycleStore(), guard)
		} else {
			metadata := descriptor.PublicMetadata()
			plan, planErr := NewSignPlan(SignPlanOption{
				Key:     shares[id],
				Presign: metadata,
				Intent: SignIntent{
					SessionID: signID,
					Context:   ctx,
					Message:   input,
					Signers:   metadata.Signers,
				},
				Limits: &limits,
			})
			if planErr != nil {
				return nil, nil, planErr
			}
			runtime, runtimeErr := prepareTestSignRuntimeFromPersisted(context.Background(), presignSessions[id], descriptor, signID, guard)
			if runtimeErr != nil {
				return nil, nil, runtimeErr
			}
			session, out, err = StartSign(plan, runtime)
		}
		if err != nil {
			return nil, nil, err
		}
		signSessions[id] = session
		signMessages = append(signMessages, out...)
	}
	for _, env := range signMessages {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			inbound, err := openSimulationInbound(env)
			if err != nil {
				return nil, nil, err
			}
			if _, err := signSessions[id].Handle(inbound); err != nil {
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

func openSimulationInbound(env tss.Envelope) (tss.InboundEnvelope, error) {
	return testutil.OpenInboundEnvelope(env, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: tss.ChannelConfidential,
		ChannelID:  "simulation",
		PeerKeyID:  fmt.Sprintf("party-%d", env.From),
		ReceivedAt: time.Now(),
	}, nil)
}

// simulationCGGMP21Policies returns the production CGGMP21 policy set with
// broadcast consistency relaxed to None for all payload types. It is used by
// test-only in-memory simulations that route messages directly without
// broadcast certificate coordination.
func simulationCGGMP21Policies() (tss.PolicySet, error) {
	entries := CGGMP21Policies().Entries()
	relaxed := make([]tss.DeliveryPolicy, len(entries))
	for i, p := range entries {
		relaxed[i] = p
		relaxed[i].BroadcastConsistency = tss.BroadcastConsistencyNone
		relaxed[i].RequireSenderSignature = false
	}
	ps, err := tss.NewPolicySet(relaxed...)
	if err != nil {
		return tss.PolicySet{}, fmt.Errorf("build simulation CGGMP21 policy set: %w", err)
	}
	return ps, nil
}
