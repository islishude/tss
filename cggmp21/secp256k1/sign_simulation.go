package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/islishude/tss"
)

// Sign runs an in-memory presign and signing exchange for a context-bound message.
func Sign(message []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	return signWithDigest(message, signers, ctx, false, DefaultLimits())
}

// SignDigestInteractive runs a full interactive signing exchange for a raw
// digest after binding ctx before nonce generation. It does not return or
// persist a reusable Presign.
func SignDigestInteractive(digest32 []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	if len(digest32) != sha256.Size {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	return signWithDigest(digest32, signers, ctx, true, DefaultLimits())
}

func signWithDigest(input []byte, signers []*KeyShare, ctx PresignContext, rawDigest bool, limits Limits) ([]byte, *Signature, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make(tss.PartySet, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.requireMPCMaterial(limits); err != nil {
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
		guard, err := tss.NewEnvelopeGuard(id, shares[id].state.parties, protocol, presignID, simPolicies, tss.NewInMemoryReplayCache())
		if err != nil {
			return nil, nil, err
		}
		plan, err := NewPresignPlan(PresignPlanOption{
			Key:       shares[id],
			SessionID: presignID,
			Signers:   ids,
			Context:   ctx,
			Limits:    &limits,
		})
		if err != nil {
			return nil, nil, err
		}
		session, out, err := StartPresign(shares[id], plan, tss.LocalConfig{Self: id, Context: context.Background()}, guard)
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
			out, err := presignSessions[id].HandlePresignMessage(inbound)
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
	attemptStore := newSimulationSignAttemptStore()
	for _, id := range ids {
		presign, ok := presignSessions[id].Presign()
		if !ok {
			return nil, nil, fmt.Errorf("presign not completed for %d", id)
		}
		var session *SignSession
		var out []tss.Envelope
		guard, err := tss.NewEnvelopeGuard(id, shares[id].state.parties, protocol, signID, simPolicies, tss.NewInMemoryReplayCache())
		if err != nil {
			return nil, nil, err
		}
		if rawDigest {
			session, out, err = startSignDigestBound(context.Background(), shares[id], presign, signID, input, presign.state.contextHash, true, attemptStore, guard, limits)
		} else {
			request := SignRequest{
				Context:      ctx,
				Message:      input,
				LowS:         true,
				AttemptStore: attemptStore,
			}
			plan, planErr := NewSignPlan(SignPlanOption{
				Key:       shares[id],
				Presign:   presign,
				SessionID: signID,
				Request:   request,
				Limits:    &limits,
			})
			if planErr != nil {
				return nil, nil, planErr
			}
			session, out, err = StartSign(shares[id], presign, plan, tss.LocalConfig{Self: id, Context: context.Background()}, guard)
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
			if _, err := signSessions[id].HandleSignMessage(inbound); err != nil {
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
	raw, err := env.MarshalBinary()
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	return tss.OpenEnvelope(raw, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: tss.ChannelConfidential,
		ChannelID:  "simulation",
		PeerKeyID:  fmt.Sprintf("party-%d", env.From),
		ReceivedAt: time.Now(),
	})
}

type simulationSignAttemptStore struct {
	mu       sync.Mutex
	attempts map[string]SignAttemptRecord
	burns    map[string]struct{}
}

func newSimulationSignAttemptStore() *simulationSignAttemptStore {
	return &simulationSignAttemptStore{
		attempts: make(map[string]SignAttemptRecord),
		burns:    make(map[string]struct{}),
	}
}

// LoadSignAttempt loads an in-memory simulation attempt.
func (s *simulationSignAttemptStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	if s == nil {
		return SignAttemptRecord{}, errors.New("nil simulation sign attempt store")
	}
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[string(presignID)]; ok {
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	record, ok := s.attempts[string(presignID)]
	if !ok {
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	return record.Clone(), nil
}

// CommitSignAttempt commits an in-memory simulation attempt.
func (s *simulationSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	if ctx == nil {
		return SignAttemptCommit{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptCommit{}, err
	}
	if err := validateSignAttemptCandidate(candidate); err != nil {
		return SignAttemptCommit{}, err
	}
	key := string(candidate.PresignID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[key]; ok {
		return SignAttemptCommit{}, ErrSignAttemptBurned
	}
	if existing, ok := s.attempts[key]; ok {
		if candidate.SameBaseAttempt(existing) {
			return SignAttemptCommit{Status: SignAttemptExistingSame, Record: existing.Clone()}, nil
		}
		if bytes.Equal(existing.IntentHash, candidate.IntentHash) {
			return SignAttemptCommit{}, ErrSignAttemptNonDeterminism
		}
		return SignAttemptCommit{}, ErrSignAttemptConflict
	}
	s.attempts[key] = candidate.Clone()
	return SignAttemptCommit{Status: SignAttemptCreated, Record: candidate.Clone()}, nil
}

// UpdateSignAttemptDelivery records in-memory delivery progress.
func (s *simulationSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	key := string(update.PresignID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[key]; ok {
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	record, ok := s.attempts[key]
	if !ok {
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	updated, err := applySignAttemptDeliveryUpdate(record, update)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	s.attempts[key] = updated.Clone()
	return updated.Clone(), nil
}

// CompleteSignAttempt completes an in-memory simulation attempt.
func (s *simulationSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	key := string(result.PresignID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[key]; ok {
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	record, ok := s.attempts[key]
	if !ok {
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	if !bytes.Equal(record.AttemptHash, result.AttemptHash) {
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	if record.Completed {
		if bytes.Equal(record.SignatureR, result.Signature.R) && bytes.Equal(record.SignatureS, result.Signature.S) && record.SignatureRecoveryID == result.Signature.RecoveryID {
			return record.Clone(), nil
		}
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	record.Completed = true
	record.SignatureR = append([]byte(nil), result.Signature.R...)
	record.SignatureS = append([]byte(nil), result.Signature.S...)
	record.SignatureRecoveryID = result.Signature.RecoveryID
	s.attempts[key] = record
	return record.Clone(), nil
}

// BurnPresign burns an in-memory simulation presign.
func (s *simulationSignAttemptStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	if s == nil {
		return errors.New("nil simulation sign attempt store")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := string(burn.PresignID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.attempts[key]; ok {
		return ErrSignAttemptConflict
	}
	if s.burns == nil {
		s.burns = make(map[string]struct{})
	}
	s.burns[key] = struct{}{}
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
