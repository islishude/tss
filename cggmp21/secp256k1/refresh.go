package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	refreshCommitmentsHashLabel = "cggmp21-secp256k1-refresh-commitments-v1"
	refreshTranscriptHashLabel  = "cggmp21-secp256k1-refresh-transcript-v1"
)

// refreshPartyData holds all per-party state for a single refresh participant.
// Commitments, share, and auxiliary material are populated during round 1;
// confirmation is set during round 2 after the transcript is finalized.
type refreshPartyData struct {
	commitments  [][]byte
	share        *big.Int
	paillierPub  PaillierPublicShare
	ringPedersen RingPedersenPublicShare
	confirmation *KeygenConfirmation
}

// RefreshSession refreshes CGGMP21 key shares and rotates Paillier keys while
// preserving the group public key and chain code. The participant set and
// threshold are fixed to the original key share. Each existing participant
// generates a polynomial with zero constant term (to refresh the secret share)
// and a new Paillier keypair (to rotate encryption material).
type RefreshSession struct {
	mu sync.Mutex

	oldKey         *KeyShare                         // Caller-owned share being refreshed; not destroyed with the session.
	cfg            tss.ThresholdConfig               // Local threshold runtime view fixed by the refresh plan.
	log            tss.Logger                        // Optional protocol logger.
	limits         Limits                            // Local fail-closed resource policy.
	securityParams SecurityParams                    // Cryptographic profile inherited from oldKey.
	planHash       []byte                            // Digest every refresh payload must echo.
	partyData      map[tss.PartyID]*refreshPartyData // Per-party refresh state keyed by sender.
	completed      bool                              // Terminal success flag after newShare is confirmed.
	aborted        bool                              // Terminal failure/destruction flag.
	guard          *tss.EnvelopeGuard                // Transport replay, identity, and policy guard.
	newShare       *KeyShare                         // Refreshed key share produced on completion.
	ownPoly        []*big.Int                        // Local zero-constant polynomial coefficients; secret-bearing.
	newPaillier    *pai.PrivateKey                   // Fresh local Paillier private key for rotated auxiliary material.
}

// StartRefresh starts CGGMP21 key-share refresh with Paillier key rotation.
// The participant set and threshold are fixed to oldKey.state.parties and
// oldKey.state.threshold. The group public key and chain code are preserved from the
// original key share.
func StartRefresh(oldKey *KeyShare, plan *RefreshPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*RefreshSession, []tss.Envelope, error) {
	if oldKey == nil || oldKey.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil old key share"))
	}
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	if local.Self != oldKey.state.party {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("local self must match the old key's party ID"))
	}
	if plan.state.threshold != oldKey.state.threshold ||
		!bytes.Equal(plan.state.publicKey, oldKey.state.publicKey) ||
		!bytes.Equal(plan.state.chainCode, oldKey.state.chainCode) ||
		!slices.Equal(plan.state.parties, oldKey.state.parties) {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("refresh plan does not match old key share"))
	}
	limits := plan.limits
	if err := config.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, config.SessionID, config.Self); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if err := oldKey.requireMPCMaterial(limits); err != nil {
		return nil, nil, err
	}
	// Generate a new Paillier keypair for key rotation.
	newPaillierKey, err := generatePaillierKey(config.Ctx(), config.Reader(), plan.state.paillierBits)
	if err != nil {
		return nil, nil, err
	}
	newPaillierPubBytes, err := newPaillierKey.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	modProof, err := zkpai.ProveModulus(config.Reader(), refreshPaillierDomain(config, config.Self, newPaillierPubBytes, planHash), newPaillierKey, config.Self)
	if err != nil {
		return nil, nil, err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(config.Reader(), newPaillierKey)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenParamsBytes, err := zkpai.MarshalRingPedersenParams(ringPedersenParams)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(config.Reader(), refreshRingPedersenDomain(config, config.Self, ringPedersenParamsBytes, planHash), newPaillierKey, ringPedersenParams, ringPedersenLambda, config.Self)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenProofBytes, err := zkpai.Marshal(ringPedersenProof)
	if err != nil {
		return nil, nil, err
	}
	poly, err := shamir.RandomPolynomial(config.Reader(), secp.Order(), config.Threshold, big.NewInt(0))
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		if coeff.Sign() == 0 {
			commitments[i] = nil
			continue
		}
		enc, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(coeff)))
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	s := &RefreshSession{
		oldKey:         oldKey,
		cfg:            config,
		log:            config.Logger(),
		limits:         limits,
		securityParams: plan.securityParams,
		planHash:       append([]byte(nil), planHash...),
		partyData: func() map[tss.PartyID]*refreshPartyData {
			pd := make(map[tss.PartyID]*refreshPartyData, len(oldKey.state.parties))
			for _, id := range oldKey.state.parties {
				pd[id] = &refreshPartyData{}
			}
			pd[oldKey.state.party] = &refreshPartyData{
				commitments:  commitments,
				share:        shamir.Eval(poly, oldKey.state.party, secp.Order()),
				paillierPub:  PaillierPublicShare{Party: oldKey.state.party, PublicKey: newPaillierPubBytes, Proof: modProofBytes},
				ringPedersen: RingPedersenPublicShare{Party: oldKey.state.party, Params: ringPedersenParamsBytes, Proof: ringPedersenProofBytes},
			}
			return pd
		}(),
		ownPoly:     poly,
		newPaillier: newPaillierKey,
		guard:       guard,
	}
	commitPayload, err := marshalRefreshCommitmentsPayloadWithLimits(refreshCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  newPaillierPubBytes,
		PaillierProof:      modProofBytes,
		RingPedersenParams: ringPedersenParamsBytes,
		RingPedersenProof:  ringPedersenProofBytes,
		PlanHash:           planHash,
	}, s.limits)
	if err != nil {
		return nil, nil, err
	}
	commitEnv, err := newEnvelope(config, 1, oldKey.state.party, tss.BroadcastPartyId, payloadRefreshCommitments, commitPayload)
	if err != nil {
		return nil, nil, err
	}
	out := []tss.Envelope{commitEnv}
	for _, id := range oldKey.state.parties {
		if id == oldKey.state.party {
			continue
		}
		share := shamir.Eval(poly, id, secp.Order())
		payload, err := marshalRefreshSharePayloadWithLimits(refreshSharePayload{Share: share, PlanHash: planHash}, s.limits)
		if err != nil {
			return nil, nil, err
		}
		shareEnv, err := newEnvelope(config, 1, oldKey.state.party, id, payloadRefreshShare, payload)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, shareEnv)
	}
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, completionOut...)
	return s, out, nil
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *RefreshSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// partyEntry returns the per-party data for id, or an error when id is not in the session.
func (s *RefreshSession) partyEntry(id tss.PartyID) (*refreshPartyData, error) {
	pd, ok := s.partyData[id]
	if !ok {
		return nil, fmt.Errorf("party %d is not a refresh participant", id)
	}
	return pd, nil
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *RefreshSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// HandleRefreshMessage validates and applies one refresh envelope.
func (s *RefreshSession) HandleRefreshMessage(in tss.InboundEnvelope) (out []tss.Envelope, err error) {
	env := in.Envelope()
	if s == nil {
		return nil, errors.New("nil refresh session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	if err := s.validateInbound(in); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	if env.PayloadType == payloadKeygenConfirmation {
		return s.handleRefreshConfirmation(env)
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadRefreshCommitments:
		pd, err := s.partyEntry(env.From)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if pd.commitments != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh commitments"))
		}
		p, err := unmarshalRefreshCommitmentsPayloadWithLimits(env.Payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := requirePlanHash("refresh", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		if err := validateRefreshCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		pk, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PaillierPublicKey, s.limits.Paillier.MaxModulusBits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		proof, err := zkpai.UnmarshalModulusProof(p.PaillierProof)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"refresh Paillier modulus does not meet security requirements",
				tss.NewPartySet(env.From),
				err,
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if !zkpai.VerifyModulus(refreshPaillierDomain(s.cfg, env.From, p.PaillierPublicKey, s.planHash), pk, env.From, proof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid refresh Paillier modulus proof",
				tss.NewPartySet(env.From),
				errors.New("invalid refresh Paillier modulus proof"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		ringParams, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(p.RingPedersenParams, s.limits.Paillier.MaxModulusBits)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed refresh Ring-Pedersen parameters",
				tss.NewPartySet(env.From),
				err,
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if ringParams.N.Cmp(pk.N) != 0 {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"refresh Ring-Pedersen modulus mismatch",
				tss.NewPartySet(env.From),
				errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		ringProof, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed refresh Ring-Pedersen proof",
				tss.NewPartySet(env.From),
				err,
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if !zkpai.VerifyRingPedersen(refreshRingPedersenDomain(s.cfg, env.From, p.RingPedersenParams, s.planHash), ringParams, env.From, ringProof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid refresh Ring-Pedersen proof",
				tss.NewPartySet(env.From),
				errors.New("invalid refresh Ring-Pedersen proof"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		pd.commitments = p.Commitments
		pd.paillierPub = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
		pd.ringPedersen = RingPedersenPublicShare{Party: env.From, Params: p.RingPedersenParams, Proof: p.RingPedersenProof}
	case payloadRefreshShare:
		pd, err := s.partyEntry(env.From)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if pd.share != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh share"))
		}
		p, err := unmarshalRefreshSharePayloadWithLimits(env.Payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := requirePlanHash("refresh", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		share := secp.ScalarFromBigInt(p.Share)
		pd.share = share.BigInt()
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return s.tryComplete()
}

// KeyShare returns the refreshed key share when refresh completes.
func (s *RefreshSession) KeyShare() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed || s.aborted || s.newShare == nil {
		return nil, false
	}
	return cloneKeyShareValue(s.newShare), true
}

// Destroy clears sensitive session state. Use only on material that will
// never be needed for processing further messages.
func (s *RefreshSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abort()
}

// abort marks the session aborted and clears secret-bearing accumulated
// state: received polynomial shares, own polynomial coefficients, generated
// Paillier material, and any pending or completed new share.
func (s *RefreshSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	for _, pd := range s.partyData {
		if pd.share != nil {
			secret.ClearBigInt(pd.share)
		}
	}
	for _, coeff := range s.ownPoly {
		secret.ClearBigInt(coeff)
	}
	s.ownPoly = nil
	if s.newPaillier != nil {
		s.newPaillier.Destroy()
		s.newPaillier = nil
	}
	if s.newShare != nil {
		s.newShare.Destroy()
		s.newShare = nil
	}
	s.completed = false
}

// allRefreshRound1Complete returns true when every party has submitted round 1 data.
func (s *RefreshSession) allRefreshRound1Complete() bool {
	for _, id := range s.oldKey.state.parties {
		pd := s.partyData[id]
		if pd == nil || pd.commitments == nil || pd.share == nil ||
			len(pd.paillierPub.PublicKey) == 0 || len(pd.ringPedersen.Params) == 0 {
			return false
		}
	}
	return true
}

// allRefreshConfirmationsReceived returns true when every party has submitted a confirmation.
func (s *RefreshSession) allRefreshConfirmationsReceived() bool {
	for _, id := range s.oldKey.state.parties {
		pd := s.partyData[id]
		if pd == nil || pd.confirmation == nil {
			return false
		}
	}
	return true
}
