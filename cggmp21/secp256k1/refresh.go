package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	shamirsecp "github.com/islishude/tss/internal/shamir/secp256k1"
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
	share        *secret.Scalar
	paillierPub  paillierPublicMaterial
	ringPedersen ringPedersenPublicMaterial
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
	newPaillier    *pai.PrivateKey                   // Fresh local Paillier private key for rotated auxiliary material.
}

// StartRefresh starts CGGMP21 key-share refresh with Paillier key rotation.
// The participant set and threshold are fixed to oldKey.state.parties and
// oldKey.state.threshold. The group public key and chain code are preserved from the
// original key share.
//
// In production, StartRefresh starts this party's local proactive refresh state
// machine from shared refresh-run metadata. The refreshed KeyShare returned at
// completion is staged output; applications should install it with
// compare-and-swap against the expected current key generation.
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
	modDomain, err := refreshPaillierDomain(config, config.Self, &newPaillierKey.PublicKey, planHash, limits)
	if err != nil {
		return nil, nil, err
	}
	modProof, err := zkpai.ProveModulus(config.Reader(), modDomain, newPaillierKey, config.Self)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(config.Reader(), newPaillierKey)
	if err != nil {
		return nil, nil, err
	}
	defer ringPedersenLambda.Destroy()
	ringDomain, err := refreshRingPedersenDomain(config, config.Self, ringPedersenParams, planHash, limits)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(config.Reader(), ringDomain, newPaillierKey, ringPedersenParams, ringPedersenLambda, config.Self)
	if err != nil {
		return nil, nil, err
	}
	zero := secp.ScalarZero()
	poly, err := shamirsecp.RandomPolynomial(config.Reader(), config.Threshold, &zero)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		if coeff.IsZero() {
			commitments[i] = nil
			continue
		}
		enc, err := secp.PointBytes(secp.ScalarBaseMult(coeff))
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	localShare, err := secpSecretScalarFromScalarAllowZero(shamirsecp.Eval(poly, oldKey.state.party))
	if err != nil {
		return nil, nil, err
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
				commitments: commitments,
				share:       localShare,
				paillierPub: paillierPublicMaterial{
					Party:     oldKey.state.party,
					PublicKey: newPaillierKey.PublicKey.Clone(),
					Proof:     modProof.Clone(),
				},
				ringPedersen: ringPedersenPublicMaterial{
					Party:  oldKey.state.party,
					Params: ringPedersenParams.Clone(),
					Proof:  ringPedersenProof.Clone(),
				},
			}
			return pd
		}(),
		newPaillier: newPaillierKey,
		guard:       guard,
	}
	commitPayload, err := (refreshCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  newPaillierKey.PublicKey,
		PaillierProof:      *modProof,
		RingPedersenParams: *ringPedersenParams,
		RingPedersenProof:  *ringPedersenProof,
		PlanHash:           planHash,
	}).MarshalBinaryWithLimits(s.limits)
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
		share, err := secpSecretScalarFromScalarAllowZero(shamirsecp.Eval(poly, id))
		if err != nil {
			return nil, nil, err
		}
		payload, err := (refreshSharePayload{Share: share, PlanHash: planHash}).MarshalBinaryWithLimits(s.limits)
		share.Destroy()
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
		p, err := tss.DecodeBinaryValueWithLimits[refreshCommitmentsPayload](env.Payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := requirePlanHash("refresh", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		if err := validateRefreshCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		observedPaillierKeyHash, err := hashWireEvidenceField(evidenceFieldObservedPaillierKeyHash, &p.PaillierPublicKey, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		pk := &p.PaillierPublicKey
		proof := &p.PaillierProof
		if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"refresh Paillier modulus does not meet security requirements",
				tss.NewPartySet(env.From),
				err,
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				observedPaillierKeyHash,
			)
		}
		modDomain, err := refreshPaillierDomain(s.cfg, env.From, pk, s.planHash, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		if !zkpai.VerifyModulus(modDomain, pk, env.From, proof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid refresh Paillier modulus proof",
				tss.NewPartySet(env.From),
				errors.New("invalid refresh Paillier modulus proof"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				observedPaillierKeyHash,
			)
		}
		ringParams := &p.RingPedersenParams
		if ringParams.N.Cmp(pk.N) != 0 {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"refresh Ring-Pedersen modulus mismatch",
				tss.NewPartySet(env.From),
				errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				observedPaillierKeyHash,
			)
		}
		ringProof := &p.RingPedersenProof
		ringDomain, err := refreshRingPedersenDomain(s.cfg, env.From, ringParams, s.planHash, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		if !zkpai.VerifyRingPedersen(s.securityParams, ringDomain, ringParams, env.From, ringProof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid refresh Ring-Pedersen proof",
				tss.NewPartySet(env.From),
				errors.New("invalid refresh Ring-Pedersen proof"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
				observedPaillierKeyHash,
			)
		}
		pd.commitments = p.Commitments
		pd.paillierPub = paillierPublicMaterial{
			Party:     env.From,
			PublicKey: p.PaillierPublicKey.Clone(),
			Proof:     p.PaillierProof.Clone(),
		}
		pd.ringPedersen = ringPedersenPublicMaterial{
			Party:  env.From,
			Params: p.RingPedersenParams.Clone(),
			Proof:  p.RingPedersenProof.Clone(),
		}
	case payloadRefreshShare:
		pd, err := s.partyEntry(env.From)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if pd.share != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh share"))
		}
		p, err := tss.DecodeBinaryValueWithLimits[refreshSharePayload](env.Payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := requirePlanHash("refresh", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		pd.share = p.Share.Clone()
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
			pd.share.Destroy()
			pd.share = nil
		}
	}
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
			pd.paillierPub.PublicKey == nil || pd.paillierPub.Proof == nil ||
			pd.ringPedersen.Params == nil || pd.ringPedersen.Proof == nil {
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
