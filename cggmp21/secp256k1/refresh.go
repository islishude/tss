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
	"github.com/islishude/tss/internal/transcript"
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
	factorProof  *zkpai.FactorProof
	confirmation *KeygenConfirmation
}

// RefreshSession refreshes CGGMP21 key shares and rotates Paillier keys while
// preserving the group public key and chain code. The participant set and
// threshold are fixed to the original key share. Each existing participant
// generates a polynomial with zero constant term (to refresh the secret share)
// and a new Paillier keypair (to rotate encryption material).
type RefreshSession struct {
	mu sync.Mutex

	oldKey          *KeyShare                         // Caller-owned share being refreshed; not destroyed with the session.
	cfg             tss.ThresholdConfig               // Local threshold runtime view fixed by the refresh plan.
	log             tss.Logger                        // Optional protocol logger.
	limits          Limits                            // Local fail-closed resource policy.
	securityParams  SecurityParams                    // Cryptographic profile inherited from oldKey.
	planHash        []byte                            // Digest every refresh payload must echo.
	partyData       map[tss.PartyID]*refreshPartyData // Per-party refresh state keyed by sender.
	completed       bool                              // Terminal success flag after newShare is confirmed.
	aborted         bool                              // Terminal failure/destruction flag.
	guard           *tss.EnvelopeGuard                // Transport replay, identity, and policy guard.
	newShare        *KeyShare                         // Refreshed key share produced on completion.
	newPaillier     *pai.PrivateKey                   // Fresh local Paillier private key for rotated auxiliary material.
	localPolynomial shamir.Polynomial                 // Zero-constant polynomial retained until encrypted shares are emitted.
	sharesSent      bool                              // Round-2 encrypted shares have been emitted.
}

// StartRefresh starts CGGMP21 key-share refresh with Paillier key rotation.
// The participant set and threshold are fixed to oldKey.state.Parties and
// oldKey.state.Threshold. The group public key and chain code are preserved from the
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
	if local.Self != oldKey.state.Party {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("local self must match the old key's party ID"))
	}
	oldCommitmentsHash, err := keygenCommitmentsHash(oldKey.state.GroupCommitments)
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, fmt.Errorf("hash old group commitments: %w", err))
	}
	if plan.state.threshold != oldKey.state.Threshold ||
		!bytes.Equal(plan.state.publicKey, oldKey.state.PublicKey) ||
		!bytes.Equal(plan.state.chainCode, oldKey.state.ChainCode) ||
		!slices.Equal(plan.state.parties, oldKey.state.Parties) ||
		plan.state.oldPaillierProofSession != oldKey.state.PaillierProofSessionID ||
		!bytes.Equal(plan.state.oldKeygenTranscriptHash, oldKey.state.KeygenTranscriptHash) ||
		!bytes.Equal(plan.state.oldPlanHash, oldKey.state.PlanHash) ||
		!bytes.Equal(plan.state.oldCommitmentsHash, oldCommitmentsHash) {
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
	if err := requireLocalEnvelopeSigner(guard, local.EnvelopeSigner); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	if err := oldKey.requireMPCMaterial(limits); err != nil {
		return nil, nil, err
	}
	// Generate a new Paillier keypair for key rotation.
	newPaillierKey, err := generatePaillierKey(config.Ctx(), config.Reader(), plan.state.paillierBits)
	if err != nil {
		return nil, nil, err
	}
	paillierOwned := true
	defer func() {
		if paillierOwned {
			newPaillierKey.Destroy()
		}
	}()
	modDomain, err := refreshPaillierDomain(config, config.Self, newPaillierKey.PublicKey, planHash, limits)
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
	poly, err := shamir.RandomPolynomial(config.Reader(), config.Threshold, &zero)
	if err != nil {
		return nil, nil, err
	}
	polynomialOwned := true
	defer func() {
		if polynomialOwned {
			clearSecpPolynomial(poly)
		}
	}()
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
	localShare, err := secpSecretScalarFromScalarAllowZero(shamir.Eval(poly, oldKey.state.Party))
	if err != nil {
		return nil, nil, err
	}
	localShareOwned := true
	defer func() {
		if localShareOwned {
			localShare.Destroy()
		}
	}()
	s := &RefreshSession{
		oldKey:         oldKey,
		cfg:            config,
		log:            config.Logger(),
		limits:         limits,
		securityParams: plan.securityParams,
		planHash:       append([]byte(nil), planHash...),
		partyData: func() map[tss.PartyID]*refreshPartyData {
			pd := make(map[tss.PartyID]*refreshPartyData, len(oldKey.state.Parties))
			for _, id := range oldKey.state.Parties {
				pd[id] = &refreshPartyData{}
			}
			pd[oldKey.state.Party] = &refreshPartyData{
				commitments: commitments,
				share:       localShare,
				paillierPub: paillierPublicMaterial{
					Party:     oldKey.state.Party,
					PublicKey: newPaillierKey.PublicKey.Clone(),
					Proof:     modProof.Clone(),
				},
				ringPedersen: ringPedersenPublicMaterial{
					Party:  oldKey.state.Party,
					Params: ringPedersenParams.Clone(),
					Proof:  ringPedersenProof.Clone(),
				},
			}
			return pd
		}(),
		newPaillier:     newPaillierKey,
		localPolynomial: poly,
		guard:           guard,
	}
	commitPayload, err := (refreshCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  newPaillierKey.PublicKey,
		PaillierProof:      modProof,
		RingPedersenParams: ringPedersenParams,
		RingPedersenProof:  ringPedersenProof,
		PlanHash:           planHash,
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, nil, err
	}
	commitEnv, err := newEnvelope(config, refreshStartRound, oldKey.state.Party, tss.BroadcastPartyId, payloadRefreshCommitments, commitPayload)
	if err != nil {
		return nil, nil, err
	}
	out := []tss.Envelope{commitEnv}
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, completionOut...)
	paillierOwned = false
	localShareOwned = false
	polynomialOwned = false
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

// Handle validates and applies one refresh envelope.
func (s *RefreshSession) Handle(in tss.InboundEnvelope) (out []tss.Envelope, err error) {
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
		err = bindInboundAuthenticationEvidence(err, in)
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	if err := tss.ValidateInboundWithoutReplay(s.guard, in, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self); err != nil {
		return nil, err
	}
	if env.PayloadType == payloadRefreshShare && env.Round == refreshShareRound {
		pd, pdErr := s.partyEntry(env.From)
		if pdErr == nil && pd.commitments == nil {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh share arrived before commitments"))
		}
	}
	if s.hasAcceptedInbound(env) {
		if err := s.validateInbound(in); err != nil {
			if errors.Is(err, tss.ErrDuplicateMessage) {
				return nil, tss.ErrDuplicateMessage
			}
			return nil, err
		}
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("refresh message slot is already accepted"))
	}
	staged := s.cloneForInboundTransition()
	liveConfigLog := staged.cfg.Log
	liveLog := staged.log
	stagedLog := new(stagedLifecycleLogger)
	staged.cfg.Log = stagedLog
	staged.log = stagedLog
	defer stagedLog.discard()
	stagedOwned := true
	defer func() {
		if stagedOwned {
			staged.abort()
		}
	}()
	out, err = staged.applyValidatedInbound(env)
	if err != nil {
		return nil, err
	}
	if err := s.validateInbound(in); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	staged.cfg.Log = liveConfigLog
	staged.log = liveLog
	s.commitInboundTransition(staged)
	stagedOwned = false
	stagedLog.flush(s.log)
	return out, nil
}

func (s *RefreshSession) hasAcceptedInbound(env tss.Envelope) bool {
	if s == nil {
		return false
	}
	pd, err := s.partyEntry(env.From)
	if err != nil || pd == nil {
		return false
	}
	switch env.PayloadType {
	case payloadRefreshCommitments:
		return pd.commitments != nil
	case payloadRefreshShare:
		return pd.share != nil
	case payloadKeygenConfirmation:
		return pd.confirmation != nil
	default:
		return false
	}
}

// applyValidatedInbound performs protocol verification, transition staging,
// and outbound construction on an independently owned session copy. The live
// handler commits replay and swaps this state only after this method succeeds.
func (s *RefreshSession) applyValidatedInbound(env tss.Envelope) ([]tss.Envelope, error) {
	if env.PayloadType == payloadKeygenConfirmation {
		return s.handleRefreshConfirmation(env)
	}
	switch env.PayloadType {
	case payloadRefreshCommitments:
		if env.Round != refreshStartRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh commitments in wrong round"))
		}
		pd, err := s.partyEntry(env.From)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if pd.commitments != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh commitments"))
		}
		p, err := tss.DecodeBinaryWithLimits[refreshCommitmentsPayload](env.Payload, s.limits)
		if err != nil {
			fields := append(keyContextEvidenceFields(s.oldKey), hashEvidenceField("refresh_commitment_payload_hash", env.Payload))
			return nil, protocolErrorWithEvidence(tss.ErrCodeInvalidMessage, env, tss.EvidenceKindRefreshCommitment,
				"malformed refresh commitments", tss.NewPartySet(env.From), err, fields...)
		}
		if err := requirePlanHash("refresh", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		if err := validateRefreshCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			fields := append(keyContextEvidenceFields(s.oldKey),
				rawEvidenceField(evidenceFieldCommitmentsHash, transcript.ByteSlicesHash(refreshCommitmentsHashLabel, p.Commitments)))
			return nil, verificationErrorWithEvidence(env, tss.EvidenceKindRefreshCommitment,
				"invalid refresh commitments", tss.NewPartySet(env.From), err, fields...)
		}
		observedPaillierKeyHash, err := hashObservedPaillierKeyEvidenceField(p.PaillierPublicKey, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		pk := p.PaillierPublicKey
		proof := p.PaillierProof
		if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPaillierAux,
				"refresh Paillier modulus does not meet security requirements",
				tss.NewPartySet(env.From),
				err,
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)),
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
				tss.EvidenceKindPaillierAux,
				"invalid refresh Paillier modulus proof",
				tss.NewPartySet(env.From),
				errors.New("invalid refresh Paillier modulus proof"),
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)),
				observedPaillierKeyHash,
			)
		}
		ringParams := p.RingPedersenParams
		if ringParams.N.Cmp(pk.N) != 0 {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPaillierAux,
				"refresh Ring-Pedersen modulus mismatch",
				tss.NewPartySet(env.From),
				errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)),
				observedPaillierKeyHash,
			)
		}
		ringProof := p.RingPedersenProof
		ringDomain, err := refreshRingPedersenDomain(s.cfg, env.From, ringParams, s.planHash, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		if !zkpai.VerifyRingPedersen(s.securityParams, ringDomain, ringParams, env.From, ringProof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPaillierAux,
				"invalid refresh Ring-Pedersen proof",
				tss.NewPartySet(env.From),
				errors.New("invalid refresh Ring-Pedersen proof"),
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)),
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
		if env.Round != refreshShareRound {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh encrypted share in wrong round"))
		}
		pd, err := s.partyEntry(env.From)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if pd.share != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh share"))
		}
		p, err := tss.DecodeBinaryValueWithLimits[refreshSharePayload](env.Payload, s.limits)
		if err != nil {
			return nil, protocolErrorWithEvidence(tss.ErrCodeInvalidMessage, env, tss.EvidenceKindPaillierAux,
				"malformed refresh share or Paillier factor proof", tss.NewPartySet(env.From), err,
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)))
		}
		if err := requirePlanHash("refresh", p.PlanHash, s.planHash); err != nil {
			return nil, protocolErrorWithEvidence(tss.ErrCodeVerification, env, tss.EvidenceKindPaillierAux,
				"refresh share factor proof plan mismatch", tss.NewPartySet(env.From), err,
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)))
		}
		if pd.commitments == nil {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh share arrived before commitments"))
		}
		selfPD := s.partyData[s.cfg.Self]
		factorDomain, err := refreshFactorProofDomain(s.cfg, env.From, s.cfg.Self, pd.paillierPub.PublicKey, selfPD.ringPedersen.Params, s.planHash, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		if err := zkpai.VerifyFactor(s.securityParams, factorDomain, zkpai.FactorStatement{ProverPaillierN: pd.paillierPub.PublicKey, VerifierAux: selfPD.ringPedersen.Params}, &p.FactorProof); err != nil {
			return nil, verificationErrorWithEvidence(env, tss.EvidenceKindPaillierAux, "invalid refresh Paillier factor proof", tss.NewPartySet(env.From), err,
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)))
		}
		evaluation, err := secp.EvalCommitments(pd.commitments, s.cfg.Self)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		domain, err := refreshEncryptedShareDomain(s.cfg, env.From, s.cfg.Self, selfPD.paillierPub.PublicKey, s.planHash, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
		}
		ciphertext := new(big.Int).SetBytes(p.Ciphertext)
		if err := zkpai.VerifyLogStar(s.securityParams, domain, zkpai.LogStarStatement{PaillierN: selfPD.paillierPub.PublicKey, C: ciphertext, X: evaluation, B: secp.ScalarBaseMult(secp.ScalarOne()), VerifierAux: selfPD.ringPedersen.Params}, &p.Proof); err != nil {
			p.Proof.Destroy()
			return nil, verificationErrorWithEvidence(env, tss.EvidenceKindRefreshShare, "invalid encrypted refresh share proof", tss.NewPartySet(env.From), err,
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)),
				hashEvidenceField("encrypted_share_ciphertext_hash", p.Ciphertext))
		}
		p.Proof.Destroy()
		plaintext, err := s.newPaillier.Decrypt(ciphertext)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, 0, fmt.Errorf("verified refresh share decryption failed: %w", err))
		}
		defer secret.ClearBigInt(plaintext)
		if plaintext.Sign() < 0 || plaintext.Cmp(secp.Order()) >= 0 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, 0, errors.New("verified refresh share plaintext is out of range"))
		}
		encoded := plaintext.FillBytes(make([]byte, secp.ScalarSize))
		share, err := newSecpSecretScalarAllowZero(encoded)
		clear(encoded)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, 0, err)
		}
		pd.share = share
		pd.factorProof = p.FactorProof.Clone()
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
	clearSecpPolynomial(s.localPolynomial)
	s.localPolynomial = nil
	if s.newShare != nil {
		s.newShare.Destroy()
		s.newShare = nil
	}
	s.completed = false
}

// allRefreshRound1Complete returns true when every party has submitted round 1 data.
func (s *RefreshSession) allRefreshRound1Complete() bool {
	for _, id := range s.oldKey.state.Parties {
		pd := s.partyData[id]
		if pd == nil || pd.commitments == nil || pd.share == nil ||
			pd.paillierPub.PublicKey == nil || pd.paillierPub.Proof == nil ||
			pd.ringPedersen.Params == nil || pd.ringPedersen.Proof == nil ||
			(id != s.cfg.Self && pd.factorProof == nil) {
			return false
		}
	}
	return true
}

func (s *RefreshSession) allRefreshCommitmentsComplete() bool {
	for _, id := range s.oldKey.state.Parties {
		pd := s.partyData[id]
		if pd == nil || pd.commitments == nil || pd.paillierPub.PublicKey == nil || pd.ringPedersen.Params == nil {
			return false
		}
	}
	return true
}

func (s *RefreshSession) emitEncryptedRefreshShares() ([]tss.Envelope, error) {
	if s.sharesSent || len(s.localPolynomial) == 0 || !s.allRefreshCommitmentsComplete() {
		return nil, nil
	}
	out := make([]tss.Envelope, 0, len(s.oldKey.state.Parties)-1)
	for _, receiver := range s.oldKey.state.Parties {
		if receiver == s.cfg.Self {
			continue
		}
		receiverData := s.partyData[receiver]
		share, err := secpSecretScalarFromScalarAllowZero(shamir.Eval(s.localPolynomial, receiver))
		if err != nil {
			return nil, err
		}
		ciphertext, randomness, err := receiverData.paillierPub.PublicKey.EncryptSecret(s.cfg.Reader(), share)
		if err != nil {
			share.Destroy()
			return nil, err
		}
		evaluation, err := secp.EvalCommitments(s.partyData[s.cfg.Self].commitments, receiver)
		if err != nil {
			share.Destroy()
			randomness.Destroy()
			return nil, err
		}
		domain, err := refreshEncryptedShareDomain(s.cfg, s.cfg.Self, receiver, receiverData.paillierPub.PublicKey, s.planHash, s.limits)
		if err != nil {
			share.Destroy()
			randomness.Destroy()
			return nil, err
		}
		proof, err := zkpai.ProveLogStar(s.securityParams, domain, zkpai.LogStarStatement{PaillierN: receiverData.paillierPub.PublicKey, C: ciphertext, X: evaluation, B: secp.ScalarBaseMult(secp.ScalarOne()), VerifierAux: receiverData.ringPedersen.Params}, zkpai.LogStarWitness{X: share, Rho: randomness}, s.cfg.Reader())
		share.Destroy()
		randomness.Destroy()
		if err != nil {
			return nil, err
		}
		factorDomain, err := refreshFactorProofDomain(s.cfg, s.cfg.Self, receiver, s.newPaillier.PublicKey, receiverData.ringPedersen.Params, s.planHash, s.limits)
		if err != nil {
			return nil, err
		}
		factorProof, err := zkpai.ProveFactor(s.securityParams, factorDomain, s.newPaillier, receiverData.ringPedersen.Params, s.cfg.Reader())
		if err != nil {
			return nil, err
		}
		payload, err := (refreshSharePayload{Ciphertext: ciphertext.Bytes(), Proof: *proof, PlanHash: s.planHash, FactorProof: *factorProof}).MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, err
		}
		env, err := newEnvelope(s.cfg, refreshShareRound, s.cfg.Self, receiver, payloadRefreshShare, payload)
		clear(payload)
		if err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	s.sharesSent = true
	clearSecpPolynomial(s.localPolynomial)
	s.localPolynomial = nil
	return out, nil
}

// allRefreshConfirmationsReceived returns true when every party has submitted a confirmation.
func (s *RefreshSession) allRefreshConfirmationsReceived() bool {
	for _, id := range s.oldKey.state.Parties {
		pd := s.partyData[id]
		if pd == nil || pd.confirmation == nil {
			return false
		}
	}
	return true
}
