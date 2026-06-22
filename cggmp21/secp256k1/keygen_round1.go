package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	shamirsecp "github.com/islishude/tss/internal/shamir/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// StartKeygen starts CGGMP21-style threshold ECDSA key generation from a shared
// keygen plan and local runtime configuration.
//
// In production, the shared plan is reconstructed independently by every party
// from the same authenticated keygen-run metadata. It does not require or imply
// sharing a Go object across parties. The run creator must generate one session
// ID for the keygen run and distribute it to every participant before parties
// call StartKeygen locally.
//
// Broadcast consistency: round 1 broadcasts commitments, Paillier keys, and proofs
// to all parties. The caller MUST ensure that every recipient receives identical
// broadcast payloads (equivocation-resistant transport). After keygen completes,
// all parties SHOULD compare KeygenTranscriptHash out-of-band to detect
// equivocation. A mismatch indicates a dishonest participant or compromised
// transport and requires aborting the key material.
func StartKeygen(plan *KeygenPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	config, limits, securityParams, planHash, err := resolveKeygenStart(plan, local, guard)
	if err != nil {
		return nil, nil, err
	}

	localMaterial, err := generateKeygenLocalMaterial(config, limits, securityParams, planHash)
	if err != nil {
		return nil, nil, err
	}
	s, err := newKeygenSession(config, limits, securityParams, planHash, guard, localMaterial)
	if err != nil {
		localMaterial.Destroy()
		return nil, nil, err
	}
	prepared := &preparedCGGMPKeygenStart{session: s}
	defer prepared.destroy()
	out, err := emitKeygenRound1(s, localMaterial)
	if err != nil {
		return nil, nil, err
	}
	prepared.out = out
	localMaterial.clearPolynomial()
	completionOut, err := s.tryAdvance()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, completionOut...)
	prepared.out = out
	prepared.markCommitted()
	return s, out, nil
}

func resolveKeygenStart(
	plan *KeygenPlan,
	local tss.LocalConfig,
	guard *tss.EnvelopeGuard,
) (tss.ThresholdConfig, Limits, SecurityParams, []byte, error) {
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, local.Self, err)
	}
	limits := plan.limits
	if err := config.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, config.SessionID, config.Self); err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	config.Parties = config.SortedParties()
	return config, limits, plan.securityParams, planHash, nil
}

func generateKeygenLocalMaterial(
	config tss.ThresholdConfig,
	limits Limits,
	securityParams SecurityParams,
	planHash []byte,
) (*keygenLocalMaterial, error) {
	chainCode := make([]byte, bip32util.ChainCodeSize)
	defer clear(chainCode)
	if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
		return nil, err
	}
	chainCodeCommit := bip32util.ChainCodeCommitment(cggmpChainCodeCommitLabel, config.SessionID, config.Self, chainCode)
	paillierKey, err := generatePaillierKey(config.Ctx(), config.Reader(), int(securityParams.MinPaillierBits))
	if err != nil {
		return nil, err
	}
	cleanup := newCleanupStack()
	defer cleanup.run()
	cleanup.add(paillierKey.Destroy)
	modDomain, err := keygenModulusDomain(config, config.Self, &paillierKey.PublicKey, planHash, limits)
	if err != nil {
		return nil, err
	}
	modProof, err := zkpai.ProveModulus(config.Reader(), modDomain, paillierKey, config.Self)
	if err != nil {
		return nil, err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(config.Reader(), paillierKey)
	if err != nil {
		return nil, err
	}
	defer ringPedersenLambda.Destroy()
	ringDomain, err := keygenRingPedersenDomain(config, config.Self, ringPedersenParams, planHash, limits)
	if err != nil {
		return nil, err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(
		config.Reader(),
		ringDomain,
		paillierKey,
		ringPedersenParams,
		ringPedersenLambda,
		config.Self,
	)
	if err != nil {
		return nil, err
	}
	poly, err := shamirsecp.RandomPolynomial(config.Reader(), config.Threshold, nil)
	if err != nil {
		return nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point := secp.ScalarBaseMult(coeff)
		encoded, err := secp.PointBytes(point)
		if err != nil {
			clearSecpPolynomial(poly)
			return nil, err
		}
		commitments[i] = encoded
	}
	localShare, err := secpSecretScalarFromScalar(shamirsecp.Eval(poly, config.Self))
	if err != nil {
		clearSecpPolynomial(poly)
		return nil, err
	}
	material := &keygenLocalMaterial{
		commitments:     commitments,
		localShare:      localShare,
		chainCode:       bytes.Clone(chainCode),
		chainCodeCommit: bytes.Clone(chainCodeCommit),
		paillier:        paillierKey,
		paillierPub: paillierPublicMaterial{
			Party:     config.Self,
			PublicKey: paillierKey.PublicKey.Clone(),
			Proof:     modProof.Clone(),
		},
		ringPedersen: ringPedersenPublicMaterial{
			Party:  config.Self,
			Params: ringPedersenParams.Clone(),
			Proof:  ringPedersenProof.Clone(),
		},
		polynomial: poly,
	}
	cleanup.disarm()
	return material, nil
}

func newKeygenSession(
	config tss.ThresholdConfig,
	limits Limits,
	securityParams SecurityParams,
	planHash []byte,
	guard *tss.EnvelopeGuard,
	local *keygenLocalMaterial,
) (*KeygenSession, error) {
	round1 := newKeygenRound1Inbox(config.Parties)
	if err := round1.recordLocal(config.Self, local); err != nil {
		return nil, err
	}
	return &KeygenSession{
		cfg:            config,
		limits:         limits,
		securityParams: securityParams,
		planHash:       bytes.Clone(planHash),
		local:          local,
		round1:         round1,
		confirmations:  newKeygenConfirmationInbox(config.Parties),
		state:          keygenCollectingRound1,
		guard:          guard,
	}, nil
}

func emitKeygenRound1(s *KeygenSession, local *keygenLocalMaterial) (out []tss.Envelope, err error) {
	if s == nil || local == nil || local.paillier == nil {
		return nil, errors.New("incomplete keygen start state")
	}
	defer func() {
		if err != nil {
			for i := range out {
				clear(out[i].Payload)
			}
			out = nil
		}
	}()
	out = make([]tss.Envelope, 0, len(s.cfg.Parties))
	commitPayload, err := (keygenCommitmentsPayload{
		Commitments:        local.commitments,
		PaillierPublicKey:  &local.paillier.PublicKey,
		PaillierProof:      local.paillierPub.Proof,
		ChainCodeCommit:    local.chainCodeCommit,
		RingPedersenParams: local.ringPedersen.Params,
		RingPedersenProof:  local.ringPedersen.Proof,
		PlanHash:           s.planHash,
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	commitEnv, err := newEnvelope(s.cfg, keygenStartRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenCommitments, commitPayload)
	clear(commitPayload)
	if err != nil {
		return nil, err
	}
	out = append(out, commitEnv)
	for _, id := range s.cfg.Parties {
		if id == s.cfg.Self {
			continue
		}
		share, err := secpSecretScalarFromScalar(shamirsecp.Eval(local.polynomial, id))
		if err != nil {
			return nil, err
		}
		payload, err := (keygenSharePayload{Share: share, PlanHash: s.planHash}).MarshalBinaryWithLimits(s.limits)
		share.Destroy()
		if err != nil {
			return nil, err
		}
		shareEnv, err := newEnvelope(s.cfg, keygenStartRound, s.cfg.Self, id, payloadKeygenShare, payload)
		clear(payload)
		if err != nil {
			return nil, err
		}
		out = append(out, shareEnv)
	}
	return out, nil
}

func (s *KeygenSession) buildAcceptCGGMPKeygenCommitmentsTx(env tss.Envelope) (*acceptCGGMPKeygenCommitmentsTx, error) {
	slot, err := s.round1.slot(env.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if slot.commitments != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate commitments"))
	}

	// ---- 1. PARSE ----
	p, err := tss.DecodeBinaryWithLimits[keygenCommitmentsPayload](env.Payload, s.limits)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenCommitment,
			"malformed keygen commitment payload",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
		)
	}

	// ---- 2. POLICY VALIDATE ----
	// (duplicate check done in dispatcher)
	if err := requirePlanHash("keygen", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if err := validateCommitments(p.Commitments, s.cfg.Threshold); err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenCommitment,
			"invalid keygen commitment",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			rawEvidenceField(evidenceFieldCommitmentsHash, transcript.ByteSlicesHash(keygenCommitmentsHashLabel, p.Commitments)),
		)
	}
	observedPaillierKeyHash, err := hashWireEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	pk := p.PaillierPublicKey
	proof := p.PaillierProof
	if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"Paillier modulus does not meet security requirements",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	modDomain, err := keygenModulusDomain(s.cfg, env.From, pk, s.planHash, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	if !zkpai.VerifyModulus(modDomain, pk, env.From, proof) {
		s.cfg.Logger().Warn(s.cfg.Ctx(), "invalid Paillier modulus proof",
			"party_id", s.cfg.Self,
			"from", env.From,
		)
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid Paillier modulus proof",
			tss.NewPartySet(env.From),
			errors.New("invalid Paillier modulus proof"),
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	ringParams := p.RingPedersenParams
	if ringParams.N.Cmp(pk.N) != 0 {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"Ring-Pedersen modulus mismatch",
			tss.NewPartySet(env.From),
			errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	ringProof := p.RingPedersenProof
	ringDomain, err := keygenRingPedersenDomain(s.cfg, env.From, ringParams, s.planHash, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	if !zkpai.VerifyRingPedersen(s.securityParams, ringDomain, ringParams, env.From, ringProof) {
		s.cfg.Logger().Warn(s.cfg.Ctx(), "invalid Ring-Pedersen proof",
			"party_id", s.cfg.Self,
			"from", env.From,
		)
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid Ring-Pedersen proof",
			tss.NewPartySet(env.From),
			errors.New("invalid Ring-Pedersen proof"),
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}

	if len(p.ChainCodeCommit) != sha256.Size {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("chain code commit must be %d bytes, got %d", sha256.Size, len(p.ChainCodeCommit)))
	}
	return &acceptCGGMPKeygenCommitmentsTx{
		from:            env.From,
		commitments:     p.Commitments,
		chainCodeCommit: bytes.Clone(p.ChainCodeCommit),
		paillierPub: paillierPublicMaterial{
			Party:     env.From,
			PublicKey: p.PaillierPublicKey.Clone(),
			Proof:     p.PaillierProof.Clone(),
		},
		ringPedersen: ringPedersenPublicMaterial{
			Party:  env.From,
			Params: p.RingPedersenParams.Clone(),
			Proof:  p.RingPedersenProof.Clone(),
		},
	}, nil
}

func (s *KeygenSession) buildAcceptCGGMPKeygenShareTx(env tss.Envelope) (*acceptCGGMPKeygenShareTx, error) {
	slot, err := s.round1.slot(env.From)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if slot.share != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate share"))
	}

	// ---- 1. PARSE ----
	p, err := tss.DecodeBinaryWithLimits[keygenSharePayload](env.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if p.Share == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("missing keygen share"))
	}

	// ---- 2. POLICY VALIDATE ----
	// (direct-confidential, duplicate checks done in dispatcher)
	if err := requirePlanHash("keygen", p.PlanHash, s.planHash); err != nil {
		p.Share.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	share, err := secpScalarFromSecret(p.Share)
	if err != nil {
		p.Share.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}

	// Eagerly verify the share against the sender's polynomial commitments
	// when they are already available. If the commitments have not arrived
	// yet, defer verification to tryComplete (which re-checks all shares
	// once every party's commitments are in).
	if slot.commitments != nil {
		if err := secp.VerifyShare(slot.commitments, s.cfg.Self, share); err != nil {
			s.cfg.Logger().Warn(s.cfg.Ctx(), "invalid DKG share (eager verification)",
				"party_id", s.cfg.Self,
				"dealer", env.From,
			)
			protoErr, evErr := s.buildShareVerificationBlame(env.From, slot.commitments, err)
			if evErr != nil {
				p.Share.Destroy()
				return nil, evErr
			}
			p.Share.Destroy()
			return nil, protoErr
		}
	}
	return &acceptCGGMPKeygenShareTx{
		from:  env.From,
		share: p.Share,
	}, nil
}

// Complete returns the confirmed local key share when keygen has finished.
func (s *KeygenSession) Complete() (*KeyShare, bool) {
	if s == nil || s.state != keygenConfirmed || !s.completed {
		return nil, false
	}
	return cloneKeyShareValue(s.keyShare), true
}

// KeyShare returns the confirmed local key share when keygen has finished.
func (s *KeygenSession) KeyShare() (*KeyShare, bool) {
	return s.Complete()
}

func validateCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for _, commitment := range commitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return err
		}
	}
	return nil
}
