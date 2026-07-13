package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/sessiontx"
	"github.com/islishude/tss/internal/shamir"
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
	s, err := newKeygenSession(config, limits, securityParams, planHash, guard, localMaterial, nil)
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
	if err := requireLocalEnvelopeSigner(guard, local.EnvelopeSigner); err != nil {
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
	return generateKeygenLocalMaterialWithContribution(config, limits, planHash, nil, nil, int(securityParams.MinPaillierBits))
}

func generateKeygenLocalMaterialWithContribution(
	config tss.ThresholdConfig,
	limits Limits,
	planHash []byte,
	constant *secp.Scalar,
	chainContribution []byte,
	paillierBits int,
) (*keygenLocalMaterial, error) {
	chainCode := bytes.Clone(chainContribution)
	if chainCode == nil {
		chainCode = make([]byte, bip32util.ChainCodeSize)
		if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
			return nil, err
		}
	} else if len(chainCode) != bip32util.ChainCodeSize {
		return nil, errors.New("trusted-dealer chain code contribution must be 32 bytes")
	}
	defer clear(chainCode)
	chainCodeCommit := bip32util.ChainCodeCommitment(cggmpChainCodeCommitLabel, config.SessionID, config.Self, chainCode)
	paillierKey, err := generatePaillierKey(config.Ctx(), config.Reader(), paillierBits)
	if err != nil {
		return nil, err
	}
	cleanup := sessiontx.NewCleanupStack()
	defer cleanup.Run()
	cleanup.Add(paillierKey.Destroy)
	modDomain, err := keygenModulusDomain(config, config.Self, paillierKey.PublicKey, planHash, limits)
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
	poly, err := shamir.RandomPolynomial(config.Reader(), config.Threshold, constant)
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
	localShare, err := secpSecretScalarFromScalar(shamir.Eval(poly, config.Self))
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
	cleanup.Disarm()
	return material, nil
}

func newKeygenSession(
	config tss.ThresholdConfig,
	limits Limits,
	securityParams SecurityParams,
	planHash []byte,
	guard *tss.EnvelopeGuard,
	local *keygenLocalMaterial,
	importPlan *TrustedDealerImportPlan,
) (*KeygenSession, error) {
	round1 := newKeygenRound1Inbox(config.Parties)
	if err := round1.recordLocal(config.Self, local); err != nil {
		return nil, err
	}
	return &KeygenSession{
		cfg:                  config,
		limits:               limits,
		securityParams:       securityParams,
		planHash:             bytes.Clone(planHash),
		importPlan:           cloneCGGMPTrustedDealerPlan(importPlan),
		local:                local,
		round1:               round1,
		confirmations:        newKeygenConfirmationInbox(config.Parties),
		pendingConfirmations: make(map[tss.PartyID]*KeygenConfirmation),
		state:                keygenCollectingRound1,
		guard:                guard,
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
	out = make([]tss.Envelope, 0, 1)
	commitPayload, err := (keygenCommitmentsPayload{
		Commitments:        local.commitments,
		PaillierPublicKey:  local.paillier.PublicKey,
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
	return out, nil
}

func (s *KeygenSession) emitEncryptedKeygenShares() ([]tss.Envelope, error) {
	if s.sharesSent || s.local == nil || len(s.local.polynomial) == 0 || !s.round1.commitmentsComplete() {
		return nil, nil
	}
	out := make([]tss.Envelope, 0, len(s.cfg.Parties)-1)
	for _, receiver := range s.cfg.Parties {
		if receiver == s.cfg.Self {
			continue
		}
		slot, err := s.round1.slot(receiver)
		if err != nil {
			return nil, err
		}
		shareScalar := shamir.Eval(s.local.polynomial, receiver)
		share, err := secpSecretScalarFromScalarAllowZero(shareScalar)
		if err != nil {
			return nil, err
		}
		ciphertext, randomness, err := slot.paillierPub.PublicKey.EncryptSecret(s.cfg.Reader(), share)
		if err != nil {
			share.Destroy()
			return nil, err
		}
		evaluation, err := secp.EvalCommitments(s.local.commitments, receiver)
		if err != nil {
			share.Destroy()
			randomness.Destroy()
			return nil, err
		}
		domain, err := keygenEncryptedShareDomain(s.cfg, s.cfg.Self, receiver, slot.paillierPub.PublicKey, s.planHash, s.limits)
		if err != nil {
			share.Destroy()
			randomness.Destroy()
			return nil, err
		}
		proof, err := zkpai.ProveLogStar(s.securityParams, domain, zkpai.LogStarStatement{
			PaillierN: slot.paillierPub.PublicKey, C: ciphertext, X: evaluation,
			B: secp.ScalarBaseMult(secp.ScalarOne()), VerifierAux: slot.ringPedersen.Params,
		}, zkpai.LogStarWitness{X: share, Rho: randomness}, s.cfg.Reader())
		share.Destroy()
		randomness.Destroy()
		if err != nil {
			return nil, err
		}
		factorDomain, err := keygenFactorProofDomain(s.cfg, s.cfg.Self, receiver, s.local.paillier.PublicKey, slot.ringPedersen.Params, s.planHash, s.limits)
		if err != nil {
			return nil, err
		}
		factorProof, err := zkpai.ProveFactor(s.securityParams, factorDomain, s.local.paillier, slot.ringPedersen.Params, s.cfg.Reader())
		if err != nil {
			return nil, err
		}
		payload, err := (keygenSharePayload{Ciphertext: ciphertext.Bytes(), Proof: *proof, PlanHash: s.planHash, FactorProof: *factorProof}).MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, err
		}
		env, err := newEnvelope(s.cfg, keygenShareRound, s.cfg.Self, receiver, payloadKeygenShare, payload)
		clear(payload)
		if err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	s.sharesSent = true
	s.local.clearPolynomial()
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
	if s.importPlan != nil {
		expected, ok := s.importPlan.commitmentFor(env.From)
		if !ok || len(p.Commitments) == 0 || !bytes.Equal(p.Commitments[0], expected.ConstantCommitment) || !bytes.Equal(p.ChainCodeCommit, expected.ChainCodeCommit) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenCommitment,
				"keygen commitment does not match trusted-dealer import plan",
				tss.NewPartySet(env.From),
				errors.New("trusted-dealer import commitment mismatch"),
				rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			)
		}
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
			tss.EvidenceKindPaillierAux,
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
			tss.EvidenceKindPaillierAux,
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
			tss.EvidenceKindPaillierAux,
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
		return nil, protocolErrorWithEvidence(tss.ErrCodeInvalidMessage, env, tss.EvidenceKindPaillierAux,
			"malformed keygen share or Paillier factor proof", tss.NewPartySet(env.From), err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)))
	}
	// ---- 2. POLICY VALIDATE ----
	// (direct-confidential, duplicate checks done in dispatcher)
	if err := requirePlanHash("keygen", p.PlanHash, s.planHash); err != nil {
		return nil, protocolErrorWithEvidence(tss.ErrCodeVerification, env, tss.EvidenceKindPaillierAux,
			"keygen share factor proof plan mismatch", tss.NewPartySet(env.From), err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)))
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if slot.commitments == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("encrypted keygen share arrived before dealer commitments"))
	}
	localSlot, err := s.round1.slot(s.cfg.Self)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	factorDomain, err := keygenFactorProofDomain(s.cfg, env.From, s.cfg.Self, slot.paillierPub.PublicKey, localSlot.ringPedersen.Params, s.planHash, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	if err := zkpai.VerifyFactor(s.securityParams, factorDomain, zkpai.FactorStatement{ProverPaillierN: slot.paillierPub.PublicKey, VerifierAux: localSlot.ringPedersen.Params}, &p.FactorProof); err != nil {
		return nil, verificationErrorWithEvidence(env, tss.EvidenceKindPaillierAux, "invalid Paillier factor proof", tss.NewPartySet(env.From), err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)))
	}
	evaluation, err := secp.EvalCommitments(slot.commitments, s.cfg.Self)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	domain, err := keygenEncryptedShareDomain(s.cfg, env.From, s.cfg.Self, localSlot.paillierPub.PublicKey, s.planHash, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	ciphertext := new(big.Int).SetBytes(p.Ciphertext)
	if err := zkpai.VerifyLogStar(s.securityParams, domain, zkpai.LogStarStatement{
		PaillierN: localSlot.paillierPub.PublicKey, C: ciphertext, X: evaluation,
		B: secp.ScalarBaseMult(secp.ScalarOne()), VerifierAux: localSlot.ringPedersen.Params,
	}, &p.Proof); err != nil {
		p.Proof.Destroy()
		return nil, verificationErrorWithEvidence(env, tss.EvidenceKindKeygenShare,
			"invalid encrypted keygen share proof", tss.NewPartySet(env.From), err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			rawEvidenceField(evidenceFieldCommitmentsHash, transcript.ByteSlicesHash(keygenCommitmentsHashLabel, slot.commitments)),
			hashEvidenceField("encrypted_share_ciphertext_hash", p.Ciphertext))
	}
	p.Proof.Destroy()
	plaintext, err := s.local.paillier.Decrypt(ciphertext)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, 0, fmt.Errorf("verified encrypted keygen share decryption failed: %w", err))
	}
	defer secret.ClearBigInt(plaintext)
	if plaintext.Sign() < 0 || plaintext.Cmp(secp.Order()) >= 0 {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, 0, errors.New("verified encrypted keygen share plaintext is outside scalar field"))
	}
	shareBytes := make([]byte, secp.ScalarSize)
	plaintext.FillBytes(shareBytes)
	share, err := newSecpSecretScalarAllowZero(shareBytes)
	clear(shareBytes)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, 0, err)
	}
	shareScalar, err := secpScalarFromSecretAllowZero(share)
	if err != nil || secp.VerifyShare(slot.commitments, s.cfg.Self, shareScalar) != nil {
		share.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, 0, errors.New("verified encrypted share decrypted inconsistently"))
	}
	return &acceptCGGMPKeygenShareTx{
		from: env.From, share: share, factorProof: p.FactorProof.Clone(),
	}, nil
}

// Complete returns the confirmed local key share when keygen has finished.
func (s *KeygenSession) Complete() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != keygenConfirmed || !s.completed {
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
