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
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// StartKeygen starts CGGMP21-style threshold ECDSA key generation from a shared
// keygen plan and local runtime configuration.
//
// Broadcast consistency: round 1 broadcasts commitments, Paillier keys, and proofs
// to all parties. The caller MUST ensure that every recipient receives identical
// broadcast payloads (equivocation-resistant transport). After keygen completes,
// all parties SHOULD compare KeygenTranscriptHash out-of-band to detect
// equivocation. A mismatch indicates a dishonest participant or compromised
// transport and requires aborting the key material.
func StartKeygen(plan *KeygenPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
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

	// Sort parties to ensure consistent broadcast ordering and transcript hashes across
	config.Parties = config.SortedParties()

	chainCode := make([]byte, bip32util.ChainCodeSize)
	if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
		return nil, nil, err
	}
	chainCodeCommit := cggmpChainCodeCommit(config.SessionID, config.Self, chainCode)
	paillierKey, err := generatePaillierKey(config.Ctx(), config.Reader(), int(plan.securityParams.MinPaillierBits))
	if err != nil {
		return nil, nil, err
	}
	paillierPubBytes, err := paillierKey.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	modProof, err := zkpai.ProveModulus(config.Reader(), keygenModulusDomain(config, config.Self, paillierPubBytes, planHash), paillierKey, config.Self)
	if err != nil {
		return nil, nil, err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(config.Reader(), paillierKey)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenParamsBytes, err := zkpai.MarshalRingPedersenParams(ringPedersenParams)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(config.Reader(), keygenRingPedersenDomain(config, config.Self, ringPedersenParamsBytes, planHash), paillierKey, ringPedersenParams, ringPedersenLambda, config.Self)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenProofBytes, err := zkpai.Marshal(ringPedersenProof)
	if err != nil {
		return nil, nil, err
	}
	poly, err := shamir.RandomPolynomial(config.Reader(), secp.Order(), config.Threshold, nil)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point := secp.ScalarBaseMult(secp.ScalarFromBigInt(coeff))
		enc, err := secp.PointBytes(point)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	partyData := make(map[tss.PartyID]*keygenPartyData, len(config.Parties))
	for _, id := range config.Parties {
		if id == config.Self {
			partyData[id] = &keygenPartyData{
				commitments:     commitments,
				share:           shamir.Eval(poly, id, secp.Order()),
				chainCode:       bytes.Clone(chainCode),
				chainCodeCommit: bytes.Clone(chainCodeCommit),
				paillierPub:     PaillierPublicShare{Party: id, PublicKey: paillierPubBytes, Proof: modProofBytes},
				ringPedersen:    RingPedersenPublicShare{Party: id, Params: ringPedersenParamsBytes, Proof: ringPedersenProofBytes},
			}
		} else {
			partyData[id] = new(keygenPartyData)
		}
	}
	s := &KeygenSession{
		cfg:            config,
		log:            config.Logger(),
		limits:         limits,
		securityParams: plan.securityParams,
		planHash:       bytes.Clone(planHash),
		partyData:      partyData,
		paillier:       paillierKey,
		state:          keygenCollecting,
		guard:          guard,
	}
	out := make([]tss.Envelope, 0, len(config.Parties))
	commitPayload, err := marshalKeygenCommitmentsPayloadWithLimits(keygenCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  paillierPubBytes,
		PaillierProof:      modProofBytes,
		ChainCodeCommit:    chainCodeCommit,
		RingPedersenParams: ringPedersenParamsBytes,
		RingPedersenProof:  ringPedersenProofBytes,
		PlanHash:           planHash,
	}, s.limits)
	if err != nil {
		return nil, nil, err
	}
	commitEnv, err := newEnvelope(config, keygenStartRound, config.Self, tss.BroadcastPartyId, payloadKeygenCommitments, commitPayload)
	if err != nil {
		return nil, nil, err
	}
	out = append(out, commitEnv)
	for _, id := range config.Parties {
		if id == config.Self {
			continue
		}
		share := shamir.Eval(poly, id, secp.Order())
		payload, err := marshalKeygenSharePayloadWithLimits(keygenSharePayload{Share: share, PlanHash: planHash}, s.limits)
		if err != nil {
			return nil, nil, err
		}
		shareEnv, err := newEnvelope(config, keygenStartRound, config.Self, id, payloadKeygenShare, payload)
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

// handleKeygenCommitments validates and applies a keygen commitments payload.
//
// Follows the handler template (see doc.go).
func (s *KeygenSession) handleKeygenCommitments(env tss.Envelope) ([]tss.Envelope, error) {
	// ---- 1. PARSE ----
	p, err := unmarshalKeygenCommitmentsPayloadWithLimits(env.Payload, s.limits)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenCommitment,
			"malformed keygen commitment payload",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
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
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			rawEvidenceField(evidenceFieldCommitmentsHash, wireutil.ByteSlicesHash(keygenCommitmentsHashLabel, p.Commitments)),
		)
	}
	pk, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PaillierPublicKey, s.limits.Paillier.MaxModulusBits)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed Paillier public key",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	proof, err := zkpai.UnmarshalModulusProof(p.PaillierProof)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed Paillier modulus proof",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"Paillier modulus does not meet security requirements",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	if !zkpai.VerifyModulus(keygenModulusDomain(s.cfg, env.From, p.PaillierPublicKey, s.planHash), pk, env.From, proof) {
		s.log.Warn(s.cfg.Ctx(), "invalid Paillier modulus proof",
			"party_id", s.cfg.Self,
			"from", env.From,
		)
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid Paillier modulus proof",
			tss.NewPartySet(env.From),
			errors.New("invalid Paillier modulus proof"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	ringParams, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(p.RingPedersenParams, s.limits.Paillier.MaxModulusBits)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed Ring-Pedersen parameters",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	if ringParams.N.Cmp(pk.N) != 0 {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"Ring-Pedersen modulus mismatch",
			tss.NewPartySet(env.From),
			errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	ringProof, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed Ring-Pedersen proof",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	if !zkpai.VerifyRingPedersen(keygenRingPedersenDomain(s.cfg, env.From, p.RingPedersenParams, s.planHash), ringParams, env.From, ringProof) {
		s.log.Warn(s.cfg.Ctx(), "invalid Ring-Pedersen proof",
			"party_id", s.cfg.Self,
			"from", env.From,
		)
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid Ring-Pedersen proof",
			tss.NewPartySet(env.From),
			errors.New("invalid Ring-Pedersen proof"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}

	// ---- 4. MUTATE STATE ----
	pd := s.partyData[env.From]
	pd.commitments = p.Commitments
	if len(p.ChainCodeCommit) != sha256.Size {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("chain code commit must be %d bytes, got %d", sha256.Size, len(p.ChainCodeCommit)))
	}
	pd.chainCodeCommit = bytes.Clone(p.ChainCodeCommit)
	pd.paillierPub = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
	pd.ringPedersen = RingPedersenPublicShare{Party: env.From, Params: p.RingPedersenParams, Proof: p.RingPedersenProof}

	// ---- 5. EMIT ----
	return s.tryComplete()
}

// handleKeygenShare validates and applies a keygen share payload.
//
// Follows the handler template (see doc.go).
func (s *KeygenSession) handleKeygenShare(env tss.Envelope) ([]tss.Envelope, error) {
	// ---- 1. PARSE ----
	p, err := unmarshalKeygenSharePayloadWithLimits(env.Payload, s.limits)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}

	// ---- 2. POLICY VALIDATE ----
	// (direct-confidential, duplicate checks done in dispatcher)
	if err := requirePlanHash("keygen", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	share := secp.ScalarFromBigInt(p.Share)

	// Eagerly verify the share against the sender's polynomial commitments
	// when they are already available. If the commitments have not arrived
	// yet, defer verification to tryComplete (which re-checks all shares
	// once every party's commitments are in).
	if pd := s.partyData[env.From]; pd.commitments != nil {
		if err := secp.VerifyShare(pd.commitments, s.cfg.Self, share); err != nil {
			s.log.Warn(s.cfg.Ctx(), "invalid DKG share (eager verification)",
				"party_id", s.cfg.Self,
				"dealer", env.From,
			)
			protoErr, evErr := s.buildShareVerificationBlame(env.From, pd.commitments, err)
			if evErr != nil {
				return nil, evErr
			}
			return nil, protoErr
		}
	}

	// ---- 4. MUTATE STATE ----
	s.partyData[env.From].share = share.BigInt()

	// ---- 5. EMIT ----
	return s.tryComplete()
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
