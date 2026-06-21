package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	shamirsecp "github.com/islishude/tss/internal/shamir/secp256k1"
	"github.com/islishude/tss/internal/transcript"
)

// StartPresign starts this party's local offline CGGMP-style presign state
// machine from a shared immutable lifecycle plan. Production applications should
// create one presign run with one session ID, one signer set, and one context,
// then have every signer reconstruct an equivalent plan locally. The resulting
// Presign is a party-local one-use record and must be durably persisted before
// it is made available for signing.
func StartPresign(key *KeyShare, plan *PresignPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (s *PresignSession, out []tss.Envelope, err error) {
	if key == nil || key.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil key share"))
	}
	if local.Self == 0 {
		local.Self = key.state.party
	}
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil presign plan"))
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, plan.state.sessionID, local.Self); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := key.requireMPCMaterial(plan.limits); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	limits := plan.limits
	if err := plan.validateKey(key, local); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	sessionID := plan.state.sessionID
	signers := slices.Clone(plan.state.signers)
	// Snapshot the normalized context and derivation once. The resulting
	// Presign stores derivation.ChildPublicKey as the verification key.
	ctx := plan.state.context.Clone()
	contextHash := slices.Clone(plan.state.contextHash)
	derivation := plan.state.derivation.Clone()
	derivationOwned := false
	defer func() {
		if !derivationOwned && derivation != nil {
			derivation.Destroy()
		}
	}()
	paillierKey, err := key.paillierPrivate()
	if err != nil {
		return nil, nil, err
	}
	paillierOwned := false
	defer func() {
		if !paillierOwned && paillierKey != nil {
			paillierKey.Destroy()
		}
	}()
	config := tss.ThresholdConfig{
		Threshold:    key.state.threshold,
		Parties:      signers,
		Self:         local.Self,
		SessionID:    sessionID,
		Rand:         local.Rand,
		Context:      local.Context,
		RoundTimeout: local.RoundTimeout,
		Log:          local.Log,
	}
	// k_i and gamma_i are local nonce scalars. Only Enc(k_i) and Gamma_i leave
	// the process; the raw nonce scalars stay inside the local presign record.
	kShare, err := secp.RandomScalar(config.Reader())
	if err != nil {
		return nil, nil, err
	}
	gamma, err := secp.RandomScalar(config.Reader())
	if err != nil {
		return nil, nil, err
	}
	gammaComm, err := secp.PointBytes(secp.ScalarBaseMult(gamma))
	if err != nil {
		return nil, nil, err
	}
	lambda, err := shamirsecp.LagrangeCoefficient(key.state.party, signers)
	if err != nil {
		return nil, nil, err
	}
	sec, err := secpScalarFromSecret(key.state.secret)
	if err != nil {
		return nil, nil, err
	}
	// xBar is lambda_i*x_i, the signer-set-adjusted secret share used in
	// chi = k*x. The public commitment is derived from the verification share.
	xBar := secp.ScalarMul(lambda, sec)
	kShareSecret, err := newSecpSecretScalar(kShare.Bytes())
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			kShareSecret.Destroy()
		}
	}()
	gammaSecret, err := newSecpSecretScalar(gamma.Bytes())
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			gammaSecret.Destroy()
		}
	}()
	xBarSecret, err := secpSecretScalarFromScalar(xBar)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			xBarSecret.Destroy()
		}
	}()
	localVerificationShare, ok := key.verificationShare(key.state.party)
	if !ok {
		return nil, nil, errors.New("missing local verification share")
	}
	localVerificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, nil, err
	}
	xBarComm, err := secp.PointBytes(secp.ScalarMult(localVerificationPoint, lambda))
	if err != nil {
		return nil, nil, err
	}
	// Round 1 publishes Enc_i(k_i); each peer receives a verifier-specific
	// Πenc proof bound to that public payload and the peer's RP parameters.
	startOpening, err := mta.Start(config.Reader(), kShareSecret, &paillierKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	paillierPub, err := key.paillierPublicFor(key.state.party, limits)
	if err != nil {
		return nil, nil, err
	}
	openingReturned := false
	defer func() {
		if !openingReturned {
			startOpening.Destroy()
		}
	}()
	presignPayload := presignRound1Payload{
		Gamma:             gammaComm,
		EncK:              slices.Clone(startOpening.Message.Ciphertext),
		PaillierPublicKey: *paillierPub,
		PlanHash:          slices.Clone(planHash),
	}
	payload, err := presignPayload.MarshalBinaryWithLimits(limits)
	if err != nil {
		return nil, nil, err
	}
	publicHash, err := presignRound1PublicHash(presignPayload, limits)
	if err != nil {
		return nil, nil, err
	}
	env, err := newEnvelope(config, 1, key.state.party, tss.BroadcastPartyId, payloadPresignRound1, payload)
	if err != nil {
		return nil, nil, err
	}
	parties, partyIndex := newPresignPartyStates(signers)
	selfState := &parties[partyIndex[key.state.party]]
	selfState.round1.payload = presignPayload
	selfState.round1.havePayload = true
	selfState.round1.verified = true
	s = &PresignSession{
		key:            key,
		sessionID:      sessionID,
		config:         config,
		log:            config.Logger(),
		limits:         limits,
		securityParams: plan.securityParams,
		signers:        signers,
		context:        ctx,
		contextHash:    contextHash,
		derivation:     derivation,
		planHash:       slices.Clone(planHash),
		paillier:       paillierKey,
		kShare:         kShareSecret,
		gamma:          gammaSecret,
		xBar:           xBarSecret,
		gammaComm:      gammaComm,
		xBarComm:       xBarComm,
		partyIndex:     partyIndex,
		parties:        parties,
		startOpening:   startOpening,
		guard:          guard,
	}
	derivationOwned = true
	paillierOwned = true
	openingReturned = true
	prepared := &preparedPresignStart{session: s}
	defer prepared.destroy()
	// Defensive: clear local secret scalar references so only session fields
	// own the secrets. The defer guards above will not fire since err is nil.
	// startOpening is kept alive for the per-verifier proof loop below.
	kShareSecret = nil
	gammaSecret = nil
	xBarSecret = nil

	out = []tss.Envelope{env}
	prepared.out = out
	for _, peer := range signers {
		if peer == key.state.party {
			continue
		}
		peerRP, err := key.ringPedersenPublicFor(peer, limits)
		if err != nil {
			return nil, nil, err
		}
		proofDomain, err := mtaStartProofDomain(key, sessionID, signers, key.state.party, peer, &paillierKey.PublicKey, contextHash, planHash, limits)
		if err != nil {
			return nil, nil, err
		}
		proof, err := mta.ProveStartForVerifier(plan.securityParams, config.Reader(), proofDomain, s.startOpening, &s.paillier.PublicKey, peerRP)
		if err != nil {
			return nil, nil, err
		}
		proofPayload, err := (presignRound1ProofPayload{
			PublicRound1Hash: publicHash,
			EncKProof:        *proof,
			PlanHash:         slices.Clone(planHash),
		}).MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, nil, err
		}
		proofEnv, err := newEnvelope(config, 1, key.state.party, peer, payloadPresignRound1Proof, proofPayload)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, proofEnv)
		prepared.out = out
	}
	// Clear startOpening after all per-verifier proofs are generated.
	// The MtA Finish path in round 2 only uses the Paillier private key and the
	// StartMessage ciphertext — the StartOpening witness (k, rho) is never read
	// after the proofs are generated. Clear it early to reduce the window of
	// secret material exposure.
	s.startOpening.Destroy()
	s.startOpening = nil
	startOpening = nil

	round2, err := s.tryEmitRound2()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round2...)
	prepared.out = out
	round3, err := s.tryEmitRound3()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round3...)
	prepared.out = out
	prepared.markCommitted()
	return s, out, nil
}

func (s *PresignSession) buildAcceptPresignRound1PayloadTx(env tss.Envelope) (*acceptPresignRound1PayloadTx, error) {
	// ---- 1. PARSE ----
	p, err := tss.DecodeBinaryValueWithLimits[presignRound1Payload](env.Payload, s.limits)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound1,
			"malformed presign round1 payload",
			tss.NewPartySet(env.From),
			err,
			fields...,
		)
	}

	// ---- 2. POLICY VALIDATE ----
	// (round, broadcast, duplicate, transport checks done in dispatcher)
	if err := requirePlanHash("presign", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if err := s.validateRound1Public(env.From, p); err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPresignRound1,
			"invalid presign round1 public payload",
			tss.NewPartySet(env.From),
			err,
			s.presignRound1EvidenceFields(env.From, p)...,
		)
	}

	st, ok := s.partyState(env.From)
	if !ok {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errPresignSignerMissing)
	}
	verified := false
	if st.round1.haveProof {
		if err := s.validateRound1Proof(env.From, p, st.round1.proof); err != nil {
			proofEnv := st.round1.proofEnvelope
			return nil, verificationErrorWithEvidence(
				proofEnv,
				tss.EvidenceKindPresignRound1,
				"invalid presign round1 proof",
				tss.NewPartySet(env.From),
				err,
				s.presignRound1ProofEvidenceFields(env.From, p, st.round1.proof)...,
			)
		}
		verified = true
	}
	return &acceptPresignRound1PayloadTx{
		from:     env.From,
		payload:  p,
		verified: verified,
	}, nil
}

func (s *PresignSession) buildAcceptPresignRound1ProofTx(env tss.Envelope) (*acceptPresignRound1ProofTx, error) {
	// ---- 1. PARSE ----
	p, err := tss.DecodeBinaryValueWithLimits[presignRound1ProofPayload](env.Payload, s.limits)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound1,
			"malformed presign round1 proof payload",
			tss.NewPartySet(env.From),
			err,
			fields...,
		)
	}

	// ---- 2. POLICY VALIDATE ----
	// (round, direct-confidential, self-send, duplicate checks done in dispatcher)
	if err := requirePlanHash("presign", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}

	st, ok := s.partyState(env.From)
	if !ok {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errPresignSignerMissing)
	}
	verified := false
	if st.round1.havePayload {
		if err := s.validateRound1Proof(env.From, st.round1.payload, p); err != nil {
			public := st.round1.payload
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPresignRound1,
				"invalid presign round1 proof",
				tss.NewPartySet(env.From),
				err,
				s.presignRound1ProofEvidenceFields(env.From, public, p)...,
			)
		}
		verified = true
	}
	return &acceptPresignRound1ProofTx{
		from:          env.From,
		proof:         p,
		proofEnvelope: env.Clone(),
		verified:      verified,
	}, nil
}

func (s *PresignSession) presignRound1EvidenceFields(from tss.PartyID, p presignRound1Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	publicHash, _ := presignRound1PublicHash(p, s.limits)
	observedPaillierField, err := hashWireEvidenceField(evidenceFieldObservedPaillierKeyHash, &p.PaillierPublicKey, s.limits)
	if err != nil {
		observedPaillierField = rawEvidenceField(evidenceFieldObservedPaillierKeyHash, hashBytes(nil))
	}
	fields = append(fields,
		observedPaillierField,
		rawEvidenceField("round1_public_hash", publicHash),
		hashEvidenceField("gamma_hash", p.Gamma),
		hashEvidenceField("enc_k_hash", p.EncK),
	)
	if expected, err := s.key.paillierPublicFor(from, s.limits); err == nil {
		if encoded, err := expected.MarshalBinary(); err == nil {
			fields = append(fields, hashEvidenceField(evidenceFieldExpectedPaillierKeyHash, encoded))
		}
	}
	return fields
}

func (s *PresignSession) presignRound1ProofEvidenceFields(from tss.PartyID, public presignRound1Payload, proof presignRound1ProofPayload) []tss.EvidenceField {
	fields := s.presignRound1EvidenceFields(from, public)
	proofBytes, _ := canonicalWireMessageBytes(&proof.EncKProof, s.limits)
	return append(fields,
		rawEvidenceField("proof_public_round1_hash", proof.PublicRound1Hash),
		hashEvidenceField("enc_k_proof_hash", proofBytes),
	)
}

func (s *PresignSession) validateRound1Public(from tss.PartyID, p presignRound1Payload) error {
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return fmt.Errorf("invalid gamma: %w", err)
	}
	expectedPK, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return err
	}
	expectedPKBytes, err := canonicalWireMessageBytes(expectedPK, s.limits)
	if err != nil {
		return err
	}
	observedPKBytes, err := canonicalWireMessageBytes(&p.PaillierPublicKey, s.limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedPKBytes, observedPKBytes) {
		return errors.New("round1 Paillier public key does not match keygen")
	}
	ciphertext := new(big.Int).SetBytes(p.EncK)
	if err := expectedPK.ValidateCiphertext(ciphertext); err != nil {
		return fmt.Errorf("invalid encrypted nonce ciphertext: %w", err)
	}
	return nil
}

func (s *PresignSession) validateRound1Proof(from tss.PartyID, public presignRound1Payload, proof presignRound1ProofPayload) error {
	publicHash, err := presignRound1PublicHash(public, s.limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(publicHash, proof.PublicRound1Hash) {
		return errors.New("presign round1 proof public hash mismatch")
	}
	proverPK, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.state.party, s.limits)
	if err != nil {
		return err
	}
	start := mta.StartMessage{Ciphertext: public.EncK}
	domain, err := mtaStartProofDomain(s.key, s.sessionID, s.signers, from, s.key.state.party, &public.PaillierPublicKey, s.contextHash, s.planHash, s.limits)
	if err != nil {
		return err
	}
	return mta.VerifyStart(s.securityParams, domain, start, proverPK, localRP, &proof.EncKProof)
}

func presignRound1PublicHash(p presignRound1Payload, limits Limits) ([]byte, error) {
	payload, err := p.MarshalBinaryWithLimits(limits)
	if err != nil {
		return nil, err
	}
	t := transcript.New(presignRound1PublicLabel)
	t.AppendBytes("payload", payload)
	return t.Sum(), nil
}
