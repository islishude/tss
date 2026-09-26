package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/planvalidation"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/tssrun"
)

// StartPresign starts this party's local offline CGGMP-style presign state
// machine from a shared immutable lifecycle plan and an exact current key
// generation loaded from runtime.LifecycleStore. A caller-supplied raw KeyShare
// is intentionally not accepted. The RunPresign lease is durable before any
// protocol envelope is returned, and successful completion atomically installs
// the secret presign record before the session exposes public metadata.
func StartPresign(plan *PresignPlan, runtime PresignRuntime) (s *PresignSession, out []tss.Envelope, err error) {
	local := runtime.Local
	if err := validatePresignRuntime(plan, runtime); err != nil {
		return nil, nil, err
	}

	timeout := durableStoreTimeout(runtime.DurableStoreTimeout)
	key, err := loadLifecycleKeyShare(local.Ctx(), runtime.LifecycleStore, runtime.Binding, plan.limits, timeout)
	if err != nil {
		return nil, nil, err
	}
	keyOwned := true
	defer func() {
		if keyOwned {
			key.Destroy()
		}
	}()
	if err := plan.validateKey(key, local); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	sessionID := plan.state.sessionID
	storeCtx, cancel := durableStoreContext(local.Ctx(), timeout)
	lease, err := runtime.LifecycleStore.AcquireRunLease(storeCtx, runtime.Binding, tssrun.RunPresign, sessionID)
	cancel()
	if err != nil {
		return nil, nil, err
	}
	leaseOwned := true
	var recoverableSession *PresignSession
	defer func() {
		if err == nil || !leaseOwned {
			return
		}
		for i := range out {
			clearEnvelope(&out[i])
		}
		out = nil
		if recoverableSession != nil {
			recoverableSession.abort()
		}
		storeCtx, finishCancel := durableStoreContext(local.Ctx(), timeout)
		finishErr := runtime.LifecycleStore.FinishRunLease(storeCtx, lease, tssrun.LeaseAborted)
		finishCancel()
		if finishErr != nil {
			if recoverableSession != nil {
				recoverableSession.closePending = true
				s = recoverableSession
				leaseOwned = false
			}
			err = errors.Join(err, fmt.Errorf("abort uncommitted presign run lease: %w", finishErr))
			return
		}
		s = nil
	}()
	s, out, err = preparePresignStart(key, plan, runtime, lease, timeout, planHash)
	recoverableSession = s
	if s != nil {
		keyOwned = false
	}
	if err != nil {
		return s, out, err
	}
	leaseOwned = false
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
	if err := planvalidation.RequireHash("presign", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if err := requireFigure8Binding(p.EpochID, p.PresignID, s.epochID, s.presignID); err != nil {
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
	tx := &acceptPresignRound1PayloadTx{
		from:     env.From,
		payload:  p,
		verified: verified,
	}
	if err := tx.prepare(s); err != nil {
		tx.cleanupOnReject()
		return nil, err
	}
	return tx, nil
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
	if err := planvalidation.RequireHash("presign", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if err := requireFigure8Binding(p.EpochID, p.PresignID, s.epochID, s.presignID); err != nil {
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
	tx := &acceptPresignRound1ProofTx{
		from:          env.From,
		proof:         p,
		proofEnvelope: env.Clone(),
		verified:      verified,
	}
	if err := tx.prepare(s); err != nil {
		tx.cleanupOnReject()
		return nil, err
	}
	return tx, nil
}

func (s *PresignSession) presignRound1EvidenceFields(from tss.PartyID, p presignRound1Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	publicHash, _ := presignRound1PublicHash(p, s.limits)
	observedPaillierField, err := hashObservedPaillierKeyEvidenceField(p.PaillierPublicKey, s.limits)
	if err != nil {
		observedPaillierField = rawEvidenceField(evidenceFieldObservedPaillierKeyHash, hashBytes(nil))
	}
	fields = append(fields,
		observedPaillierField,
		rawEvidenceField("round1_public_hash", publicHash),
		hashEvidenceField("enc_k_hash", p.EncK),
		hashEvidenceField("enc_gamma_hash", p.EncGamma),
		hashEvidenceField("y_hash", p.Y),
		hashEvidenceField("a1_hash", p.A1),
		hashEvidenceField("a2_hash", p.A2),
		hashEvidenceField("b1_hash", p.B1),
		hashEvidenceField("b2_hash", p.B2),
		rawEvidenceField("epoch_id", p.EpochID),
		rawEvidenceField("presign_id", p.PresignID),
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
	gammaProofBytes, _ := canonicalWireMessageBytes(&proof.EncGammaProof, s.limits)
	return append(fields,
		rawEvidenceField("proof_public_round1_hash", proof.PublicRound1Hash),
		hashEvidenceField("enc_k_proof_hash", proofBytes),
		hashEvidenceField("enc_gamma_proof_hash", gammaProofBytes),
	)
}

func (s *PresignSession) validateRound1Public(from tss.PartyID, p presignRound1Payload) error {
	for _, field := range []struct {
		name  string
		value []byte
	}{{"Y", p.Y}, {"A1", p.A1}, {"A2", p.A2}, {"B1", p.B1}, {"B2", p.B2}} {
		if _, err := secp.PointFromBytes(field.value); err != nil {
			return fmt.Errorf("invalid Figure 8 %s: %w", field.name, err)
		}
	}
	if err := requireFigure8Binding(p.EpochID, p.PresignID, s.epochID, s.presignID); err != nil {
		return err
	}
	expectedPK, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return err
	}
	expectedPKBytes, err := canonicalWireMessageBytes(expectedPK, s.limits)
	if err != nil {
		return err
	}
	observedPKBytes, err := canonicalWireMessageBytes(p.PaillierPublicKey, s.limits)
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
	gammaCiphertext := new(big.Int).SetBytes(p.EncGamma)
	if err := expectedPK.ValidateCiphertext(gammaCiphertext); err != nil {
		return fmt.Errorf("invalid encrypted gamma ciphertext: %w", err)
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
	if err := requireFigure8Binding(proof.EpochID, proof.PresignID, s.epochID, s.presignID); err != nil {
		return err
	}
	proverPK, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.state.Party, s.limits)
	if err != nil {
		return err
	}
	domain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash, s.signers, presignStartRound, from, s.key.state.Party, "enc-elg-k")
	if err != nil {
		return err
	}
	if err := mta.VerifyStartEncElg(s.securityParams, domain, mta.StartMessage{Ciphertext: public.EncK}, public.Y, public.A1, public.A2, proverPK, localRP, &proof.EncKProof); err != nil {
		return err
	}
	gammaDomain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash, s.signers, presignStartRound, from, s.key.state.Party, "enc-elg-gamma")
	if err != nil {
		return err
	}
	return mta.VerifyStartEncElg(s.securityParams, gammaDomain, mta.StartMessage{Ciphertext: public.EncGamma}, public.Y, public.B1, public.B2, proverPK, localRP, &proof.EncGammaProof)
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

func validatePresignRuntime(plan *PresignPlan, runtime PresignRuntime) error {
	local := runtime.Local
	if plan == nil || plan.state == nil {
		return planvalidation.InvalidConfig(local.Self, errors.New("nil presign plan"))
	}
	if runtime.LifecycleStore == nil {
		return planvalidation.InvalidConfig(local.Self, errors.New("PresignRuntime.LifecycleStore is required"))
	}
	if err := runtime.Binding.Validate(); err != nil {
		return planvalidation.InvalidConfig(local.Self, err)
	}
	if local.Self == tss.BroadcastPartyId {
		return planvalidation.InvalidConfig(local.Self, errors.New("PresignRuntime.Local.Self is required"))
	}
	if err := tss.RequireEnvelopeGuard(runtime.Guard, tss.ProtocolCGGMP21Secp256k1, plan.state.sessionID, local.Self, CGGMP21Policies()); err != nil {
		return planvalidation.InvalidConfig(local.Self, err)
	}
	if err := requireLocalEnvelopeSigner(runtime.Guard, local.EnvelopeSigner); err != nil {
		return planvalidation.InvalidConfig(local.Self, err)
	}
	if runtime.Binding.KeyID != plan.state.context.KeyID {
		return planvalidation.InvalidConfig(local.Self, errors.New("presign runtime key id does not match plan context"))
	}

	return nil
}

func (s *PresignSession) prepareRound1ProofEnvelope(peer tss.PartyID, payload presignRound1Payload, publicHash []byte) (tss.Envelope, error) {
	peerRP, err := s.key.ringPedersenPublicFor(peer, s.limits)
	if err != nil {
		return tss.Envelope{}, err
	}
	proofDomain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash, s.signers, presignStartRound, s.key.state.Party, peer, "enc-elg-k")
	if err != nil {
		return tss.Envelope{}, err
	}
	proof, err := s.startOpening.ProveEncElgForVerifier(s.securityParams, s.config.Reader(), proofDomain, payload.Y, payload.A1, payload.A2, s.a, s.paillier.PublicKey, peerRP)
	if err != nil {
		return tss.Envelope{}, err
	}
	gammaDomain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash, s.signers, presignStartRound, s.key.state.Party, peer, "enc-elg-gamma")
	if err != nil {
		return tss.Envelope{}, err
	}
	gammaProof, err := s.gammaOpening.ProveEncElgForVerifier(s.securityParams, s.config.Reader(), gammaDomain, payload.Y, payload.B1, payload.B2, s.b, s.paillier.PublicKey, peerRP)
	if err != nil {
		return tss.Envelope{}, err
	}
	proofPayload, err := (presignRound1ProofPayload{
		PublicRound1Hash: publicHash,
		EncKProof:        *proof,
		EncGammaProof:    *gammaProof,
		PlanHash:         slices.Clone(s.planHash),
		EpochID:          slices.Clone(s.epochID),
		PresignID:        slices.Clone(s.presignID),
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return tss.Envelope{}, err
	}
	proofEnv, err := newEnvelope(s.config, presignStartRound, s.key.state.Party, peer, payloadPresignRound1Proof, proofPayload)
	if err != nil {
		return tss.Envelope{}, err
	}
	return proofEnv, nil
}

func samplePresignRound1Nonces(config tss.ThresholdConfig) (*presignRound1Nonces, error) {
	// Figure 8 round 1 samples k_i, gamma_i and the two ElGamal exponents.
	// Only Paillier ciphertexts and curve commitments leave the process.
	kShare, err := secp.RandomScalar(config.Reader())
	if err != nil {
		return nil, err
	}
	defer kShare.Set(secp.ScalarZero())
	gamma, err := secp.RandomScalar(config.Reader())
	if err != nil {
		return nil, err
	}
	defer gamma.Set(secp.ScalarZero())
	a, err := secp.RandomScalar(config.Reader())
	if err != nil {
		return nil, err
	}
	defer a.Set(secp.ScalarZero())
	b, err := secp.RandomScalar(config.Reader())
	if err != nil {
		return nil, err
	}
	defer b.Set(secp.ScalarZero())
	yExponent, err := secp.RandomScalar(config.Reader())
	if err != nil {
		return nil, err
	}
	defer yExponent.Set(secp.ScalarZero())
	Y := secp.ScalarBaseMult(yExponent)
	A1 := secp.ScalarBaseMult(a)
	A2 := secp.Add(secp.ScalarMult(Y, a), secp.ScalarBaseMult(kShare))
	B1 := secp.ScalarBaseMult(b)
	B2 := secp.Add(secp.ScalarMult(Y, b), secp.ScalarBaseMult(gamma))
	gammaComm, err := secp.PointBytes(secp.ScalarBaseMult(gamma))
	if err != nil {
		return nil, err
	}
	yBytes, err := secp.PointBytes(Y)
	if err != nil {
		return nil, err
	}
	a1Bytes, err := secp.PointBytes(A1)
	if err != nil {
		return nil, err
	}
	a2Bytes, err := secp.PointBytes(A2)
	if err != nil {
		return nil, err
	}
	b1Bytes, err := secp.PointBytes(B1)
	if err != nil {
		return nil, err
	}
	b2Bytes, err := secp.PointBytes(B2)
	if err != nil {
		return nil, err
	}
	nonces, err := retainPresignRound1Nonces(kShare, gamma, a, b)
	if err != nil {
		return nil, err
	}
	nonces.gammaComm = gammaComm
	nonces.public = presignRound1Payload{Y: yBytes, A1: a1Bytes, A2: a2Bytes, B1: b1Bytes, B2: b2Bytes}
	return nonces, nil
}

// retainPresignRound1Nonces converts temporary curve values to fixed-width
// secret handles before they leave the sampling function.
func retainPresignRound1Nonces(kShare, gamma, a, b secp.Scalar) (nonces *presignRound1Nonces, err error) {
	prepared := &presignRound1Nonces{}
	defer func() {
		if err != nil {
			prepared.destroy()
		}
	}()
	prepared.kShare, err = newSecpSecretScalar(kShare.Bytes())
	if err != nil {
		return nil, err
	}
	prepared.gamma, err = newSecpSecretScalar(gamma.Bytes())
	if err != nil {
		return nil, err
	}
	prepared.a, err = secpSecretScalarFromScalar(a)
	if err != nil {
		return nil, err
	}
	prepared.b, err = secpSecretScalarFromScalar(b)
	if err != nil {
		return nil, err
	}
	return prepared, nil
}

// presignRound1Nonces owns the first-round secrets until startup transfers
// them to the session. Its public tuple is the exact Figure 8 first message.
type presignRound1Nonces struct {
	kShare, gamma, a, b *secret.Scalar
	gammaComm           []byte
	public              presignRound1Payload
}

func (n *presignRound1Nonces) destroy() {
	n.kShare.Destroy()
	n.gamma.Destroy()
	n.a.Destroy()
	n.b.Destroy()
}

// preparePresignStart transfers the loaded key only once a session owns the
// prepared material. Even on failure, that session is returned internally so
// StartPresign can retain its lease recovery handle if durable abort fails.
func preparePresignStart(key *KeyShare, plan *PresignPlan, runtime PresignRuntime, lease tssrun.RunLease, timeout time.Duration, planHash []byte) (s *PresignSession, out []tss.Envelope, err error) {
	local := runtime.Local
	limits := plan.limits
	sessionID := plan.state.sessionID
	var recoverableSession *PresignSession
	defer func() {
		if err != nil && recoverableSession != nil {
			s = recoverableSession
		}
	}()
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
		Threshold:      key.state.Threshold,
		Parties:        signers,
		Self:           local.Self,
		SessionID:      sessionID,
		Rand:           local.Rand,
		Context:        local.Context,
		Log:            local.Log,
		EnvelopeSigner: local.EnvelopeSigner,
	}
	nonces, err := samplePresignRound1Nonces(config)
	if err != nil {
		return nil, nil, err
	}
	noncesOwned := true
	defer func() {
		if noncesOwned {
			nonces.destroy()
		}
	}()
	lambda, err := epochLagrangeCoefficient(key.state.Epoch, key.state.Party, signers)
	if err != nil {
		return nil, nil, err
	}
	sec, err := secpScalarFromSecret(key.state.Secret)
	if err != nil {
		return nil, nil, err
	}
	defer sec.Set(secp.ScalarZero())
	// xBar is lambda_i*x_i, the signer-set-adjusted secret share used in
	// chi = k*x. The public commitment is derived from the verification share.
	xBar := secp.ScalarMul(lambda, sec)
	defer xBar.Set(secp.ScalarZero())
	xBarSecret, err := secpSecretScalarFromScalar(xBar)
	if err != nil {
		return nil, nil, err
	}
	xBarOwned := true
	defer func() {
		if xBarOwned {
			xBarSecret.Destroy()
		}
	}()
	localVerificationShare, ok := key.verificationShare(key.state.Party)
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
	// Round 1 publishes K_i/G_i and both ElGamal tuples. Each peer receives
	// verifier-specific Πenc-elg proofs under its independent auxiliary setup.
	startOpening, err := mta.Start(config.Reader(), nonces.kShare, paillierKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	gammaOpening, err := mta.Start(config.Reader(), nonces.gamma, paillierKey.PublicKey)
	if err != nil {
		startOpening.Destroy()
		return nil, nil, err
	}
	openingReturned := false
	defer func() {
		if !openingReturned {
			startOpening.Destroy()
			gammaOpening.Destroy()
		}
	}()
	paillierPub, err := key.paillierPublicFor(key.state.Party, limits)
	if err != nil {
		return nil, nil, err
	}
	presignPayload := presignRound1Payload{
		EncK:              slices.Clone(startOpening.Message.Ciphertext),
		EncGamma:          slices.Clone(gammaOpening.Message.Ciphertext),
		Y:                 nonces.public.Y,
		A1:                nonces.public.A1,
		A2:                nonces.public.A2,
		B1:                nonces.public.B1,
		B2:                nonces.public.B2,
		PaillierPublicKey: paillierPub,
		PlanHash:          slices.Clone(planHash),
		EpochID:           slices.Clone(plan.state.epochID),
		PresignID:         slices.Clone(plan.state.presignID),
	}
	payload, err := presignPayload.MarshalBinaryWithLimits(limits)
	if err != nil {
		return nil, nil, err
	}
	publicHash, err := presignRound1PublicHash(presignPayload, limits)
	if err != nil {
		return nil, nil, err
	}
	env, err := newEnvelope(config, presignStartRound, key.state.Party, tss.BroadcastPartyId, payloadPresignRound1, payload)
	if err != nil {
		return nil, nil, err
	}
	parties, partyIndex := newPresignPartyStates(signers)
	selfState := &parties[partyIndex[key.state.Party]]
	selfState.round1.payload = presignPayload
	selfState.round1.havePayload = true
	selfState.round1.verified = true
	s = &PresignSession{
		key:              key,
		ownsKey:          true,
		sessionID:        sessionID,
		config:           config,
		log:              config.Logger(),
		limits:           limits,
		securityParams:   plan.securityParams,
		signers:          signers,
		context:          ctx,
		contextHash:      contextHash,
		presignID:        slices.Clone(plan.state.presignID),
		epochID:          slices.Clone(plan.state.epochID),
		derivation:       derivation,
		planHash:         slices.Clone(planHash),
		paillier:         paillierKey,
		kShare:           nonces.kShare,
		gamma:            nonces.gamma,
		a:                nonces.a,
		b:                nonces.b,
		xBar:             xBarSecret,
		gammaComm:        nonces.gammaComm,
		xBarComm:         xBarComm,
		partyIndex:       partyIndex,
		parties:          parties,
		startOpening:     startOpening,
		gammaOpening:     gammaOpening,
		guard:            runtime.Guard,
		lifecycleStore:   runtime.LifecycleStore,
		lifecycleLease:   lease,
		lifecycleTimeout: timeout,
	}
	recoverableSession = s
	derivationOwned = true
	paillierOwned = true
	openingReturned = true
	prepared := &preparedPresignStart{session: s}
	defer prepared.destroy()
	noncesOwned = false
	xBarOwned = false

	out, err = s.prepareInitialPresignEnvelopes(prepared, env, presignPayload, publicHash)
	if err != nil {
		return nil, nil, err
	}
	prepared.markCommitted()
	return s, out, nil
}

func (s *PresignSession) prepareInitialPresignEnvelopes(prepared *preparedPresignStart, env tss.Envelope, presignPayload presignRound1Payload, publicHash []byte) ([]tss.Envelope, error) {
	out := []tss.Envelope{env}
	prepared.out = out
	for _, peer := range s.signers {
		if peer == s.key.state.Party {
			continue
		}
		proofEnv, err := s.prepareRound1ProofEnvelope(peer, presignPayload, publicHash)
		if err != nil {
			return nil, err
		}
		out = append(out, proofEnv)
		prepared.out = out
	}
	round2, err := s.tryEmitRound2()
	if err != nil {
		return nil, err
	}
	out = append(out, round2...)
	prepared.out = out
	round3, err := s.tryEmitRound3()
	if err != nil {
		return nil, err
	}
	out = append(out, round3...)
	prepared.out = out
	return out, nil
}
