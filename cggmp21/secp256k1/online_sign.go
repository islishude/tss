package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire/wireutil"
)

// StartSign starts or idempotently resumes online signing from a shared
// immutable lifecycle plan using a context-bound presignature.
func StartSign(key *KeyShare, presign *Presign, plan *SignPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	if key == nil || key.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil key share"))
	}
	if presign == nil || presign.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil presign"))
	}
	if local.Self == 0 {
		local.Self = key.state.party
	}
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil sign plan"))
	}
	if err := tss.RequireEnvelopeGuard(guard, protocol, plan.state.sessionID, local.Self); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := key.ValidateWithLimits(plan.limits); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := plan.validate(key, presign, local); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	request := cloneSignRequest(plan.state.request)
	return startSignDigestBoundWithTimeout(local.Ctx(), key, presign, plan.state.sessionID, plan.state.digest, plan.state.contextHash, planHash, request.LowS, request.AttemptStore, guard, durableStoreTimeout(request.DurableStoreTimeout), plan.limits)
}

func startSignDigestBound(ctx context.Context, key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32, contextHash []byte, lowS bool, store SignAttemptStore, guard *tss.EnvelopeGuard, limits Limits) (*SignSession, []tss.Envelope, error) {
	var planHash []byte
	if presign != nil && presign.state != nil {
		planHash = presign.state.planHash
	}
	return startSignDigestBoundWithTimeout(ctx, key, presign, sessionID, digest32, contextHash, planHash, lowS, store, guard, DefaultSignAttemptStoreTimeout, limits)
}

func startSignDigestBoundWithTimeout(ctx context.Context, key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32, contextHash, planHash []byte, lowS bool, store SignAttemptStore, guard *tss.EnvelopeGuard, storeTTL time.Duration, limits Limits) (*SignSession, []tss.Envelope, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil context")
	}
	if key == nil || key.state == nil {
		return nil, nil, errors.New("nil key share")
	}
	if presign == nil || presign.state == nil {
		return nil, nil, errors.New("nil presign")
	}
	if err := tss.RequireEnvelopeGuard(guard, protocol, sessionID, key.state.party); err != nil {
		return nil, nil, err
	}
	if err := key.requireMPCMaterial(limits); err != nil {
		return nil, nil, err
	}
	if err := validatePresign(key, presign, limits); err != nil {
		return nil, nil, err
	}
	if err := presign.VerifySignMaterialWithLimits(limits); err != nil {
		return nil, nil, err
	}
	if len(digest32) != 32 {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	if len(contextHash) != sha256.Size || !bytes.Equal(contextHash, presign.state.contextHash) {
		return nil, nil, errors.New("presign context mismatch")
	}
	if len(planHash) != sha256.Size {
		return nil, nil, errors.New("sign plan hash must be 32 bytes")
	}
	if store == nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 1, key.state.party, errors.New("SignRequest.AttemptStore is required for durable sign-attempt commit"))
	}

	candidate, err := buildSignAttemptRecord(key, presign, sessionID, digest32, contextHash, planHash, lowS, guard, limits)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	if !bindPresignToAttempt(presign, candidate.IntentHash, false) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.party, errors.New("presign already consumed or bound to another attempt"))
	}
	commitCtx, cancel := durableStoreContext(ctx, storeTTL)
	defer cancel()
	commit, err := store.CommitSignAttempt(commitCtx, candidate)
	if err != nil {
		if signAttemptConsumedError(err) {
			return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.party, err)
		}
		return nil, nil, fmt.Errorf("%w: %w", ErrSignAttemptOutcomeUnknown, err)
	}
	if commit.Status != SignAttemptCreated && commit.Status != SignAttemptExistingSame {
		return nil, nil, fmt.Errorf("%w: invalid commit status", ErrSignAttemptCorrupt)
	}
	return resumeMatchingSignAttempt(ctx, key, presign, candidate, commit.Record, store, guard, storeTTL, limits)
}

func durableStoreTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultSignAttemptStoreTimeout
	}
	return timeout
}

func durableStoreContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), durableStoreTimeout(timeout))
}

func signAttemptConsumedError(err error) bool {
	return errors.Is(err, ErrSignAttemptConflict) ||
		errors.Is(err, ErrSignAttemptBurned) ||
		errors.Is(err, ErrSignAttemptNonDeterminism)
}

func buildSignAttemptRecord(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32, contextHash, planHash []byte, lowS bool, guard *tss.EnvelopeGuard, limits Limits) (SignAttemptRecord, error) {
	kShare, err := secpScalarFromSecret(presign.state.kShare)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	chiShare, err := secpScalarFromSecret(presign.state.chiShare)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	littleR, err := secp.ScalarFromBytes(presign.state.littleR)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	z := new(big.Int).SetBytes(digest32)
	// Online ECDSA partial: s_i = m*k_i + r*chi_i mod q.
	partial := new(big.Int).Mul(z, kShare.BigInt())
	rs := new(big.Int).Mul(littleR.BigInt(), chiShare.BigInt())
	partial.Add(partial, rs)
	partial.Mod(partial, secp.Order())
	localVS, ok := presignVerifyShare(presign, key.state.party)
	if !ok {
		return SignAttemptRecord{}, fmt.Errorf("missing local verify share for party %d: presign may be corrupted", key.state.party)
	}
	payload := signPartialPayload{
		S:                 partial,
		PresignTranscript: slices.Clone(presign.state.transcriptHash),
		PresignContext:    slices.Clone(contextHash),
		DigestHash:        digestHash(digest32, contextHash),
		PlanHash:          slices.Clone(planHash),
		PartialEquationHash: partialEquationHash(
			sessionID, key.state.party, presign.state.transcriptHash,
			contextHash, planHash, digest32,
			littleR.Bytes(), scalarBytes(partial),
			localVS.KPoint, localVS.ChiPoint,
		),
	}
	payloadBytes, err := marshalSignPartialPayloadWithLimits(payload, limits)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        key.state.party,
		PayloadType: payloadSignPartial,
		Payload:     payloadBytes,
	})
	if err != nil {
		return SignAttemptRecord{}, err
	}
	envelopeBytes, err := env.MarshalBinary()
	if err != nil {
		return SignAttemptRecord{}, err
	}
	envelopeHash := sha256.Sum256(envelopeBytes)
	payloadHash := tss.PayloadHashFromEnvelope(env)
	envelopeDigest := env.Digest()
	digestBindingHash := digestHash(digest32, contextHash)
	policy, err := CGGMP21Policies().Match(protocol, env.Round, env.PayloadType)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	record := SignAttemptRecord{
		RecordVersion:              signAttemptRecordVersion,
		Protocol:                   protocol,
		Version:                    tss.Version,
		PresignID:                  presign.ID(),
		SessionID:                  sessionID,
		Party:                      key.state.party,
		SignerSetHash:              signAttemptSignerSetHash(presign.state.signers),
		SignPlanHash:               slices.Clone(planHash),
		ContextHash:                slices.Clone(contextHash),
		Digest:                     slices.Clone(digest32),
		DigestBindingHash:          digestBindingHash,
		LowS:                       lowS,
		CanonicalBaseEnvelopeBytes: envelopeBytes,
		CanonicalBaseEnvelopeHash:  envelopeHash[:],
		EnvelopeDigest:             envelopeDigest[:],
		PayloadHash:                payloadHash[:],
		DeliveryPolicy: SignAttemptDeliveryPolicy{
			Mode:                 policy.Mode,
			Confidentiality:      policy.Confidentiality,
			BroadcastConsistency: policy.BroadcastConsistency,
			Recipients:           slices.Clone(presign.state.signers),
		},
	}
	record.IntentHash = signAttemptIntentHash(record)
	record.AttemptHash = signAttemptHash(record)
	if err := validateSignAttemptRecordWithLimits(record, limits); err != nil {
		return SignAttemptRecord{}, err
	}
	validationSession, _, err := signSessionFromAttempt(context.Background(), key, presign, record, nil, guard, DefaultSignAttemptStoreTimeout, limits)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("local sign partial self-verification failed: %w", err)
	}
	validationSession.Destroy()
	return record, nil
}

// ResumeSign loads and resumes the only durable attempt bound to presign.
func ResumeSign(ctx context.Context, key *KeyShare, presign *Presign, store SignAttemptStore, guard *tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	return ResumeSignWithLimits(ctx, key, presign, store, guard, DefaultLimits())
}

// ResumeSignWithLimits resumes a durable sign attempt using explicit local
// validation and decoding limits.
func ResumeSignWithLimits(ctx context.Context, key *KeyShare, presign *Presign, store SignAttemptStore, guard *tss.EnvelopeGuard, limits Limits) (*SignSession, []tss.Envelope, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil context")
	}
	if key == nil || key.state == nil {
		return nil, nil, errors.New("nil key share")
	}
	if presign == nil || presign.state == nil {
		return nil, nil, errors.New("nil presign")
	}
	if store == nil {
		return nil, nil, errors.New("nil sign attempt store")
	}
	if err := key.requireMPCMaterial(limits); err != nil {
		return nil, nil, err
	}
	if err := validatePresign(key, presign, limits); err != nil {
		return nil, nil, err
	}
	record, err := store.LoadSignAttempt(ctx, presign.ID())
	if err != nil {
		if errors.Is(err, ErrSignAttemptCorrupt) {
			_ = MarkPresignConsumed(presign)
		}
		return nil, nil, err
	}
	if err := validateSignAttemptRecordWithLimits(record, limits); err != nil {
		_ = MarkPresignConsumed(presign)
		return nil, nil, err
	}
	if err := tss.RequireEnvelopeGuard(guard, protocol, record.SessionID, key.state.party); err != nil {
		return nil, nil, err
	}
	if !bindPresignToAttempt(presign, record.IntentHash, true) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.party, errors.New("presign is bound to another attempt or was manually discarded"))
	}
	return signSessionFromAttempt(ctx, key, presign, record, store, guard, DefaultSignAttemptStoreTimeout, limits)
}

func resumeMatchingSignAttempt(ctx context.Context, key *KeyShare, presign *Presign, candidate, durable SignAttemptRecord, store SignAttemptStore, guard *tss.EnvelopeGuard, storeTTL time.Duration, limits Limits) (*SignSession, []tss.Envelope, error) {
	if err := validateSignAttemptRecordWithLimits(durable, limits); err != nil {
		_ = MarkPresignConsumed(presign)
		return nil, nil, err
	}
	if !candidate.SameAttempt(durable) {
		if !bindPresignToAttempt(presign, durable.IntentHash, true) {
			_ = MarkPresignConsumed(presign)
		}
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.party, ErrSignAttemptConflict)
	}
	if !bindPresignToAttempt(presign, durable.IntentHash, true) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.party, errors.New("presign is bound to another attempt or was manually discarded"))
	}
	return signSessionFromAttempt(ctx, key, presign, durable, store, guard, storeTTL, limits)
}

func signSessionFromAttempt(ctx context.Context, key *KeyShare, presign *Presign, record SignAttemptRecord, store SignAttemptStore, guard *tss.EnvelopeGuard, storeTTL time.Duration, limits Limits) (*SignSession, []tss.Envelope, error) {
	if err := validateSignAttemptBindings(key, presign, record, limits); err != nil {
		return nil, nil, err
	}
	env, err := decodeSignAttemptEnvelopeWithLimits(record.CanonicalBaseEnvelopeBytes, limits)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	payload, err := unmarshalSignPartialPayloadWithLimits(env.Payload, limits)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	verifyKey := append([]byte(nil), key.state.publicKey...)
	if len(presign.state.additiveShift) > 0 {
		verifyKey, err = DerivePublicKey(key.state.publicKey, presign.state.additiveShift)
		if err != nil {
			return nil, nil, err
		}
	}
	s := &SignSession{
		key:       key,
		presign:   presign,
		sessionID: record.SessionID,
		log:       tss.NopLogger(),
		limits:    limits,
		digest:    slices.Clone(record.Digest),
		lowS:      record.LowS,
		planHash:  slices.Clone(record.SignPlanHash),
		publicKey: verifyKey,
		partials:  make(map[tss.PartyID]*big.Int),
		guard:     guard,
		attempt:   record.Clone(),
		store:     store,
		storeCtx:  context.WithoutCancel(ctx),
		storeTTL:  durableStoreTimeout(storeTTL),
	}
	partial, err := s.verifySignPartial(key.state.party, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: local sign partial verification failed: %w", ErrSignAttemptCorrupt, err)
	}
	s.partials[key.state.party] = partial
	if record.Completed {
		sig := &Signature{R: slices.Clone(record.SignatureR), S: slices.Clone(record.SignatureS)}
		if !VerifyDigest(verifyKey, record.Digest, sig) {
			return nil, nil, fmt.Errorf("%w: stored signature verification failed", ErrSignAttemptCorrupt)
		}
		s.signature = sig
		s.completed = true
		if record.DeliveryState.DeliveryComplete {
			return s, nil, nil
		}
		return s, []tss.Envelope{env}, nil
	}
	if store != nil {
		if err := s.tryCompleteSign(s.storeCtx); err != nil {
			return nil, nil, err
		}
		if s.completed {
			if s.attempt.DeliveryState.DeliveryComplete {
				return s, nil, nil
			}
			return s, []tss.Envelope{env}, nil
		}
	}
	if record.DeliveryState.DeliveryComplete {
		return s, nil, nil
	}
	return s, []tss.Envelope{env}, nil
}

func validateSignAttemptBindings(key *KeyShare, presign *Presign, record SignAttemptRecord, limits Limits) error {
	if err := validateSignAttemptRecordWithLimits(record, limits); err != nil {
		return err
	}
	if !bytes.Equal(record.PresignID, presign.ID()) ||
		record.Party != key.state.party ||
		!bytes.Equal(record.SignerSetHash, signAttemptSignerSetHash(presign.state.signers)) ||
		!bytes.Equal(record.ContextHash, presign.state.contextHash) {
		return fmt.Errorf("%w: key or presign binding mismatch", ErrSignAttemptCorrupt)
	}
	return nil
}

// BurnPresign durably burns a presign that must never be used for signing.
func BurnPresign(ctx context.Context, store SignAttemptStore, presign *Presign, reason string) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if store == nil {
		return errors.New("nil sign attempt store")
	}
	if presign == nil || presign.state == nil {
		return errors.New("nil presign")
	}
	if err := store.BurnPresign(ctx, SignAttemptBurn{PresignID: presign.ID(), Reason: reason}); err != nil {
		return err
	}
	return MarkPresignConsumed(presign)
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *SignSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// UpdateDelivery records durable outbox delivery progress for this attempt.
func (s *SignSession) UpdateDelivery(ctx context.Context, ack *tss.BroadcastAck, certificate *tss.BroadcastCertificate) error {
	if s == nil {
		return errors.New("nil sign session")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		return errors.New("sign attempt store unavailable during delivery update")
	}
	storeCtx, cancel := durableStoreContext(ctx, s.storeTTL)
	defer cancel()
	updated, err := s.store.UpdateSignAttemptDelivery(storeCtx, SignAttemptDeliveryUpdate{
		PresignID:   slices.Clone(s.attempt.PresignID),
		AttemptHash: slices.Clone(s.attempt.AttemptHash),
		Ack:         ack,
		Certificate: certificate,
	})
	if err != nil {
		return err
	}
	if !s.attempt.SameAttempt(updated) {
		return fmt.Errorf("%w: delivery update changed attempt identity", ErrSignAttemptCorrupt)
	}
	s.attempt = updated.Clone()
	return nil
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *SignSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.sessionID, tss.PartySet(s.presign.state.signers), s.key.state.party)
}

// HandleSignMessage validates and applies one online signing envelope.
//
// Follows the handler template (see doc.go).
func (s *SignSession) HandleSignMessage(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
	base := env.Envelope()
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(base.Round, base.From)
	}
	if s.aborted {
		return nil, abortedSessionError(base.Round, base.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	if !tss.ContainsParty(s.presign.state.signers, base.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("sender is not in signer set"))
	}

	// ---- 1 & 2. PARSE + POLICY VALIDATE ----
	if base.Round != 1 || base.PayloadType != payloadSignPartial {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("expected round 1 sign partial"))
	}
	if _, ok := s.partials[base.From]; ok {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, errors.New("duplicate sign partial"))
	}
	payload := base.Payload
	p, err := unmarshalSignPartialPayloadWithLimits(payload, s.limits)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			base,
			tss.EvidenceKindSignPartial,
			"malformed sign partial payload",
			[]tss.PartyID{base.From},
			err,
			s.signPartialContextEvidenceFields(payload)...,
		)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	partial, err := s.verifySignPartial(base.From, p)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeVerification,
			base,
			tss.EvidenceKindSignPartial,
			"sign partial verification failed",
			[]tss.PartyID{base.From},
			err,
			s.signPartialEvidenceFields(base.From, p)...,
		)
	}

	// ---- 4. MUTATE STATE ----
	s.partials[base.From] = partial

	// ---- 5. EMIT ----
	return nil, s.tryCompleteSign(s.storeCtx)
}

// Signature returns the completed ECDSA signature.
func (s *SignSession) Signature() (*Signature, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return &Signature{R: append([]byte(nil), s.signature.R...), S: append([]byte(nil), s.signature.S...)}, true
}

func (s *SignSession) signPartialEvidenceFields(from tss.PartyID, p signPartialPayload) []tss.EvidenceField {
	fields := s.signPartialContextEvidenceFields(nil)
	fields = append(fields,
		hashEvidenceField("observed_presign_transcript_hash", p.PresignTranscript),
		hashEvidenceField("observed_presign_context_hash", p.PresignContext),
		hashEvidenceField("sign_partial_hash", scalarBytes(p.S)),
	)
	// Include the sender's (blamed party's) KPoint/ChiPoint hashes.
	if vs, ok := presignVerifyShare(s.presign, from); ok {
		fields = append(fields,
			hashEvidenceField(evidenceFieldSignVerifyKPointHash, vs.KPoint),
			hashEvidenceField(evidenceFieldSignVerifyChiPointHash, vs.ChiPoint),
		)
		// Compute the expected equation hash for independent auditability.
		expectedEqHash := partialEquationHash(
			s.sessionID, from, s.presign.state.transcriptHash,
			s.presign.state.contextHash, s.planHash, s.digest,
			s.presign.state.littleR, scalarBytes(p.S),
			vs.KPoint, vs.ChiPoint,
		)
		fields = append(fields,
			rawEvidenceField(evidenceFieldPartialEquationHash, expectedEqHash),
			rawEvidenceField(evidenceFieldObservedPartialEquationHash, p.PartialEquationHash),
		)
	}
	return fields
}

func (s *SignSession) signPartialContextEvidenceFields(rawPayload []byte) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.state.signers)...)
	fields = append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.presign.state.transcriptHash),
		rawEvidenceField("presign_context_hash", s.presign.state.contextHash),
		hashEvidenceField(evidenceFieldDigestHash, s.digest),
	)
	if rawPayload != nil {
		fields = append(fields, hashEvidenceField("sign_partial_payload_hash", rawPayload))
	}
	return fields
}

// RetryCompletion retries durable persistence of a signature after all partials
// have been collected. Signature remains unavailable until persistence succeeds.
func (s *SignSession) RetryCompletion(ctx context.Context) error {
	if s == nil {
		return errors.New("nil sign session")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tryCompleteSign(ctx)
}

func (s *SignSession) tryCompleteSign(ctx context.Context) error {
	if s.completed || len(s.partials) != len(s.presign.state.signers) {
		return nil
	}
	sigS := new(big.Int)
	for _, id := range s.presign.state.signers {
		sigS.Add(sigS, s.partials[id])
		sigS.Mod(sigS, secp.Order())
	}
	if sigS.Sign() == 0 {
		return errors.New("zero ECDSA s")
	}
	if s.lowS && sigS.Cmp(new(big.Int).Rsh(new(big.Int).Set(secp.Order()), 1)) > 0 {
		sigS.Sub(secp.Order(), sigS)
	}
	r, err := secp.ScalarFromBytes(s.presign.state.littleR)
	if err != nil {
		return err
	}
	public, err := secp.PointFromBytes(s.publicKey)
	if err != nil {
		return err
	}
	if !secp.VerifyECDSA(public, s.digest, r, secp.ScalarFromBigInt(sigS)) {
		return &tss.ProtocolError{
			Code:  tss.ErrCodeInvariant,
			Round: 1,
			Err:   errors.New("all partials individually verified but aggregate ECDSA signature verification failed"),
		}
	}
	if s.store == nil {
		return errors.New("sign attempt store unavailable during completion")
	}
	signature := Signature{R: r.Bytes(), S: secp.ScalarFromBigInt(sigS).Bytes()}
	storeCtx, cancel := durableStoreContext(ctx, s.storeTTL)
	defer cancel()
	completed, err := s.store.CompleteSignAttempt(storeCtx, SignAttemptResult{
		PresignID:   slices.Clone(s.attempt.PresignID),
		AttemptHash: slices.Clone(s.attempt.AttemptHash),
		Signature:   signature,
	})
	if err != nil {
		return fmt.Errorf("persist sign attempt completion: %w", err)
	}
	if !s.attempt.SameAttempt(completed) || !completed.Completed ||
		!bytes.Equal(completed.SignatureR, signature.R) ||
		!bytes.Equal(completed.SignatureS, signature.S) {
		return fmt.Errorf("%w: completion record mismatch", ErrSignAttemptCorrupt)
	}
	if err := validateSignAttemptRecordWithLimits(completed, s.limits); err != nil {
		return err
	}
	s.attempt = completed.Clone()
	s.signature = &Signature{R: slices.Clone(signature.R), S: slices.Clone(signature.S)}
	s.completed = true
	s.log.Info(context.Background(), "signing complete",
		"party_id", s.key.state.party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	return nil
}

// VerifyDigest verifies a secp256k1 ECDSA signature over a 32-byte digest.
func VerifyDigest(publicKey, digest32 []byte, sig *Signature) bool {
	public, err := secp.PointFromBytes(publicKey)
	if err != nil {
		return false
	}
	if sig == nil {
		return false
	}
	r, err := secp.ScalarFromBytes(sig.R)
	if err != nil {
		return false
	}
	s, err := secp.ScalarFromBytes(sig.S)
	if err != nil {
		return false
	}
	return secp.VerifyECDSA(public, digest32, r, s)
}

// VerifySignature verifies a context-bound secp256k1 ECDSA signature.
func VerifySignature(publicKey []byte, request SignRequest, sig *Signature) bool {
	if err := validatePresignContext(request.Context); err != nil {
		return false
	}
	contextHash := presignContextHash(request.Context)
	digest := signMessageDigest(contextHash, request.Context.MessageDomain, request.Message)
	return VerifyDigest(publicKey, digest, sig)
}

func validatePresign(key *KeyShare, presign *Presign, limits Limits) error {
	if err := presign.ValidateWithLimits(limits); err != nil {
		return err
	}
	if presign.state.party != key.state.party {
		return errors.New("presign party mismatch")
	}
	if presign.state.threshold != key.state.threshold {
		return errors.New("presign threshold mismatch")
	}
	if !bytes.Equal(presign.state.publicKey, key.state.publicKey) {
		return errors.New("presign public key binding mismatch")
	}
	if !bytes.Equal(presign.state.keygenTranscriptHash, key.state.keygenTranscriptHash) {
		return errors.New("presign keygen transcript binding mismatch")
	}
	if !bytes.Equal(presign.state.partiesHash, wireutil.PartySetHash(key.state.parties, partySetHashLabel)) {
		return errors.New("presign participant set binding mismatch")
	}
	if len(presign.state.signers) < key.state.threshold || !tss.ContainsParty(presign.state.signers, key.state.party) {
		return errors.New("invalid presign signer set")
	}
	return nil
}

func validateSignerSet(key *KeyShare, signers []tss.PartyID, limits Limits) error {
	return tss.ValidateSignerSet(key.state.parties, key.state.threshold, signers, limits.ThresholdLimits())
}

func (s *SignSession) verifySignPartial(from tss.PartyID, p signPartialPayload) (*big.Int, error) {
	if !tss.ContainsParty(s.presign.state.signers, from) {
		return nil, errors.New("sender is not in signer set")
	}
	if !bytes.Equal(p.PresignTranscript, s.presign.state.transcriptHash) {
		return nil, errors.New("presign transcript mismatch")
	}
	if !bytes.Equal(p.PresignContext, s.presign.state.contextHash) {
		return nil, errors.New("presign context mismatch")
	}
	if err := requirePlanHash("sign", p.PlanHash, s.planHash); err != nil {
		return nil, err
	}
	expectedDigestHash := digestHash(s.digest, s.presign.state.contextHash)
	if !bytes.Equal(p.DigestHash, expectedDigestHash) {
		return nil, errors.New("digest hash mismatch")
	}
	sVal := secp.ScalarFromBigInt(p.S)
	vs, ok := presignVerifyShare(s.presign, from)
	if !ok {
		return nil, fmt.Errorf("missing verify share for party %d", from)
	}
	kPoint, err := secp.PointFromBytes(vs.KPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid KPoint for party %d: %w", from, err)
	}
	chiPoint, err := secp.PointFromBytes(vs.ChiPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid ChiPoint for party %d: %w", from, err)
	}
	littleR, err := secp.ScalarFromBytes(s.presign.state.littleR)
	if err != nil {
		return nil, err
	}
	expectedEqHash := partialEquationHash(
		s.sessionID, from, s.presign.state.transcriptHash,
		s.presign.state.contextHash, s.planHash, s.digest,
		littleR.Bytes(), scalarBytes(p.S),
		vs.KPoint, vs.ChiPoint,
	)
	if !bytes.Equal(p.PartialEquationHash, expectedEqHash) {
		return nil, errors.New("partial equation hash mismatch")
	}
	z := new(big.Int).SetBytes(s.digest)
	zScalar, err := secp.ScalarFromBytes(scalarBytes(z))
	if err != nil {
		return nil, err
	}
	lhs := secp.ScalarBaseMult(sVal)
	term1 := secp.ScalarMult(kPoint, zScalar)
	term2 := secp.ScalarMult(chiPoint, littleR)
	rhs := secp.Add(term1, term2)
	if !secp.Equal(lhs, rhs) {
		return nil, errors.New("sign partial equation verification failed")
	}
	return sVal.BigInt(), nil
}

func digestHash(digest32, contextHash []byte) []byte {
	t := transcript.New("cggmp21-secp256k1-sign-digest-binding")
	t.AppendBytes("context_hash", contextHash)
	t.AppendBytes("digest", digest32)
	return t.Sum()
}

const signPartialEquationDomain = "cggmp21-secp256k1-sign-partial-equation"

func partialEquationHash(sessionID tss.SessionID, party tss.PartyID, presignTranscriptHash, contextHash, planHash, digestHash, littleR, s, kPoint, chiPoint []byte) []byte {
	t := transcript.New(signPartialEquationDomain)
	t.AppendBytes("session_id", sessionID[:])
	t.AppendUint32("party", party)
	t.AppendBytes("presign_transcript_hash", presignTranscriptHash)
	t.AppendBytes("context_hash", contextHash)
	t.AppendBytes("plan_hash", planHash)
	t.AppendBytes("digest_hash", digestHash)
	t.AppendBytes("little_r", littleR)
	t.AppendBytes("s", s)
	t.AppendBytes("k_point", kPoint)
	t.AppendBytes("chi_point", chiPoint)
	return t.Sum()
}

func presignVerifyShare(presign *Presign, party tss.PartyID) (SignVerifyShare, bool) {
	for _, vs := range presign.state.verifyShares {
		if vs.Party == party {
			return vs, true
		}
	}
	return SignVerifyShare{}, false
}
