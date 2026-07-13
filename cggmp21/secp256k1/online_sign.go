package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
)

// StartSign starts or idempotently resumes this party's local online signing
// attempt from a shared immutable lifecycle plan using local runtime
// dependencies. The session ID identifies the signing attempt, not the earlier
// presign run. The runtime Presign is consumed through the SignAttemptStore
// boundary before outbound messages are released. If the commit outcome is
// unknown, the application must not reuse the presign with another session or
// digest; recover the same attempt with ResumeSign.
func StartSign(key *KeyShare, plan *SignPlan, runtime SignRuntime) (*SignSession, []tss.Envelope, error) {
	local := runtime.Local
	presign := runtime.Presign
	if key == nil || key.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil key share"))
	}
	if presign == nil || presign.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil presign"))
	}
	if local.Self == tss.BroadcastPartyId {
		local.Self = key.state.Party
	}
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil sign plan"))
	}
	if err := tss.RequireEnvelopeGuard(runtime.Guard, tss.ProtocolCGGMP21Secp256k1, plan.state.sessionID, local.Self); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if runtime.AttemptStore == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("SignRuntime.AttemptStore is required for durable sign-attempt commit"))
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
	return startSignDigestBoundWithTimeout(
		local.Ctx(),
		key,
		presign,
		plan.state.sessionID,
		plan.state.digest,
		plan.state.contextHash,
		planHash,
		runtime.AttemptStore,
		runtime.Guard, durableStoreTimeout(runtime.DurableStoreTimeout),
		plan.limits,
	)
}

func startSignDigestBoundWithTimeout(ctx context.Context, key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32, contextHash, planHash []byte, store SignAttemptStore, guard *tss.EnvelopeGuard, storeTTL time.Duration, limits Limits) (*SignSession, []tss.Envelope, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil context")
	}
	if key == nil || key.state == nil {
		return nil, nil, errors.New("nil key share")
	}
	if presign == nil || presign.state == nil {
		return nil, nil, errors.New("nil presign")
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, sessionID, key.state.Party); err != nil {
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
	if len(digest32) != sha256.Size {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	if len(contextHash) != sha256.Size || !bytes.Equal(contextHash, presign.state.ContextHash) {
		return nil, nil, errors.New("presign context mismatch")
	}
	if len(planHash) != sha256.Size {
		return nil, nil, errors.New("sign plan hash must be 32 bytes")
	}
	if store == nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 1, key.state.Party, errors.New("SignRuntime.AttemptStore is required for durable sign-attempt commit"))
	}
	handle, err := newPresignHandle(presign, limits)
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := newSignAttemptCoordinator(store, handle, storeTTL, limits)
	if err != nil {
		return nil, nil, err
	}

	// Build and locally verify the exact outbound partial before touching the
	// durable store. A malformed candidate must not consume the presign.
	candidate, err := buildSignAttemptRecord(ctx, key, presign, sessionID, digest32, contextHash, planHash, guard, limits)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	// The in-memory binding prevents concurrent goroutines in this process from
	// racing multiple intents into the durable store for the same presign.
	if !bindPresignToAttempt(presign, candidate.IntentHash, false) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.Party, errors.New("presign already consumed or bound to another attempt"))
	}
	// CommitSignAttempt is the cross-process linearization point. After this
	// call returns or its outcome is unknown, the presign is treated as consumed.
	commit, err := coordinator.claim(ctx, candidate)
	if err != nil {
		if signAttemptConsumedError(err) {
			return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.Party, err)
		}
		return nil, nil, err
	}
	return resumeMatchingSignAttempt(ctx, key, presign, candidate, commit.Record, coordinator, guard, limits)
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

func buildSignAttemptRecord(ctx context.Context, key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32, contextHash, planHash []byte, guard *tss.EnvelopeGuard, limits Limits) (SignAttemptRecord, error) {
	kShare, err := secpScalarFromSecret(presign.state.KShare)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	chiShare, err := secpScalarFromSecret(presign.state.ChiShare)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	littleR := presign.state.LittleR
	zScalar, err := secp.ScalarFromBytesModOrder(digest32)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	// Online ECDSA partial: s_i = m*k_i + r*chi_i mod q.
	partial := secp.ScalarAdd(
		secp.ScalarMul(zScalar, kShare),
		secp.ScalarMul(littleR, chiShare),
	)
	partialWire, err := secpSecretScalarFromScalarAllowZero(partial)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	defer partialWire.Destroy()
	localVS, ok := presignVerifyShare(presign, key.state.Party)
	if !ok {
		return SignAttemptRecord{}, fmt.Errorf("missing local verify share for party %d: presign may be corrupted", key.state.Party)
	}
	kPointBytes, err := localVS.kPointBytes()
	if err != nil {
		return SignAttemptRecord{}, err
	}
	chiPointBytes, err := localVS.chiPointBytes()
	if err != nil {
		return SignAttemptRecord{}, err
	}
	partialBytes := partial.Bytes()
	defer clear(partialBytes)
	payload := signPartialPayload{
		S:                 partialWire,
		PresignTranscript: slices.Clone(presign.state.TranscriptHash),
		PresignContext:    slices.Clone(contextHash),
		DigestHash:        digestHash(digest32, contextHash),
		PlanHash:          slices.Clone(planHash),
		PartialEquationHash: partialEquationHash(
			sessionID, key.state.Party, presign.state.TranscriptHash,
			contextHash, planHash, digest32,
			littleR.Bytes(), partialBytes,
			kPointBytes, chiPointBytes,
		),
	}
	payloadBytes, err := payload.MarshalBinaryWithLimits(limits)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       signStartRound,
		From:        key.state.Party,
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
	policy, err := CGGMP21Policies().Match(tss.ProtocolCGGMP21Secp256k1, env.Round, env.PayloadType)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	contentID, err := presign.contentIDWithLimits(limits)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	record := SignAttemptRecord{
		RecordVersion:              signAttemptRecordVersion,
		Protocol:                   tss.ProtocolCGGMP21Secp256k1,
		ProtocolVersion:            tss.ProtocolVersion,
		PresignContentID:           contentID,
		SessionID:                  sessionID,
		Party:                      key.state.Party,
		SignerSetHash:              signAttemptSignerSetHash(presign.state.Signers),
		SignPlanHash:               slices.Clone(planHash),
		ContextHash:                slices.Clone(contextHash),
		Digest:                     slices.Clone(digest32),
		DigestBindingHash:          digestBindingHash,
		CanonicalBaseEnvelopeBytes: envelopeBytes,
		CanonicalBaseEnvelopeHash:  envelopeHash[:],
		EnvelopeDigest:             envelopeDigest[:],
		PayloadHash:                payloadHash[:],
		DeliveryPolicy: SignAttemptDeliveryPolicy{
			Mode:                 policy.Mode,
			Confidentiality:      policy.Confidentiality,
			BroadcastConsistency: policy.BroadcastConsistency,
			Recipients:           slices.Clone(presign.state.Signers),
		},
	}
	record.IntentHash = signAttemptIntentHash(record)
	record.AttemptHash = signAttemptHash(record)
	if err := validateSignAttemptRecordWithLimits(record, limits); err != nil {
		return SignAttemptRecord{}, err
	}
	validationSession, _, err := signSessionFromAttempt(ctx, key, presign, record, nil, guard, limits)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("local sign partial self-verification failed: %w", err)
	}
	// signSessionFromAttempt borrows the caller-owned presign. The temporary
	// validation session must not destroy the sigma identification openings
	// needed by the real attempt.
	validationSession.presign = nil
	validationSession.Destroy()
	return record, nil
}

// ResumeSign loads and resumes the only durable attempt bound to presign.
// Production recovery must use this function with the same presign and durable
// store when a CGGMP21 sign attempt may already have committed or been sent. It
// must not create a new signing session with a different session ID or digest
// for that presign.
func ResumeSign(ctx context.Context, key *KeyShare, presign *Presign, store SignAttemptStore, guard *tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	return ResumeSignWithLimits(ctx, key, presign, store, guard, DefaultLimits())
}

// ResumeSignWithLimits resumes a durable sign attempt using explicit local
// validation and decoding limits. It has the same production recovery semantics
// as ResumeSign: the durable attempt, not a fresh session ID, is the authority
// for a presign whose online-signing outcome may be unknown.
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
	if err := presign.VerifyCryptographicMaterialWithLimits(limits); err != nil {
		return nil, nil, err
	}
	handle, err := newPresignHandle(presign, limits)
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := newSignAttemptCoordinator(store, handle, DefaultSignAttemptStoreTimeout, limits)
	if err != nil {
		return nil, nil, err
	}
	record, err := coordinator.load(ctx)
	if err != nil {
		if errors.Is(err, ErrSignAttemptCorrupt) {
			_ = DiscardLocalPresignHandle(presign)
		}
		return nil, nil, err
	}
	if err := validateSignAttemptRecordWithLimits(record, limits); err != nil {
		_ = DiscardLocalPresignHandle(presign)
		return nil, nil, err
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, record.SessionID, key.state.Party); err != nil {
		return nil, nil, err
	}
	if !bindPresignToAttempt(presign, record.IntentHash, true) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.Party, errors.New("presign is bound to another attempt or was manually discarded"))
	}
	return signSessionFromAttempt(ctx, key, presign, record, coordinator, guard, limits)
}

func resumeMatchingSignAttempt(ctx context.Context, key *KeyShare, presign *Presign, candidate, durable SignAttemptRecord, coordinator *signAttemptCoordinator, guard *tss.EnvelopeGuard, limits Limits) (*SignSession, []tss.Envelope, error) {
	if err := validateSignAttemptRecordWithLimits(durable, limits); err != nil {
		_ = DiscardLocalPresignHandle(presign)
		return nil, nil, err
	}
	if !candidate.SameAttempt(durable) {
		if !bindPresignToAttempt(presign, durable.IntentHash, true) {
			_ = DiscardLocalPresignHandle(presign)
		}
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.Party, ErrSignAttemptConflict)
	}
	if !bindPresignToAttempt(presign, durable.IntentHash, true) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.state.Party, errors.New("presign is bound to another attempt or was manually discarded"))
	}
	return signSessionFromAttempt(ctx, key, presign, durable, coordinator, guard, limits)
}

func signSessionFromAttempt(ctx context.Context, key *KeyShare, presign *Presign, record SignAttemptRecord, coordinator *signAttemptCoordinator, guard *tss.EnvelopeGuard, limits Limits) (*SignSession, []tss.Envelope, error) {
	if err := validateSignAttemptBindings(key, presign, record, limits); err != nil {
		return nil, nil, err
	}
	var ackVerifier tss.BroadcastAckVerifier
	if guard != nil {
		ackVerifier = guard.AckVerifier
	}
	if err := validateSignAttemptDeliveryAuthentication(record, ackVerifier); err != nil {
		return nil, nil, err
	}
	env, payload, err := decodeSignAttemptEnvelopeWithLimits(record.CanonicalBaseEnvelopeBytes, limits)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	defer payload.S.Destroy()
	verifyKey := presign.verificationKey()
	s := &SignSession{
		key:              key,
		presign:          presign,
		sessionID:        record.SessionID,
		log:              tss.NopLogger(),
		limits:           limits,
		digest:           slices.Clone(record.Digest),
		planHash:         slices.Clone(record.SignPlanHash),
		publicKey:        verifyKey,
		partials:         make(map[tss.PartyID]secp.Scalar),
		partialEnvelopes: make(map[tss.PartyID]tss.Envelope),
		guard:            guard,
		attempt:          record.Clone(),
		coordinator:      coordinator,
		coordinatorCtx:   context.WithoutCancel(ctx),
	}
	partial, err := s.verifySignPartial(key.state.Party, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: local sign partial verification failed: %w", ErrSignAttemptCorrupt, err)
	}
	s.partials[key.state.Party] = partial
	s.partialEnvelopes[key.state.Party] = env.Clone()
	if record.Completed {
		sig := &Signature{R: slices.Clone(record.SignatureR), S: slices.Clone(record.SignatureS), RecoveryID: record.SignatureRecoveryID}
		if !VerifyDigest(verifyKey, record.Digest, sig) || !signatureRecoveryIDMatchesPublicKey(verifyKey, record.Digest, sig) {
			return nil, nil, fmt.Errorf("%w: stored signature verification failed", ErrSignAttemptCorrupt)
		}
		s.signature = sig
		s.completed = true
		s.destroyOnlineIdentificationOpenings()
		if record.DeliveryState.DeliveryComplete {
			return s, nil, nil
		}
		return s, []tss.Envelope{env}, nil
	}
	if coordinator != nil {
		s.sigmaOpenings, err = activatePresignSigmaOpeningRecords(presign)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: restore online identification witnesses: %w", ErrSignAttemptCorrupt, err)
		}
	}
	if coordinator != nil {
		identificationOut, err := s.tryCompleteSign(s.coordinatorCtx)
		if err != nil {
			s.destroyOnlineIdentificationOpenings()
			return nil, nil, err
		}
		if len(identificationOut) > 0 {
			return s, append([]tss.Envelope{env}, identificationOut...), nil
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
	contentID, err := presign.contentIDWithLimits(limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(record.PresignContentID, contentID) ||
		record.Party != key.state.Party ||
		!bytes.Equal(record.SignerSetHash, signAttemptSignerSetHash(presign.state.Signers)) ||
		!bytes.Equal(record.ContextHash, presign.state.ContextHash) {
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
	handle, err := newPresignHandle(presign, DefaultLimits())
	if err != nil {
		return err
	}
	coordinator, err := newSignAttemptCoordinator(store, handle, DefaultSignAttemptStoreTimeout, DefaultLimits())
	if err != nil {
		return err
	}
	if err := coordinator.burn(ctx, reason); err != nil {
		return err
	}
	return DiscardLocalPresignHandle(presign)
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
	if s.coordinator == nil {
		return errors.New("sign attempt coordinator unavailable during delivery update")
	}
	var verifier tss.BroadcastAckVerifier
	if s.guard != nil {
		verifier = s.guard.AckVerifier
	}
	updated, err := s.coordinator.updateDelivery(ctx, ack, certificate, verifier)
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
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.sessionID, s.presign.state.Signers, s.key.state.Party)
}

// Handle validates and applies one online signing envelope.
//
// Follows the handler template (see doc.go).
func (s *SignSession) Handle(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
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
	if base.PayloadType == payloadSignIdentification {
		if err := validateIdentificationPayloadSize(base); err != nil {
			return nil, err
		}
	}
	defer func() {
		err = bindInboundAuthenticationEvidence(err, env)
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	if base.PayloadType == payloadSignIdentification && !s.identifying {
		if err := tss.ValidateInboundWithoutReplay(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.sessionID, s.presign.state.Signers, s.key.state.Party); err != nil {
			return nil, err
		}
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("sign identification is not active"))
	}
	if base.PayloadType == payloadSignIdentification {
		tx, err := s.buildAcceptSignIdentificationTx(env)
		if err != nil {
			return nil, err
		}
		defer tx.cleanupOnReject()
		effects, err := tx.apply(s)
		if err != nil {
			return nil, err
		}
		tx.markCommitted()
		return effects.envelopes, nil
	}
	tx, err := s.buildAcceptSignPartialTx(env)
	if err != nil {
		return nil, err
	}
	defer tx.cleanupOnReject()
	effects, err := tx.apply(s)
	if err != nil {
		return nil, err
	}
	tx.markCommitted()
	identificationOut, err := s.tryCompleteSign(s.coordinatorCtx)
	if err != nil {
		return nil, err
	}
	return append(effects.envelopes, identificationOut...), nil
}

// Signature returns the completed ECDSA signature.
func (s *SignSession) Signature() (*Signature, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed || s.identifying {
		return nil, false
	}
	return &Signature{
		R:          slices.Clone(s.signature.R),
		S:          slices.Clone(s.signature.S),
		RecoveryID: s.signature.RecoveryID,
	}, true
}

func (s *SignSession) signPartialEvidenceFields(from tss.PartyID, p signPartialPayload) []tss.EvidenceField {
	fields := s.signPartialContextEvidenceFields(nil)
	partialBytes := p.S.FixedBytes()
	defer clear(partialBytes)
	fields = append(fields,
		hashEvidenceField("observed_presign_transcript_hash", p.PresignTranscript),
		hashEvidenceField("observed_presign_context_hash", p.PresignContext),
		hashEvidenceField("sign_partial_hash", partialBytes),
	)
	// Include the sender's (blamed party's) KPoint/ChiPoint hashes.
	if vs, ok := presignVerifyShare(s.presign, from); ok {
		kPointBytes, _ := vs.kPointBytes()
		chiPointBytes, _ := vs.chiPointBytes()
		fields = append(fields,
			hashEvidenceField(evidenceFieldSignVerifyKPointHash, kPointBytes),
			hashEvidenceField(evidenceFieldSignVerifyChiPointHash, chiPointBytes),
		)
		// Compute the expected equation hash for independent auditability.
		expectedEqHash := partialEquationHash(
			s.sessionID, from, s.presign.state.TranscriptHash,
			s.presign.state.ContextHash, s.planHash, s.digest,
			s.presign.state.LittleR.Bytes(), partialBytes,
			kPointBytes, chiPointBytes,
		)
		fields = append(fields,
			rawEvidenceField(evidenceFieldPartialEquationHash, expectedEqHash),
			rawEvidenceField(evidenceFieldObservedPartialEquationHash, p.PartialEquationHash),
		)
	}
	return fields
}

func (s *SignSession) signPartialContextEvidenceFields(rawPayload []byte) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.state.Signers)...)
	fields = append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.presign.state.TranscriptHash),
		rawEvidenceField("presign_context_hash", s.presign.state.ContextHash),
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
	_, err := s.tryCompleteSign(ctx)
	return err
}

// VerifyDigest verifies a canonical low-S secp256k1 ECDSA signature over a
// 32-byte digest. High-S signatures are rejected.
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
	if !secp.IsLowS(s) {
		return false
	}
	return secp.VerifyECDSA(public, digest32, r, s)
}

// VerifySignature verifies a context-bound canonical low-S secp256k1 ECDSA
// signature.
func VerifySignature(publicKey []byte, request SignRequest, sig *Signature) bool {
	if err := validatePresignContext(request.Context); err != nil {
		return false
	}
	contextHash := presignContextHash(request.Context)
	digest := signMessageDigest(contextHash, request.Context.MessageDomain, request.Message)
	return VerifyDigest(publicKey, digest, sig)
}

// VerificationKeyForContext derives the child verification key for ctx from key.
func VerificationKeyForContext(key *KeyShare, ctx tss.SigningContext) ([]byte, error) {
	_, _, derivation, err := preparePresignContext(key, ctx)
	if err != nil {
		return nil, err
	}
	// derivation is a deep copy value
	return derivation.ChildPublicKey, nil
}

// VerifySignatureForContext verifies a context-bound canonical low-S signature
// against the child key derived from parentPublicKey and chainCode.
func VerifySignatureForContext(parentPublicKey []byte, chainCode []byte, ctx tss.SigningContext, request SignRequest, sig *Signature) bool {
	if err := validatePresignContext(ctx); err != nil {
		return false
	}
	derivation, err := DeriveNonHardenedBIP32(parentPublicKey, chainCode, ctx.Derivation.Path, tss.WithInvalidChildMode(ctx.Derivation.InvalidChildMode))
	if err != nil {
		return false
	}
	if len(ctx.Derivation.ResolvedPath) > 0 && !slices.Equal(ctx.Derivation.ResolvedPath, derivation.ResolvedPath) {
		return false
	}
	normalized := ctx.Clone()
	normalized.Derivation.Path = derivation.RequestedPath.Clone()
	normalized.Derivation.ResolvedPath = derivation.ResolvedPath.Clone()
	request.Context = normalized
	return VerifySignature(derivation.ChildPublicKey, request, sig)
}

func validatePresign(key *KeyShare, presign *Presign, limits Limits) error {
	if err := presign.ValidateWithLimits(limits); err != nil {
		return err
	}
	if presign.state.Party != key.state.Party {
		return errors.New("presign party mismatch")
	}
	if presign.state.Threshold != key.state.Threshold {
		return errors.New("presign threshold mismatch")
	}
	if validSecurityParams(key.state.SecurityParams) && presign.state.SecurityParams != key.state.SecurityParams {
		return errors.New("presign security params mismatch")
	}
	presignPublicKey, err := secp.PointBytes(presign.state.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(presignPublicKey, key.state.PublicKey) {
		return errors.New("presign public key binding mismatch")
	}
	if !bytes.Equal(presign.state.KeygenTranscriptHash, key.state.KeygenTranscriptHash) {
		return errors.New("presign keygen transcript binding mismatch")
	}
	if !bytes.Equal(presign.state.PartiesHash, tss.PartySetHash(key.state.Parties, partySetHashLabel)) {
		return errors.New("presign participant set binding mismatch")
	}
	_, contextHash, derivation, err := preparePresignContext(key, presign.state.Context)
	if err != nil {
		return err
	}
	if !bytes.Equal(contextHash, presign.state.ContextHash) {
		return errors.New("presign context hash mismatch")
	}
	if !derivation.Equal(presign.state.Derivation) {
		return errors.New("presign derivation binding mismatch")
	}
	if len(presign.state.Signers) < key.state.Threshold || !tss.ContainsParty(presign.state.Signers, key.state.Party) {
		return errors.New("invalid presign signer set")
	}
	return nil
}

func validateSignerSet(key *KeyShare, signers tss.PartySet, limits Limits) error {
	return tss.ValidateSignerSet(key.state.Parties, key.state.Threshold, signers, limits.ThresholdLimits())
}

func (s *SignSession) verifySignPartial(from tss.PartyID, p signPartialPayload) (secp.Scalar, error) {
	if !tss.ContainsParty(s.presign.state.Signers, from) {
		return secp.Scalar{}, errors.New("sender is not in signer set")
	}
	if !bytes.Equal(p.PresignTranscript, s.presign.state.TranscriptHash) {
		return secp.Scalar{}, errors.New("presign transcript mismatch")
	}
	if !bytes.Equal(p.PresignContext, s.presign.state.ContextHash) {
		return secp.Scalar{}, errors.New("presign context mismatch")
	}
	if err := requirePlanHash("sign", p.PlanHash, s.planHash); err != nil {
		return secp.Scalar{}, err
	}
	expectedDigestHash := digestHash(s.digest, s.presign.state.ContextHash)
	if !bytes.Equal(p.DigestHash, expectedDigestHash) {
		return secp.Scalar{}, errors.New("digest hash mismatch")
	}
	sVal, err := secpScalarFromSecretAllowZero(p.S)
	if err != nil {
		return secp.Scalar{}, err
	}
	vs, ok := presignVerifyShare(s.presign, from)
	if !ok {
		return secp.Scalar{}, fmt.Errorf("missing verify share for party %d", from)
	}
	kPointBytes, err := vs.kPointBytes()
	if err != nil {
		return secp.Scalar{}, fmt.Errorf("invalid KPoint for party %d: %w", from, err)
	}
	chiPointBytes, err := vs.chiPointBytes()
	if err != nil {
		return secp.Scalar{}, fmt.Errorf("invalid ChiPoint for party %d: %w", from, err)
	}
	littleR := s.presign.state.LittleR
	partialBytes := p.S.FixedBytes()
	defer clear(partialBytes)
	expectedEqHash := partialEquationHash(
		s.sessionID, from, s.presign.state.TranscriptHash,
		s.presign.state.ContextHash, s.planHash, s.digest,
		littleR.Bytes(), partialBytes,
		kPointBytes, chiPointBytes,
	)
	if !bytes.Equal(p.PartialEquationHash, expectedEqHash) {
		return secp.Scalar{}, errors.New("partial equation hash mismatch")
	}
	zScalar, err := secp.ScalarFromBytesModOrder(s.digest)
	if err != nil {
		return secp.Scalar{}, err
	}
	lhs := secp.ScalarBaseMult(sVal)
	term1 := secp.ScalarMult(vs.KPoint, zScalar)
	term2 := secp.ScalarMult(vs.ChiPoint, littleR)
	rhs := secp.Add(term1, term2)
	if !secp.Equal(lhs, rhs) {
		return secp.Scalar{}, errors.New("sign partial equation verification failed")
	}
	return sVal, nil
}

func digestHash(digest32, contextHash []byte) []byte {
	t := transcript.New("cggmp21-secp256k1-sign-digest-binding")
	t.AppendBytes("context_hash", contextHash)
	t.AppendBytes("digest", digest32)
	return t.Sum()
}

func partialEquationHash(sessionID tss.SessionID, party tss.PartyID, presignTranscriptHash, contextHash, planHash, digestHash, littleR, s, kPoint, chiPoint []byte) []byte {
	t := transcript.New("cggmp21-secp256k1-sign-partial-equation")
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

func presignVerifyShare(presign *Presign, party tss.PartyID) (signVerifyShare, bool) {
	if presign == nil || presign.state == nil {
		return signVerifyShare{}, false
	}
	for _, vs := range presign.state.VerifyShares {
		if vs.Party == party {
			return vs, true
		}
	}
	return signVerifyShare{}, false
}
