package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/tssrun"
)

// StartSign starts or idempotently recovers this party's exact durable online
// signing attempt. The available presign's secret blob is used only to prepare
// and verify the candidate outbox; CommitSignAttempt destroys that blob and
// retains only the public Figure 10 context and exact broadcast outbox.
func StartSign(plan *SignPlan, runtime SignRuntime) (*SignSession, []tss.Envelope, error) {
	local := runtime.Local
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil sign plan"))
	}
	if local.Self == tss.BroadcastPartyId {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("SignRuntime.Local.Self is required"))
	}
	if runtime.LifecycleStore == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("SignRuntime.LifecycleStore is required"))
	}
	if err := runtime.Binding.Validate(); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := validateSignLifecycleIdentifier(runtime.PresignID); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("invalid SignRuntime.PresignID"))
	}
	if err := validateCanonicalPresignSlot(runtime.PresignID, plan.state.protocolPresignID); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := validateSignLifecycleIdentifier(runtime.AttemptID); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("invalid SignRuntime.AttemptID"))
	}
	if err := tss.RequireEnvelopeGuard(runtime.Guard, tss.ProtocolCGGMP21Secp256k1, plan.state.sessionID, local.Self); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := requireLocalEnvelopeSigner(runtime.Guard, local.EnvelopeSigner); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if !plan.state.signers.Contains(local.Self) ||
		!bytes.Equal(plan.state.epochID, runtime.Binding.EpochID[:]) ||
		plan.state.intent.Context.KeyID != runtime.Binding.KeyID {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("sign plan does not match lifecycle binding or local party"))
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}

	ctx := local.Ctx()
	timeout := durableStoreTimeout(runtime.DurableStoreTimeout)
	key, err := loadLifecycleKeyShare(ctx, runtime.LifecycleStore, runtime.Binding, plan.limits, timeout)
	if err != nil {
		return nil, nil, err
	}
	keyOwned := true
	defer func() {
		if keyOwned {
			key.Destroy()
		}
	}()
	if local.Self != key.state.Party {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("local self does not match lifecycle key share party"))
	}
	storeCtx, cancel := durableStoreContext(ctx, timeout)
	lease, err := runtime.LifecycleStore.AcquireRunLease(storeCtx, runtime.Binding, tssrun.RunSign, plan.state.sessionID)
	cancel()
	if err != nil {
		return nil, nil, err
	}
	failBeforeCommit := func(cause error) error {
		return finishUncommittedSignLease(ctx, runtime.LifecycleStore, lease, timeout, cause)
	}

	storeCtx, cancel = durableStoreContext(ctx, timeout)
	candidate, err := runtime.LifecycleStore.PreparePresignCandidate(storeCtx, runtime.Binding, runtime.PresignID)
	cancel()
	if err != nil {
		if signAttemptConsumedError(err) {
			err = tss.NewProtocolError(tss.ErrCodeConsumed, signStartRound, key.state.Party, err)
		}
		return nil, nil, failBeforeCommit(err)
	}
	defer clear(candidate.Blob)
	defer clear(candidate.Metadata)
	if candidate.Binding != runtime.Binding || candidate.PresignID != runtime.PresignID {
		return nil, nil, failBeforeCommit(fmt.Errorf("%w: prepared presign lifecycle binding mismatch", ErrSignAttemptCorrupt))
	}
	publicContext, err := unmarshalSignAttemptPublicContext(candidate.Metadata, plan.limits)
	if err != nil {
		return nil, nil, failBeforeCommit(err)
	}
	defer publicContext.destroy()
	var presign Presign
	if err := presign.UnmarshalBinaryWithLimits(candidate.Blob, plan.limits); err != nil {
		return nil, nil, failBeforeCommit(fmt.Errorf("decode prepared presign: %w", err))
	}
	defer presign.Destroy()
	if err := key.requireMPCMaterial(plan.limits); err != nil {
		return nil, nil, failBeforeCommit(err)
	}
	if err := presign.VerifySignMaterialWithLimits(plan.limits); err != nil {
		return nil, nil, failBeforeCommit(err)
	}
	if err := validatePresign(key, &presign, plan.limits); err != nil {
		return nil, nil, failBeforeCommit(invalidPlanConfig(local.Self, err))
	}
	presignMetadata, ok := presign.PublicMetadata()
	if !ok {
		return nil, nil, failBeforeCommit(invalidPlanConfig(local.Self, errors.New("invalid public presign metadata")))
	}
	if err := plan.validate(key, presignMetadata, local); err != nil {
		return nil, nil, failBeforeCommit(invalidPlanConfig(local.Self, err))
	}
	if !signAttemptPublicContextMatchesPresign(publicContext, &presign) {
		return nil, nil, failBeforeCommit(fmt.Errorf("%w: public presign metadata does not match secret candidate", ErrSignAttemptCorrupt))
	}
	if err := validateSignLifecycleBinding(key, publicContext, runtime.Binding); err != nil {
		return nil, nil, failBeforeCommit(err)
	}
	outbox, rawOutbox, err := buildSignAttemptOutbox(
		ctx, key, &presign, publicContext, runtime.Binding,
		runtime.PresignID, runtime.AttemptID, plan.state.sessionID,
		plan.state.digest, plan.state.contextHash, planHash,
		runtime.DeliveryPolicy, local.EnvelopeSigner, plan.limits,
	)
	if err != nil {
		return nil, nil, failBeforeCommit(err)
	}
	defer clearSignAttemptOutbox(&outbox)
	defer clear(rawOutbox)
	query := tssrun.AttemptQuery{
		Binding:      runtime.Binding,
		PresignID:    runtime.PresignID,
		AttemptID:    runtime.AttemptID,
		IntentDigest: bytes.Clone(outbox.IntentDigest),
	}
	coordinator, err := newSignAttemptCoordinator(runtime.LifecycleStore, lease, query, timeout, plan.limits)
	if err != nil {
		return nil, nil, failBeforeCommit(err)
	}
	commit, err := coordinator.claim(ctx, outbox, rawOutbox)
	if err != nil {
		if errors.Is(err, tssrun.ErrAttemptOutcomeUnknown) {
			return nil, nil, err
		}
		if signAttemptConsumedError(err) {
			err = tss.NewProtocolError(tss.ErrCodeConsumed, signStartRound, key.state.Party, err)
		}
		return nil, nil, failBeforeCommit(err)
	}
	session, out, err := signSessionFromLifecycleAttempt(ctx, key, commit.Record, coordinator, runtime.Guard, plan.limits)
	if err != nil {
		return nil, nil, err
	}
	keyOwned = false
	return session, out, nil
}

func durableStoreTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultLifecycleStoreTimeout
	}
	return timeout
}

func durableStoreContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), durableStoreTimeout(timeout))
}

func finishUncommittedSignLease(ctx context.Context, store tssrun.LifecycleStore, lease tssrun.RunLease, timeout time.Duration, cause error) error {
	storeCtx, cancel := durableStoreContext(ctx, timeout)
	defer cancel()
	if err := store.FinishRunLease(storeCtx, lease, tssrun.LeaseAborted); err != nil {
		return errors.Join(cause, fmt.Errorf("abort uncommitted sign run lease: %w", err))
	}
	return cause
}

func signAttemptConsumedError(err error) bool {
	return errors.Is(err, tssrun.ErrPresignUnavailable) ||
		errors.Is(err, tssrun.ErrPresignBurned) ||
		errors.Is(err, tssrun.ErrAttemptConflict) ||
		errors.Is(err, tssrun.ErrAttemptNonDeterminism)
}

func buildSignAttemptOutbox(
	ctx context.Context,
	key *KeyShare,
	presign *Presign,
	publicContext signAttemptPublicContext,
	binding tssrun.GenerationBinding,
	presignID, attemptID string,
	sessionID tss.SessionID,
	digest32, contextHash, planHash []byte,
	deliveryPolicy SignAttemptDeliveryPolicy,
	envelopeSigner tss.EnvelopeSigner,
	limits Limits,
) (signAttemptOutbox, []byte, error) {
	if ctx == nil {
		return signAttemptOutbox{}, nil, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return signAttemptOutbox{}, nil, err
	}
	if len(digest32) != sha256.Size || len(contextHash) != sha256.Size || len(planHash) != sha256.Size {
		return signAttemptOutbox{}, nil, errors.New("invalid online-sign digest binding")
	}
	kShare, err := secpScalarFromSecret(presign.state.KShare)
	if err != nil {
		return signAttemptOutbox{}, nil, err
	}
	chiShare, err := secpScalarFromSecretAllowZero(presign.state.ChiShare)
	if err != nil {
		return signAttemptOutbox{}, nil, err
	}
	zScalar, err := secp.ScalarFromBytesModOrder(digest32)
	if err != nil {
		return signAttemptOutbox{}, nil, err
	}
	partial := secp.ScalarAdd(
		secp.ScalarMul(zScalar, kShare),
		secp.ScalarMul(publicContext.LittleR, chiShare),
	)
	partialWire, err := secpSecretScalarFromScalarAllowZero(partial)
	if err != nil {
		return signAttemptOutbox{}, nil, err
	}
	defer partialWire.Destroy()
	localCommitment, ok := normalizedCommitmentForPublicContext(&publicContext, key.state.Party)
	if !ok {
		return signAttemptOutbox{}, nil, fmt.Errorf("missing local normalized commitment for party %d", key.state.Party)
	}
	partialBytes := partial.Bytes()
	defer clear(partialBytes)
	payload := signPartialPayload{
		S:                 partialWire,
		PresignID:         bytes.Clone(publicContext.ProtocolPresignID),
		EpochID:           bytes.Clone(publicContext.EpochID),
		PresignTranscript: bytes.Clone(publicContext.TranscriptHash),
		PresignContext:    bytes.Clone(contextHash),
		DigestHash:        digestHash(digest32, contextHash),
		PlanHash:          bytes.Clone(planHash),
		PartialEquationHash: partialEquationHash(
			sessionID, key.state.Party, publicContext.TranscriptHash,
			contextHash, planHash, digest32,
			publicContext.LittleR.Bytes(), partialBytes,
			localCommitment.DeltaTilde, localCommitment.STilde,
		),
	}
	payloadBytes, err := payload.MarshalBinaryWithLimits(limits)
	if err != nil {
		return signAttemptOutbox{}, nil, err
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
		return signAttemptOutbox{}, nil, err
	}
	if envelopeSigner != nil {
		env, err = tss.SignEnvelope(env, envelopeSigner)
		if err != nil {
			return signAttemptOutbox{}, nil, fmt.Errorf("sign online-sign envelope: %w", err)
		}
	}
	envelopeBytes, err := env.MarshalBinary()
	if err != nil {
		return signAttemptOutbox{}, nil, err
	}
	envelopeHash := sha256.Sum256(envelopeBytes)
	payloadHash := tss.PayloadHashFromEnvelope(env)
	envelopeDigest := env.Digest()
	outbox := signAttemptOutbox{
		RecordVersion:         signAttemptOutboxVersion,
		Protocol:              tss.ProtocolCGGMP21Secp256k1,
		ProtocolVersion:       tss.ProtocolVersion,
		KeyID:                 binding.KeyID,
		KeyGeneration:         string(binding.KeyGeneration),
		EpochID:               binding.EpochID.Bytes(),
		PresignID:             presignID,
		AttemptID:             attemptID,
		ProtocolPresignID:     bytes.Clone(publicContext.ProtocolPresignID),
		SessionID:             sessionID,
		Party:                 key.state.Party,
		SignerSetHash:         signAttemptSignerSetHash(publicContext.Signers),
		SignPlanHash:          bytes.Clone(planHash),
		ContextHash:           bytes.Clone(contextHash),
		Digest:                bytes.Clone(digest32),
		DigestBindingHash:     digestHash(digest32, contextHash),
		CanonicalEnvelope:     envelopeBytes,
		CanonicalEnvelopeHash: bytes.Clone(envelopeHash[:]),
		EnvelopeDigest:        bytes.Clone(envelopeDigest[:]),
		PayloadHash:           bytes.Clone(payloadHash[:]),
		DeliveryPolicy:        deliveryPolicy.Clone(),
		VerificationKey:       bytes.Clone(publicContext.VerificationKey),
	}
	outbox.IntentDigest = signAttemptIntentDigest(outbox)
	rawOutbox, err := marshalSignAttemptOutbox(outbox, limits)
	if err != nil {
		clearSignAttemptOutbox(&outbox)
		return signAttemptOutbox{}, nil, err
	}
	_, decodedPayload, err := decodeSignAttemptEnvelopeWithLimits(outbox.CanonicalEnvelope, limits)
	if err != nil {
		clear(rawOutbox)
		clearSignAttemptOutbox(&outbox)
		return signAttemptOutbox{}, nil, err
	}
	defer decodedPayload.S.Destroy()
	validationSession := &SignSession{
		verification: publicContext.clone(),
		sessionID:    sessionID,
		limits:       limits,
		digest:       bytes.Clone(digest32),
		planHash:     bytes.Clone(planHash),
	}
	_, verifyErr := validationSession.verifySignPartial(key.state.Party, decodedPayload)
	validationSession.abort()
	if verifyErr != nil {
		clear(rawOutbox)
		clearSignAttemptOutbox(&outbox)
		return signAttemptOutbox{}, nil, fmt.Errorf("local Figure 10 partial self-verification failed: %w", verifyErr)
	}
	return outbox, rawOutbox, nil
}

// ResumeSign recovers exactly the durable attempt named by query without a
// caller-supplied key share, presign, or normalized secret tuple.
func ResumeSign(ctx context.Context, store tssrun.LifecycleStore, query tssrun.AttemptQuery, guard *tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	return ResumeSignWithLimits(ctx, store, query, guard, DefaultLimits())
}

// ResumeSignWithLimits recovers exactly the durable attempt named by query
// using explicit local resource limits.
func ResumeSignWithLimits(ctx context.Context, store tssrun.LifecycleStore, query tssrun.AttemptQuery, guard *tss.EnvelopeGuard, limits Limits) (*SignSession, []tss.Envelope, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil context")
	}
	if store == nil {
		return nil, nil, errors.New("nil lifecycle store")
	}
	if err := query.Validate(); err != nil {
		return nil, nil, err
	}
	record, err := store.QueryAttemptOutcome(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	if record.Aborted {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, signStartRound, tss.BroadcastPartyId, tssrun.ErrAttemptConflict)
	}
	if err := validateLifecycleRecordPresignSlot(record, limits); err != nil {
		return nil, nil, err
	}
	var key *KeyShare
	keyOwned := false
	defer func() {
		if keyOwned && key != nil {
			key.Destroy()
		}
	}()
	var lease tssrun.RunLease
	var coordinator *signAttemptCoordinator
	if !record.Terminal() {
		key, err = loadLifecycleKeyShare(ctx, store, query.Binding, limits, DefaultLifecycleStoreTimeout)
		if err != nil {
			return nil, nil, err
		}
		keyOwned = true
		storeCtx, cancel := durableStoreContext(ctx, DefaultLifecycleStoreTimeout)
		lease, err = store.AcquireRunLease(storeCtx, query.Binding, tssrun.RunSign, record.Intent.SessionID)
		cancel()
		if err != nil {
			return nil, nil, err
		}
		coordinator, err = newSignAttemptCoordinator(store, lease, query, DefaultLifecycleStoreTimeout, limits)
		if err != nil {
			return nil, nil, err
		}
		if err := coordinator.acceptRecord(record); err != nil {
			return nil, nil, err
		}
	}
	session, out, err := signSessionFromLifecycleAttempt(ctx, key, record, coordinator, guard, limits)
	if err != nil {
		return nil, nil, err
	}
	keyOwned = false
	return session, out, nil
}

func signSessionFromLifecycleAttempt(ctx context.Context, key *KeyShare, record tssrun.SignAttemptRecord, coordinator *signAttemptCoordinator, guard *tss.EnvelopeGuard, limits Limits) (*SignSession, []tss.Envelope, error) {
	if len(record.PresignMetadata) == 0 {
		return nil, nil, fmt.Errorf("%w: missing public presign metadata", ErrSignAttemptCorrupt)
	}
	publicContext, err := unmarshalSignAttemptPublicContext(record.PresignMetadata, limits)
	if err != nil {
		return nil, nil, err
	}
	ownedContext := true
	defer func() {
		if ownedContext {
			publicContext.destroy()
		}
	}()
	if err := validateCanonicalPresignSlot(record.PresignID, publicContext.ProtocolPresignID); err != nil {
		return nil, nil, err
	}
	var verifier tss.BroadcastAckVerifier
	if guard != nil {
		verifier = guard.AckVerifier
	}
	var outbox signAttemptOutbox
	if len(record.ExactOutbox) != 0 {
		outbox, err = unmarshalSignAttemptOutbox(record.ExactOutbox, limits)
		if err != nil {
			return nil, nil, err
		}
	} else if record.Delivered {
		delivery, decodeErr := unmarshalSignAttemptDelivery(record.Delivery, limits, verifier)
		if decodeErr != nil {
			return nil, nil, decodeErr
		}
		outbox = delivery.outboxIdentity()
	} else {
		return nil, nil, fmt.Errorf("%w: recoverable attempt missing exact outbox", ErrSignAttemptCorrupt)
	}
	ownedOutbox := true
	defer func() {
		if ownedOutbox {
			clearSignAttemptOutbox(&outbox)
		}
	}()
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, record.Intent.SessionID, publicContext.Party); err != nil {
		return nil, nil, err
	}
	if err := validateLifecycleAttemptBindings(key, publicContext, record, outbox); err != nil {
		return nil, nil, err
	}
	if record.Delivered && len(record.ExactOutbox) != 0 {
		delivery, decodeErr := unmarshalSignAttemptDelivery(record.Delivery, limits, verifier)
		if decodeErr != nil {
			return nil, nil, decodeErr
		}
		identity := delivery.outboxIdentity()
		defer clearSignAttemptOutbox(&identity)
		if !sameSignAttemptOutboxIdentity(outbox, identity) {
			return nil, nil, fmt.Errorf("%w: delivery and exact outbox identity mismatch", ErrSignAttemptCorrupt)
		}
	}
	var signature *Signature
	if record.Completed {
		completion, decodeErr := unmarshalSignAttemptCompletion(record.Completion, limits)
		if decodeErr != nil {
			return nil, nil, decodeErr
		}
		if !bytes.Equal(completion.IntentDigest, outbox.IntentDigest) {
			return nil, nil, fmt.Errorf("%w: completion intent mismatch", ErrSignAttemptCorrupt)
		}
		signature = &Signature{R: bytes.Clone(completion.SignatureR), S: bytes.Clone(completion.SignatureS), RecoveryID: completion.RecoveryID}
		if !VerifyDigest(publicContext.VerificationKey, outbox.Digest, signature) ||
			!signatureRecoveryIDMatchesPublicKey(publicContext.VerificationKey, outbox.Digest, signature) {
			return nil, nil, fmt.Errorf("%w: stored completion verification failed", ErrSignAttemptCorrupt)
		}
	}
	sessionRecord := record.Clone()
	clear(sessionRecord.PresignMetadata)
	clear(sessionRecord.ExactOutbox)
	sessionRecord.PresignMetadata = nil
	sessionRecord.ExactOutbox = nil
	s := &SignSession{
		key:              key,
		ownsKey:          key != nil,
		verification:     publicContext,
		sessionID:        outbox.SessionID,
		guard:            guard,
		log:              tss.NopLogger(),
		limits:           limits,
		digest:           bytes.Clone(outbox.Digest),
		planHash:         bytes.Clone(outbox.SignPlanHash),
		publicKey:        bytes.Clone(publicContext.VerificationKey),
		partials:         make(map[tss.PartyID]secp.Scalar),
		partialEnvelopes: make(map[tss.PartyID]tss.Envelope),
		completed:        record.Completed,
		signature:        signature,
		attempt:          sessionRecord,
		outbox:           outbox,
		coordinator:      coordinator,
		coordinatorCtx:   context.WithoutCancel(ctx),
	}
	ownedContext = false
	ownedOutbox = false
	if len(s.outbox.CanonicalEnvelope) != 0 {
		env, payload, decodeErr := decodeSignAttemptEnvelopeWithLimits(s.outbox.CanonicalEnvelope, limits)
		if decodeErr != nil {
			s.Destroy()
			return nil, nil, fmt.Errorf("%w: decode exact sign outbox: %w", ErrSignAttemptCorrupt, decodeErr)
		}
		defer payload.S.Destroy()
		partial, verifyErr := s.verifySignPartial(key.state.Party, payload)
		if verifyErr != nil {
			s.Destroy()
			return nil, nil, fmt.Errorf("%w: local sign partial verification failed: %w", ErrSignAttemptCorrupt, verifyErr)
		}
		s.partials[key.state.Party] = partial
		s.partialEnvelopes[key.state.Party] = env.Clone()
		if !record.Completed && coordinator != nil {
			if _, err := s.tryCompleteSign(s.coordinatorCtx); err != nil {
				s.Destroy()
				return nil, nil, err
			}
		}
		if !record.Delivered {
			return s, []tss.Envelope{env}, nil
		}
	}
	return s, nil, nil
}

func validateSignLifecycleBinding(key *KeyShare, publicContext signAttemptPublicContext, binding tssrun.GenerationBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if publicContext.KeyID != binding.KeyID || !bytes.Equal(publicContext.EpochID, binding.EpochID[:]) {
		return fmt.Errorf("%w: key generation or epoch binding mismatch", ErrSignAttemptCorrupt)
	}
	if key != nil && (key.state == nil || key.state.Epoch == nil ||
		publicContext.Party != key.state.Party ||
		!bytes.Equal(publicContext.EpochID, key.state.Epoch.EpochID)) {
		return fmt.Errorf("%w: lifecycle key share does not match public attempt context", ErrSignAttemptCorrupt)
	}
	return nil
}

func validateLifecycleAttemptBindings(key *KeyShare, publicContext signAttemptPublicContext, record tssrun.SignAttemptRecord, outbox signAttemptOutbox) error {
	if err := validateSignLifecycleBinding(key, publicContext, record.Binding); err != nil {
		return err
	}
	binding, err := outbox.binding()
	if err != nil {
		return fmt.Errorf("%w: invalid outbox generation binding", ErrSignAttemptCorrupt)
	}
	if err := validateCanonicalPresignSlot(record.PresignID, publicContext.ProtocolPresignID); err != nil {
		return err
	}
	if binding != record.Binding || outbox.PresignID != record.PresignID ||
		outbox.AttemptID != record.Intent.AttemptID || outbox.SessionID != record.Intent.SessionID ||
		outbox.Party != publicContext.Party ||
		!bytes.Equal(outbox.IntentDigest, record.Intent.IntentDigest) ||
		!bytes.Equal(outbox.ProtocolPresignID, publicContext.ProtocolPresignID) ||
		!bytes.Equal(outbox.EpochID, publicContext.EpochID) ||
		!bytes.Equal(outbox.SignerSetHash, signAttemptSignerSetHash(publicContext.Signers)) ||
		!bytes.Equal(outbox.ContextHash, publicContext.ContextHash) ||
		!bytes.Equal(outbox.VerificationKey, publicContext.VerificationKey) ||
		!outbox.DeliveryPolicy.Equal(SignAttemptDeliveryPolicy{
			Mode:                 outbox.DeliveryPolicy.Mode,
			Confidentiality:      outbox.DeliveryPolicy.Confidentiality,
			BroadcastConsistency: outbox.DeliveryPolicy.BroadcastConsistency,
			Recipients:           publicContext.Signers,
		}) {
		return fmt.Errorf("%w: lifecycle attempt public binding mismatch", ErrSignAttemptCorrupt)
	}
	if len(record.OutboxDigest) != sha256.Size {
		return fmt.Errorf("%w: invalid durable outbox digest", ErrSignAttemptCorrupt)
	}
	if len(record.ExactOutbox) != 0 {
		digest := sha256.Sum256(record.ExactOutbox)
		if !bytes.Equal(record.OutboxDigest, digest[:]) {
			return fmt.Errorf("%w: durable exact outbox digest mismatch", ErrSignAttemptCorrupt)
		}
	}
	return nil
}

func validateLifecycleRecordPresignSlot(record tssrun.SignAttemptRecord, limits Limits) error {
	if len(record.PresignMetadata) == 0 {
		return fmt.Errorf("%w: missing public presign metadata", ErrSignAttemptCorrupt)
	}
	publicContext, err := unmarshalSignAttemptPublicContext(record.PresignMetadata, limits)
	if err != nil {
		return err
	}
	defer publicContext.destroy()
	return validateCanonicalPresignSlot(record.PresignID, publicContext.ProtocolPresignID)
}

func validateCanonicalPresignSlot(slot string, protocolPresignID []byte) error {
	expected, err := PresignSlotID(protocolPresignID)
	if err != nil {
		return fmt.Errorf("%w: invalid public protocol presign id", ErrSignAttemptCorrupt)
	}
	if slot != expected {
		return fmt.Errorf("%w: lifecycle presign slot does not match public protocol presign id", ErrSignAttemptCorrupt)
	}
	return nil
}

func sameSignAttemptOutboxIdentity(a, b signAttemptOutbox) bool {
	return bytes.Equal(a.IntentDigest, b.IntentDigest) &&
		bytes.Equal(a.CanonicalEnvelopeHash, b.CanonicalEnvelopeHash) &&
		a.SessionID == b.SessionID && a.Party == b.Party &&
		a.PresignID == b.PresignID && a.AttemptID == b.AttemptID
}

// BurnPresign durably burns an available presign without loading its secret
// blob into the caller.
func BurnPresign(ctx context.Context, store tssrun.LifecycleStore, binding tssrun.GenerationBinding, presignID string, protocolPresignID []byte, reason string) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if store == nil {
		return errors.New("nil lifecycle store")
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	if err := validateSignLifecycleIdentifier(presignID); err != nil {
		return err
	}
	if err := validateCanonicalPresignSlot(presignID, protocolPresignID); err != nil {
		return err
	}
	return store.BurnPresign(ctx, binding, presignID, reason)
}
