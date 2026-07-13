package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/tssrun"
)

// Guard returns the session's envelope guard for use by transport adapters.
func (s *SignSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// UpdateDelivery validates local acknowledgement progress and durably records
// only a complete authenticated delivery certificate.
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
	if len(s.outbox.CanonicalEnvelope) == 0 {
		return fmt.Errorf("%w: exact delivery outbox unavailable", ErrSignAttemptCorrupt)
	}
	env, payload, err := decodeSignAttemptEnvelopeWithLimits(s.outbox.CanonicalEnvelope, s.limits)
	if err != nil {
		return err
	}
	defer payload.S.Destroy()
	if s.guard == nil || s.guard.AckVerifier == nil {
		return tss.ErrMissingAckVerifier
	}
	if ack != nil {
		if !s.outbox.DeliveryPolicy.Recipients.Contains(ack.Party) {
			return errors.New("broadcast acknowledgement party is not a delivery recipient")
		}
		if err := tss.VerifyBroadcastAck(env, *ack, s.guard.AckVerifier); err != nil {
			return err
		}
		for i := range s.deliveryAcks {
			if s.deliveryAcks[i].Party != ack.Party {
				continue
			}
			if s.deliveryAcks[i].Equal(*ack) {
				break
			}
			return errors.New("conflicting broadcast acknowledgement")
		}
		if !slices.ContainsFunc(s.deliveryAcks, func(existing tss.BroadcastAck) bool { return existing.Party == ack.Party }) {
			s.deliveryAcks = append(s.deliveryAcks, ack.Clone())
			slices.SortFunc(s.deliveryAcks, compareBroadcastAckParty)
		}
	}
	if certificate == nil {
		return nil
	}
	if err := certificate.VerifyFull(env, s.outbox.DeliveryPolicy.Recipients, s.guard.AckVerifier); err != nil {
		return err
	}
	acks := slices.Clone(certificate.Acks)
	slices.SortFunc(acks, compareBroadcastAckParty)
	canonical, err := tss.NewBroadcastCertificate(env, s.outbox.DeliveryPolicy.Recipients, acks)
	if err != nil {
		return err
	}
	delivery := deliveryForOutbox(s.outbox, canonical)
	rawDelivery, err := marshalSignAttemptDelivery(delivery, s.limits, s.guard.AckVerifier)
	if err != nil {
		return err
	}
	defer clear(rawDelivery)
	updated, err := s.coordinator.markDelivered(ctx, rawDelivery)
	if err != nil {
		return err
	}
	if !sameLifecycleAttemptQuery(s.attempt.Query(), updated.Query()) {
		return fmt.Errorf("%w: delivery update changed attempt identity", ErrSignAttemptCorrupt)
	}
	s.attempt = signSessionAttemptRecord(updated)
	return nil
}

func compareBroadcastAckParty(a, b tss.BroadcastAck) int {
	if a.Party < b.Party {
		return -1
	}
	if a.Party > b.Party {
		return 1
	}
	return 0
}

func signSessionAttemptRecord(record tssrun.SignAttemptRecord) tssrun.SignAttemptRecord {
	clone := record.Clone()
	clear(clone.PresignMetadata)
	clear(clone.ExactOutbox)
	clone.PresignMetadata = nil
	clone.ExactOutbox = nil
	return clone
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *SignSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.sessionID, s.verification.Signers, s.key.state.Party)
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
	defer func() {
		err = bindInboundAuthenticationEvidence(err, env)
		if shouldAbortSession(err) {
			if s.coordinator != nil {
				if abortErr := s.coordinator.abort(s.coordinatorCtx, "terminal online-sign protocol rejection"); abortErr != nil {
					err = errors.Join(err, fmt.Errorf("persist sign attempt abort: %w", abortErr))
				}
			}
			s.abort()
		}
	}()
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
	_, err = s.tryCompleteSign(s.coordinatorCtx)
	if err != nil {
		return nil, err
	}
	return effects.envelopes, nil
}

// Signature returns the completed ECDSA signature.
func (s *SignSession) Signature() (*Signature, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed {
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
	if commitment, ok := normalizedCommitmentForPublicContext(&s.verification, from); ok {
		fields = append(fields,
			hashEvidenceField("delta_tilde_hash", commitment.DeltaTilde),
			hashEvidenceField("s_tilde_hash", commitment.STilde),
		)
		expectedEqHash := partialEquationHash(
			s.sessionID, from, s.verification.TranscriptHash,
			s.verification.ContextHash, s.planHash, s.digest,
			s.verification.LittleR.Bytes(), partialBytes,
			commitment.DeltaTilde, commitment.STilde,
		)
		fields = append(fields,
			rawEvidenceField(evidenceFieldPartialEquationHash, expectedEqHash),
			rawEvidenceField(evidenceFieldObservedPartialEquationHash, p.PartialEquationHash),
		)
	}
	return fields
}

func (s *SignSession) signPartialContextEvidenceFields(rawPayload []byte) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.verification.Signers)...)
	fields = append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.verification.TranscriptHash),
		rawEvidenceField("presign_context_hash", s.verification.ContextHash),
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
	if err != nil || sig == nil {
		return false
	}
	r, err := secp.ScalarFromBytes(sig.R)
	if err != nil {
		return false
	}
	s, err := secp.ScalarFromBytes(sig.S)
	if err != nil || !secp.IsLowS(s) {
		return false
	}
	return secp.VerifyECDSA(public, digest32, r, s)
}

// VerifySignature verifies a context-bound canonical low-S secp256k1 ECDSA signature.
func VerifySignature(publicKey []byte, request SignRequest, sig *Signature) bool {
	if err := validatePresignContext(request.Context); err != nil {
		return false
	}
	contextHash := presignContextHash(request.Context)
	digest := signMessageDigest(contextHash, request.Context.MessageDomain, request.Message)
	return VerifyDigest(publicKey, digest, sig)
}

func (s *SignSession) verifySignPartial(from tss.PartyID, p signPartialPayload) (secp.Scalar, error) {
	if !tss.ContainsParty(s.verification.Signers, from) {
		return secp.Scalar{}, errors.New("sender is not in signer set")
	}
	if !bytes.Equal(p.PresignTranscript, s.verification.TranscriptHash) {
		return secp.Scalar{}, errors.New("presign transcript mismatch")
	}
	if !bytes.Equal(p.PresignContext, s.verification.ContextHash) {
		return secp.Scalar{}, errors.New("presign context mismatch")
	}
	if !bytes.Equal(p.PresignID, s.verification.ProtocolPresignID) || !bytes.Equal(p.EpochID, s.verification.EpochID) {
		return secp.Scalar{}, errors.New("presign or epoch identifier mismatch")
	}
	if err := requirePlanHash("sign", p.PlanHash, s.planHash); err != nil {
		return secp.Scalar{}, err
	}
	expectedDigestHash := digestHash(s.digest, s.verification.ContextHash)
	if !bytes.Equal(p.DigestHash, expectedDigestHash) {
		return secp.Scalar{}, errors.New("digest hash mismatch")
	}
	sVal, err := secpScalarFromSecretAllowZero(p.S)
	if err != nil {
		return secp.Scalar{}, err
	}
	commitment, ok := normalizedCommitmentForPublicContext(&s.verification, from)
	if !ok {
		return secp.Scalar{}, fmt.Errorf("missing normalized commitment for party %d", from)
	}
	littleR := s.verification.LittleR
	partialBytes := p.S.FixedBytes()
	defer clear(partialBytes)
	expectedEqHash := partialEquationHash(
		s.sessionID, from, s.verification.TranscriptHash,
		s.verification.ContextHash, s.planHash, s.digest,
		littleR.Bytes(), partialBytes,
		commitment.DeltaTilde, commitment.STilde,
	)
	if !bytes.Equal(p.PartialEquationHash, expectedEqHash) {
		return secp.Scalar{}, errors.New("partial equation hash mismatch")
	}
	zScalar, err := secp.ScalarFromBytesModOrder(s.digest)
	if err != nil {
		return secp.Scalar{}, err
	}
	if err := verifyFigure10Partial(s.verification.Gamma, commitment, zScalar, littleR, sVal); err != nil {
		return secp.Scalar{}, err
	}
	return sVal, nil
}

func digestHash(digest32, contextHash []byte) []byte {
	t := transcript.New("cggmp21-secp256k1-sign-digest-binding")
	t.AppendBytes("context_hash", contextHash)
	t.AppendBytes("digest", digest32)
	return t.Sum()
}

func partialEquationHash(sessionID tss.SessionID, party tss.PartyID, presignTranscriptHash, contextHash, planHash, digestHash, littleR, sigma, deltaTilde, sTilde []byte) []byte {
	t := transcript.New("cggmp21-secp256k1-sign-partial-equation")
	t.AppendBytes("session_id", sessionID[:])
	t.AppendUint32("party", party)
	t.AppendBytes("presign_transcript_hash", presignTranscriptHash)
	t.AppendBytes("context_hash", contextHash)
	t.AppendBytes("plan_hash", planHash)
	t.AppendBytes("digest_hash", digestHash)
	t.AppendBytes("little_r", littleR)
	t.AppendBytes("sigma", sigma)
	t.AppendBytes("delta_tilde", deltaTilde)
	t.AppendBytes("s_tilde", sTilde)
	return t.Sum()
}
