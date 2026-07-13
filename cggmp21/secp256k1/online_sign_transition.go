package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/tssrun"
)

type signPartial struct {
	scalar   secp.Scalar
	envelope tss.Envelope
}

type acceptSignPartialTx struct {
	from      tss.PartyID
	partial   signPartial
	committed bool
}

//nolint:unparam // All transition apply methods return sessionEffects; this transition intentionally emits none.
func (tx *acceptSignPartialTx) apply(s *SignSession) (sessionEffects, error) {
	if tx == nil {
		return sessionEffects{}, errors.New("nil sign partial transition")
	}
	if s == nil {
		return sessionEffects{}, errors.New("nil sign session")
	}
	s.partials[tx.from] = tx.partial.scalar
	if s.partialEnvelopes == nil {
		s.partialEnvelopes = make(map[tss.PartyID]tss.Envelope, len(s.verification.Signers))
	}
	s.partialEnvelopes[tx.from] = tx.partial.envelope.Clone()
	return sessionEffects{}, nil
}

func (*acceptSignPartialTx) cleanupOnReject() {}

func (tx *acceptSignPartialTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

func (s *SignSession) buildAcceptSignPartialTx(env tss.InboundEnvelope) (*acceptSignPartialTx, error) {
	base := env.Envelope()
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	if !tss.ContainsParty(s.verification.Signers, base.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("sender is not in signer set"))
	}
	if base.Round != signStartRound || base.PayloadType != payloadSignPartial {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("expected round 1 sign partial"))
	}
	if _, ok := s.partials[base.From]; ok {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, errors.New("duplicate sign partial"))
	}
	payload := base.Payload
	p, err := tss.DecodeBinaryValueWithLimits[signPartialPayload](payload, s.limits)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			base,
			tss.EvidenceKindSignPartial,
			"malformed sign partial payload",
			tss.NewPartySet(base.From),
			err,
			s.signPartialContextEvidenceFields(payload)...,
		)
	}
	defer p.S.Destroy()
	partial, err := s.verifySignPartial(base.From, p)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeVerification,
			base,
			tss.EvidenceKindSignPartial,
			"sign partial verification failed",
			tss.NewPartySet(base.From),
			err,
			s.signPartialEvidenceFields(base.From, p)...,
		)
	}
	return &acceptSignPartialTx{
		from: base.From,
		partial: signPartial{
			scalar:   partial,
			envelope: base.Clone(),
		},
	}, nil
}

type preparedFinalSignature struct {
	signature Signature
	committed bool
}

func (p *preparedFinalSignature) destroy() {
	if p == nil || p.committed {
		return
	}
	clear(p.signature.R)
	clear(p.signature.S)
	p.signature = Signature{}
}

func (s *SignSession) prepareFinalSignature() (*preparedFinalSignature, bool, error) {
	if s == nil {
		return nil, false, errors.New("nil sign session")
	}
	if s.completed || len(s.partials) != len(s.verification.Signers) {
		return nil, false, nil
	}
	sigS := secp.ScalarZero()
	for _, id := range s.verification.Signers {
		partial, ok := s.partials[id]
		if !ok {
			return nil, false, nil
		}
		sigS = secp.ScalarAdd(sigS, partial)
	}
	if sigS.IsZero() {
		return nil, false, errors.New("zero ECDSA s")
	}
	normalizedS, sWasNegated := secp.NormalizeLowS(sigS)
	rPointBytes, err := secp.PointBytes(s.verification.Gamma)
	if err != nil {
		return nil, false, err
	}
	recoveryID, err := recoveryIDFromPresignR(rPointBytes, sWasNegated)
	if err != nil {
		return nil, false, err
	}
	r := s.verification.LittleR
	public, err := secp.PointFromBytes(s.publicKey)
	if err != nil {
		return nil, false, err
	}
	if !secp.VerifyECDSA(public, s.digest, r, normalizedS) {
		return nil, false, errors.New("all Figure 10 partials verified but aggregate ECDSA signature verification failed")
	}
	return &preparedFinalSignature{
		signature: Signature{
			R:          r.Bytes(),
			S:          normalizedS.Bytes(),
			RecoveryID: recoveryID,
		},
	}, true, nil
}

func (s *SignSession) commitFinalSignature(ctx context.Context, prepared *preparedFinalSignature, completed tssrun.SignAttemptRecord) {
	s.attempt = completed.Clone()
	clear(s.attempt.PresignMetadata)
	clear(s.attempt.ExactOutbox)
	s.attempt.PresignMetadata = nil
	s.attempt.ExactOutbox = nil
	s.signature = &Signature{
		R:          slices.Clone(prepared.signature.R),
		S:          slices.Clone(prepared.signature.S),
		RecoveryID: prepared.signature.RecoveryID,
	}
	s.completed = true
	prepared.committed = true
	s.log.Info(ctx, "signing complete",
		"party_id", s.key.state.Party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	if s.ownsKey && s.key != nil {
		s.key.Destroy()
		s.key = nil
		s.ownsKey = false
	}
}

//nolint:unparam // the envelope result is retained for the session transition contract; completion currently emits no wire effect.
func (s *SignSession) tryCompleteSign(ctx context.Context) ([]tss.Envelope, error) {
	prepared, ready, err := s.prepareFinalSignature()
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, nil
	}
	defer prepared.destroy()
	if s.coordinator == nil {
		return nil, errors.New("sign attempt coordinator unavailable during completion")
	}
	completed, err := s.coordinator.complete(ctx, prepared.signature)
	if err != nil {
		return nil, err
	}
	completion, err := unmarshalSignAttemptCompletion(completed.Completion, s.limits)
	if err != nil {
		return nil, err
	}
	if !sameLifecycleAttemptQuery(s.attempt.Query(), completed.Query()) ||
		!bytes.Equal(completion.IntentDigest, completed.Intent.IntentDigest) ||
		!bytes.Equal(completion.SignatureR, prepared.signature.R) ||
		!bytes.Equal(completion.SignatureS, prepared.signature.S) ||
		completion.RecoveryID != prepared.signature.RecoveryID {
		return nil, fmt.Errorf("%w: completion record mismatch", ErrSignAttemptCorrupt)
	}
	s.commitFinalSignature(ctx, prepared, completed)
	return nil, nil
}
