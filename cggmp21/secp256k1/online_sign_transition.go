package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
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

func (tx *acceptSignPartialTx) apply(s *SignSession) (sessionEffects, error) {
	if tx == nil {
		return sessionEffects{}, errors.New("nil sign partial transition")
	}
	if s == nil {
		return sessionEffects{}, errors.New("nil sign session")
	}
	s.partials[tx.from] = tx.partial.scalar
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
	if !tss.ContainsParty(s.presign.state.signers, base.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("sender is not in signer set"))
	}
	if base.Round != 1 || base.PayloadType != payloadSignPartial {
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
	if s.completed || len(s.partials) != len(s.presign.state.signers) {
		return nil, false, nil
	}
	sigS := secp.ScalarZero()
	for _, id := range s.presign.state.signers {
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
	rPointBytes, err := secp.PointBytes(s.presign.state.r)
	if err != nil {
		return nil, false, err
	}
	recoveryID, err := recoveryIDFromPresignR(rPointBytes, sWasNegated)
	if err != nil {
		return nil, false, err
	}
	r := s.presign.state.littleR
	public, err := secp.PointFromBytes(s.publicKey)
	if err != nil {
		return nil, false, err
	}
	if !secp.VerifyECDSA(public, s.digest, r, normalizedS) {
		return nil, false, &tss.ProtocolError{
			Code:  tss.ErrCodeInvariant,
			Round: 1,
			Err:   errors.New("all partials individually verified but aggregate ECDSA signature verification failed"),
		}
	}
	return &preparedFinalSignature{
		signature: Signature{
			R:          r.Bytes(),
			S:          normalizedS.Bytes(),
			RecoveryID: recoveryID,
		},
	}, true, nil
}

func (s *SignSession) commitFinalSignature(ctx context.Context, prepared *preparedFinalSignature, completed SignAttemptRecord) {
	s.attempt = completed.Clone()
	s.signature = &Signature{
		R:          slices.Clone(prepared.signature.R),
		S:          slices.Clone(prepared.signature.S),
		RecoveryID: prepared.signature.RecoveryID,
	}
	s.completed = true
	prepared.committed = true
	s.log.Info(ctx, "signing complete",
		"party_id", s.key.state.party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
}

func (s *SignSession) tryCompleteSign(ctx context.Context) error {
	prepared, ready, err := s.prepareFinalSignature()
	if err != nil || !ready {
		return err
	}
	defer prepared.destroy()
	if s.coordinator == nil {
		return errors.New("sign attempt coordinator unavailable during completion")
	}
	completed, err := s.coordinator.complete(ctx, prepared.signature)
	if err != nil {
		return err
	}
	if !s.attempt.SameAttempt(completed) ||
		!bytes.Equal(completed.SignatureR, prepared.signature.R) ||
		!bytes.Equal(completed.SignatureS, prepared.signature.S) ||
		completed.SignatureRecoveryID != prepared.signature.RecoveryID {
		return fmt.Errorf("%w: completion record mismatch", ErrSignAttemptCorrupt)
	}
	s.commitFinalSignature(ctx, prepared, completed)
	return nil
}
