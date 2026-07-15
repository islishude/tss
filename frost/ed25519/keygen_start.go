package ed25519

import (
	"bytes"
	"errors"
	"io"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
)

// StartKeygen starts dealerless DKG from a shared immutable lifecycle plan.
func StartKeygen(plan *KeygenPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	cfg, limits, planHash, err := resolveFROSTKeygenStart(plan, local, guard)
	if err != nil {
		return nil, nil, err
	}
	material, err := generateFROSTKeygenLocalMaterial(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := prepareFROSTKeygenProof(cfg, planHash, material); err != nil {
		material.Destroy()
		return nil, nil, err
	}
	session, err := newFROSTKeygenSession(cfg, limits, planHash, guard, material, nil)
	if err != nil {
		material.Destroy()
		return nil, nil, err
	}
	out, err := emitFROSTKeygenRound1(session, material)
	if err != nil {
		session.abort()
		return nil, nil, err
	}
	more, err := session.tryAdvance()
	if err != nil {
		clearEnvelopePayloads(out)
		session.abort()
		return nil, nil, err
	}
	out = append(out, more...)
	return session, out, nil
}

func resolveFROSTKeygenStart(plan *KeygenPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (tss.ThresholdConfig, Limits, []byte, error) {
	cfg, err := plan.thresholdConfig(local)
	if err != nil {
		return tss.ThresholdConfig{}, Limits{}, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	limits := plan.limits
	if err := cfg.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return tss.ThresholdConfig{}, Limits{}, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, cfg.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return tss.ThresholdConfig{}, Limits{}, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, cfg.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolFROSTEd25519, cfg.SessionID, cfg.Self); err != nil {
		return tss.ThresholdConfig{}, Limits{}, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, cfg.Self, err)
	}
	cfg.Parties = cfg.SortedParties()
	return cfg, limits, planHash, nil
}

func generateFROSTKeygenLocalMaterial(cfg tss.ThresholdConfig) (*frostKeygenLocalMaterial, error) {
	return generateFROSTKeygenLocalMaterialWithContribution(cfg, nil, nil)
}

func generateFROSTKeygenLocalMaterialWithContribution(cfg tss.ThresholdConfig, constant *fed.Scalar, chainCode []byte) (*frostKeygenLocalMaterial, error) {
	material := new(frostKeygenLocalMaterial)
	ok := false
	defer func() {
		if !ok {
			material.Destroy()
		}
	}()
	poly, err := randomScalarPolynomial(cfg.Reader(), cfg.Threshold, constant)
	if err != nil {
		return nil, err
	}
	material.polynomial = poly
	points := make([]*fed.Point, len(poly))
	for i, coeff := range poly {
		points[i] = fed.NewIdentityPoint().ScalarBaseMult(coeff)
	}
	commitments, err := newKeygenCommitmentsFromPoints(points, cfg.Threshold)
	if err != nil {
		return nil, err
	}
	material.commitments = &commitments
	if chainCode == nil {
		material.chainCode = make([]byte, 32)
		if _, err := io.ReadFull(cfg.Reader(), material.chainCode); err != nil {
			return nil, err
		}
	} else {
		if len(chainCode) != 32 {
			return nil, errors.New("trusted-dealer chain code contribution must be 32 bytes")
		}
		material.chainCode = bytes.Clone(chainCode)
	}
	material.chainCodeCommit = bip32util.ChainCodeCommitment(
		frostChainCodeCommitLabel,
		cfg.SessionID,
		cfg.Self,
		material.chainCode,
	)
	localShare := evalScalarPolynomial(poly, cfg.Self)
	material.localShare, err = newEdSecretScalarFromFed(localShare)
	localShare.Set(fed.NewScalar())
	if err != nil {
		return nil, err
	}
	ok = true
	return material, nil
}

func newFROSTKeygenSession(cfg tss.ThresholdConfig, limits Limits, planHash []byte, guard *tss.EnvelopeGuard, local *frostKeygenLocalMaterial, importPlan *TrustedDealerImportPlan) (*KeygenSession, error) {
	if local == nil || local.commitments == nil || local.localShare == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, cfg.Self, errMissingKeygenLocalMaterial)
	}
	round1 := newFROSTKeygenRound1Inbox(cfg.Parties)
	if local.proof == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, cfg.Self, errors.New("missing local keygen constant-term proof"))
	}
	if err := round1.recordLocalFor(cfg.Self, *local.commitments, local.proof, local.localShare, local.chainCodeCommit); err != nil {
		return nil, err
	}
	return &KeygenSession{
		cfg:                  cfg,
		limits:               limits,
		planHash:             bytes.Clone(planHash),
		importPlan:           cloneFROSTTrustedDealerPlan(importPlan),
		guard:                guard,
		local:                local,
		round1:               round1,
		confirmations:        newFROSTKeygenConfirmationInbox(cfg.Parties),
		pendingConfirmations: make(map[tss.PartyID]*KeygenConfirmation),
		state:                keygenCollectingCommitments,
	}, nil
}

func emitFROSTKeygenRound1(s *KeygenSession, local *frostKeygenLocalMaterial) (out []tss.Envelope, err error) {
	defer func() {
		if err != nil {
			clearEnvelopePayloads(out)
		}
	}()
	commitPayload, err := marshalKeygenCommitmentsPayloadWithLimits(keygenCommitmentsPayload{
		Commitments:     local.commitments.Clone(),
		ChainCodeCommit: bytes.Clone(local.chainCodeCommit),
		PlanHash:        bytes.Clone(s.planHash),
		Proof:           local.proof.Clone(),
	}, s.limits)
	if err != nil {
		return nil, err
	}
	commitEnv, err := newEnvelope(s.cfg, keygenCommitmentRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenCommitments, commitPayload)
	clear(commitPayload)
	if err != nil {
		return nil, err
	}
	out = append(out, commitEnv)
	local.ownMessages = tss.CloneSlice(out)
	return out, nil
}

func emitFROSTKeygenRound2(s *KeygenSession, local *frostKeygenLocalMaterial) (out []tss.Envelope, err error) {
	if local == nil || local.polynomial == nil {
		return nil, errors.New("missing local polynomial for keygen share round")
	}
	defer func() {
		if err != nil {
			clearEnvelopePayloads(out)
		}
	}()
	for _, id := range s.cfg.Parties {
		if id == s.cfg.Self {
			continue
		}
		share := evalScalarPolynomial(local.polynomial, id)
		secretShare, convertErr := newEdSecretScalarFromFed(share)
		share.Set(fed.NewScalar())
		if convertErr != nil {
			return nil, convertErr
		}
		payload, marshalErr := marshalKeygenSharePayloadWithLimits(keygenSharePayload{
			Share:    secretShare,
			PlanHash: bytes.Clone(s.planHash),
		}, s.limits)
		secretShare.Destroy()
		if marshalErr != nil {
			return nil, marshalErr
		}
		env, envelopeErr := newEnvelope(s.cfg, keygenShareRound, s.cfg.Self, id, payloadKeygenShare, payload)
		clear(payload)
		if envelopeErr != nil {
			return nil, envelopeErr
		}
		out = append(out, env)
	}
	local.ownMessages = append(local.ownMessages, tss.CloneSlice(out)...)
	return out, nil
}

var errMissingKeygenLocalMaterial = errors.New("missing keygen local material")
