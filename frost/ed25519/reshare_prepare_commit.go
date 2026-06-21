package ed25519

import (
	"bytes"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type preparedReshareDealerStart struct {
	session   *ReshareSession
	out       []tss.Envelope
	committed bool
}

func (p *preparedReshareDealerStart) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.session != nil {
		p.session.abort()
		if p.session.newShare != nil {
			p.session.newShare.Destroy()
			p.session.newShare = nil
		}
	}
	clearEnvelopePayloads(p.out)
}

func (p *preparedReshareDealerStart) markCommitted() {
	if p != nil {
		p.committed = true
	}
}

func prepareReshareDealerStart(
	oldKey *KeyShare,
	config tss.ThresholdConfig,
	limits Limits,
	planHash []byte,
	oldParties tss.PartySet,
	newParties tss.PartySet,
	newThreshold int,
	mode frostReshareMode,
	role frostReshareRole,
	constant *fed.Scalar,
	guard *tss.EnvelopeGuard,
) (*preparedReshareDealerStart, error) {
	poly, err := randomScalarPolynomial(config.Reader(), newThreshold, constant)
	if err != nil {
		return nil, err
	}
	defer clearScalars(poly)

	commitmentPoints := make([]*fed.Point, len(poly))
	for i, coeff := range poly {
		commitmentPoints[i] = fed.NewIdentityPoint().ScalarBaseMult(coeff)
	}
	commitments, err := newReshareCommitmentsFromPoints(commitmentPoints, newThreshold)
	if err != nil {
		return nil, err
	}

	session := &ReshareSession{
		oldKey:       oldKey,
		oldPublicKey: oldKey.state.publicKey.Clone(),
		chainCode:    bytes.Clone(oldKey.state.chainCode),
		oldParties:   oldParties.Clone(),
		newParties:   newParties.Clone(),
		newThreshold: newThreshold,
		selfID:       oldKey.state.party,
		mode:         mode,
		role:         role,
		cfg:          config,
		log:          config.Logger(),
		limits:       limits,
		planHash:     bytes.Clone(planHash),
		commits:      map[tss.PartyID]reshareCommitments{oldKey.state.party: commitments.Clone()},
		shares:       make(map[tss.PartyID]*secret.Scalar),
		guard:        guard,
	}
	prepared := &preparedReshareDealerStart{session: session}
	defer func() {
		if err != nil {
			prepared.destroy()
		}
	}()

	if session.requiresInboundShares() {
		ownShare := evalScalarPolynomial(poly, oldKey.state.party)
		ownSecretShare, shareErr := newEdSecretScalarFromFed(ownShare)
		ownShare.Set(fed.NewScalar())
		if shareErr != nil {
			err = shareErr
			return nil, err
		}
		session.shares[oldKey.state.party] = ownSecretShare
	}

	commitPayload, err := marshalReshareCommitmentsPayloadWithLimits(reshareCommitmentsPayload{
		Commitments: commitments.Clone(),
		PlanHash:    planHash,
	}, limits)
	if err != nil {
		return nil, err
	}
	commitEnv, err := newEnvelope(config, 1, oldKey.state.party, tss.BroadcastPartyId, payloadReshareCommitments, commitPayload)
	clear(commitPayload)
	if err != nil {
		return nil, err
	}
	prepared.out = append(prepared.out, commitEnv)

	if session.requiresOutboundShares() {
		for _, id := range newParties {
			if id == oldKey.state.party {
				continue
			}
			share := evalScalarPolynomial(poly, id)
			secretShare, shareErr := newEdSecretScalarFromFed(share)
			share.Set(fed.NewScalar())
			if shareErr != nil {
				err = shareErr
				return nil, err
			}
			payload, marshalErr := marshalReshareSharePayloadWithLimits(
				reshareSharePayload{Share: secretShare, PlanHash: planHash},
				limits,
			)
			secretShare.Destroy()
			if marshalErr != nil {
				err = marshalErr
				return nil, err
			}
			shareEnv, envelopeErr := newEnvelope(config, 1, oldKey.state.party, id, payloadReshareShare, payload)
			clear(payload)
			if envelopeErr != nil {
				err = envelopeErr
				return nil, err
			}
			prepared.out = append(prepared.out, shareEnv)
		}
	}
	if err = session.tryComplete(); err != nil {
		return nil, err
	}
	return prepared, nil
}
