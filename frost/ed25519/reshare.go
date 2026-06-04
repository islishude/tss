package ed25519

import (
	"errors"
	"fmt"
	"math/big"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/shamir"
)

const (
	payloadReshareCommitments = "frost.ed25519.reshare.commitments"
	payloadReshareShare       = "frost.ed25519.reshare.share"
)

// ReshareSession tracks FROST key resharing for threshold or participant-set changes.
// The group public key is preserved because every participant generates a
// polynomial with zero constant term.
type ReshareSession struct {
	oldKey     *KeyShare
	cfg        tss.ThresholdConfig
	log        tss.Logger
	newParties []tss.PartyID
	commits    map[tss.PartyID][][]byte
	shares     map[tss.PartyID]*big.Int
	completed  bool
	aborted    bool
	newShare   *KeyShare
	ownPoly    []*big.Int
}

type reshareCommitmentsPayload struct {
	Commitments [][]byte `json:"commitments"`
}

type reshareSharePayload struct {
	Share []byte `json:"share"`
}

// StartReshare starts FROST resharing. The group public key is preserved.
// newParties defines the target participant set; it may differ in size and
// identity from the current participant set.
func StartReshare(oldKey *KeyShare, config tss.ThresholdConfig, newParties []tss.PartyID) (*ReshareSession, []tss.Envelope, error) {
	if err := oldKey.Validate(); err != nil {
		return nil, nil, err
	}
	if err := config.ValidateWithLimits(tss.DefaultLimitsForAlgorithm(tss.AlgorithmFROSTEd25519)); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	newParties = tss.SortParties(newParties)
	if !tss.ContainsParty(newParties, oldKey.Party) {
		return nil, nil, errors.New("local party must be in the new participant set")
	}
	config.Parties = append([]tss.PartyID(nil), oldKey.Parties...)
	// Zero-coefficient polynomial preserves the group secret.
	poly, err := shamir.RandomPolynomial(config.Reader(), edcurve.Order(), config.Threshold, big.NewInt(0))
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point, err := edcurve.ScalarBaseMultBig(coeff)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = point.Bytes()
	}
	s := &ReshareSession{
		oldKey:     oldKey,
		cfg:        config,
		log:        config.Logger(),
		newParties: newParties,
		commits:    map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:     map[tss.PartyID]*big.Int{oldKey.Party: shamir.Eval(poly, oldKey.Party, edcurve.Order())},
		ownPoly:    poly,
	}
	commitPayload, err := marshalReshareCommitmentsPayload(reshareCommitmentsPayload{Commitments: commitments})
	if err != nil {
		return nil, nil, err
	}
	out := []tss.Envelope{envelope(config, 1, oldKey.Party, 0, payloadReshareCommitments, commitPayload, false)}
	for _, id := range newParties {
		if id == oldKey.Party {
			continue
		}
		share := shamir.Eval(poly, id, edcurve.Order())
		shareBytes, err := scalarBytes(share)
		if err != nil {
			return nil, nil, err
		}
		payload, err := marshalReshareSharePayload(reshareSharePayload{Share: shareBytes})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(config, 1, oldKey.Party, id, payloadReshareShare, payload, true))
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

// HandleReshareMessage validates and applies one reshare envelope.
func (s *ReshareSession) HandleReshareMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	if s.completed {
		return nil, errors.New("reshare session is already completed")
	}
	if s.aborted {
		return nil, errors.New("reshare session is aborted")
	}
	if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.oldKey.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare only accepts round 1 messages"))
	}
	if env.To != 0 && env.To != s.oldKey.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	switch env.PayloadType {
	case payloadReshareCommitments:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare commitments"))
		}
		p, err := unmarshalReshareCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateReshareCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		s.commits[env.From] = p.Commitments
	case payloadReshareShare:
		if err := requireDirectConfidential(env, s.oldKey.Party, payloadReshareShare); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare share"))
		}
		p, err := unmarshalReshareSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		scalar, err := edcurve.ScalarFromCanonical(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		s.shares[env.From] = edcurve.ScalarToBig(scalar)
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return nil, s.tryComplete()
}

// KeyShare returns the reshared key share when resharing completes.
func (s *ReshareSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return cloneKeyShareValue(s.newShare), true
}

func (s *ReshareSession) tryComplete() error {
	if s.completed {
		return nil
	}
	// Wait for all old participants (they are the dealers) to contribute.
	if len(s.commits) != len(s.oldKey.Parties) || len(s.shares) != len(s.oldKey.Parties) {
		return nil
	}
	order := edcurve.Order()
	for dealer, share := range s.shares {
		if err := edcurve.VerifyShare(s.commits[dealer], uint32(s.oldKey.Party), share); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: frostReshareBlame(s.cfg, dealer, s.commits[dealer]),
				Err:   err,
			}
		}
	}
	oldSecret, err := s.oldKey.secretBig()
	if err != nil {
		return err
	}
	// new_secret = old_secret + sum_i f_i(self)  (mod order).
	// Since each f_i(0) = 0, the aggregated polynomial preserves the group secret.
	newSecret := new(big.Int).Set(oldSecret)
	for _, dealer := range s.oldKey.Parties {
		newSecret.Add(newSecret, s.shares[dealer])
		newSecret.Mod(newSecret, order)
	}
	newSecretBytes, err := scalarBytes(newSecret)
	if err != nil {
		return err
	}
	// New group commitments: sum of all dealers' commitments per degree.
	newCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*fed.Point, 0, len(s.oldKey.Parties))
		for _, dealer := range s.oldKey.Parties {
			p, err := edcurve.PointFromBytesAllowIdentity(s.commits[dealer][degree])
			if err != nil {
				return err
			}
			points = append(points, p)
		}
		// The old group commitments contribute the existing key share.
		if degree < len(s.oldKey.GroupCommitments) {
			oldCommitment, err := edcurve.PointFromBytesAllowIdentity(s.oldKey.GroupCommitments[degree])
			if err != nil {
				return err
			}
			points = append(points, oldCommitment)
		}
		newCommitments[degree] = edcurve.AddPoints(points...).Bytes()
	}
	if _, err := edcurve.PointFromBytes(newCommitments[0]); err != nil {
		return fmt.Errorf("invalid reshared group public key: %w", err)
	}
	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := edcurve.EvalCommitments(newCommitments, uint32(id))
		if err != nil {
			return err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub})
	}
	reshareTranscriptHash := keygenDomain(s.cfg.SessionID, s.cfg.Threshold, s.cfg.Parties, s.oldKey.Party, newCommitments[0])
	s.newShare = &KeyShare{
		Version:              tss.Version,
		Party:                s.oldKey.Party,
		Threshold:            s.cfg.Threshold,
		Parties:              append([]tss.PartyID(nil), s.newParties...),
		PublicKey:            append([]byte(nil), newCommitments[0]...),
		ChainCode:            append([]byte(nil), s.oldKey.ChainCode...),
		secret:               newSecretBytes,
		GroupCommitments:     newCommitments,
		VerificationShares:   verificationShares,
		KeygenTranscriptHash: reshareTranscriptHash,
	}
	s.completed = true
	s.log.Info(s.cfg.Ctx(), "reshare complete",
		"party_id", s.oldKey.Party,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return s.newShare.Validate()
}

func validateReshareCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for _, commitment := range commitments {
		if _, err := edcurve.PointFromBytesAllowIdentity(commitment); err != nil {
			return err
		}
	}
	return nil
}
