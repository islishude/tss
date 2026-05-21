package secp256k1

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
)

type KeygenSession struct {
	cfg       tss.ThresholdConfig
	commits   map[tss.PartyID][][]byte
	shares    map[tss.PartyID]*big.Int
	completed bool
	keyShare  *KeyShare
}

type keygenCommitmentsPayload struct {
	Commitments [][]byte `json:"commitments"`
}

type keygenSharePayload struct {
	Share []byte `json:"share"`
}

func StartKeygen(config tss.ThresholdConfig) (*KeygenSession, []tss.Envelope, error) {
	if err := config.Validate(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	parties := config.SortedParties()
	config.Parties = parties
	poly, err := shamir.RandomPolynomial(config.Reader(), secp.Order(), config.Threshold, nil)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point := secp.ScalarBaseMult(coeff)
		enc, err := secp.PointBytes(point)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	s := &KeygenSession{
		cfg:     config,
		commits: map[tss.PartyID][][]byte{config.Self: commitments},
		shares:  map[tss.PartyID]*big.Int{config.Self: shamir.Eval(poly, config.Self, secp.Order())},
	}
	out := make([]tss.Envelope, 0, len(parties))
	commitPayload, err := json.Marshal(keygenCommitmentsPayload{Commitments: commitments})
	if err != nil {
		return nil, nil, err
	}
	out = append(out, envelope(config, 1, config.Self, 0, payloadKeygenCommitments, commitPayload, false))
	for _, id := range parties {
		if id == config.Self {
			continue
		}
		share := shamir.Eval(poly, id, secp.Order())
		payload, err := json.Marshal(keygenSharePayload{Share: scalarBytes(share)})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(config, 1, config.Self, id, payloadKeygenShare, payload, true))
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

func (s *KeygenSession) HandleKeygenMessage(env tss.Envelope) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
	if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.cfg.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if env.To != 0 && env.To != s.cfg.Self {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadKeygenCommitments:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate commitments"))
		}
		var p keygenCommitmentsPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		s.commits[env.From] = p.Commitments
	case payloadKeygenShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate share"))
		}
		var p keygenSharePayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		share, err := secp.ParseScalar(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		s.shares[env.From] = share
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return nil, s.tryComplete()
}

func (s *KeygenSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.keyShare, true
}

func (s *KeygenSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.cfg.Parties) || len(s.shares) != len(s.cfg.Parties) {
		return nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.cfg.Self), share); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: &tss.Blame{Reason: "invalid DKG share", Parties: []tss.PartyID{dealer}},
				Err:   err,
			}
		}
	}
	secret := new(big.Int)
	for _, dealer := range s.cfg.Parties {
		secret.Add(secret, s.shares[dealer])
		secret.Mod(secret, order)
	}
	groupCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*secp.Point, 0, len(s.cfg.Parties))
		for _, dealer := range s.cfg.Parties {
			p, err := secp.PointFromBytes(s.commits[dealer][degree])
			if err != nil {
				return err
			}
			points = append(points, p)
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return err
		}
		groupCommitments[degree] = enc
	}
	verificationShares := make([]VerificationShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		pub, err := secp.EvalCommitments(groupCommitments, uint32(id))
		if err != nil {
			return err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	s.keyShare = &KeyShare{
		Version:            tss.Version,
		Party:              s.cfg.Self,
		Threshold:          s.cfg.Threshold,
		Parties:            append([]tss.PartyID(nil), s.cfg.Parties...),
		PublicKey:          append([]byte(nil), groupCommitments[0]...),
		Secret:             scalarBytes(secret),
		GroupCommitments:   groupCommitments,
		VerificationShares: verificationShares,
		SecurityNotice:     ExperimentalSecurityNotice,
	}
	s.completed = true
	return s.keyShare.Validate()
}

func validateCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for _, commitment := range commitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return err
		}
	}
	return nil
}
