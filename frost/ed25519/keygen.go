package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// KeygenSession tracks dealerless FROST DKG state for one local party.
type KeygenSession struct {
	mu          sync.Mutex
	cfg         tss.ThresholdConfig
	log         tss.Logger
	commits     map[tss.PartyID][][]byte
	shares      map[tss.PartyID]edcurve.Scalar
	chainCodes  map[tss.PartyID][]byte
	completed   bool
	aborted     bool
	keyShare    *KeyShare
	ownPoly     []edcurve.Scalar
	ownMessages []tss.Envelope
}

type keygenCommitmentsPayload struct {
	Commitments [][]byte `json:"commitments"`
	ChainCode   []byte   `json:"chain_code,omitempty"`
}

type keygenSharePayload struct {
	Share []byte `json:"share"`
}

// StartKeygen starts dealerless DKG and returns outbound round-one envelopes.
func StartKeygen(config tss.ThresholdConfig) (*KeygenSession, []tss.Envelope, error) {
	return StartKeygenWithOptions(config, KeygenOptions{})
}

// StartKeygenWithOptions starts dealerless DKG with optional HD chain code generation.
func StartKeygenWithOptions(config tss.ThresholdConfig, opts KeygenOptions) (*KeygenSession, []tss.Envelope, error) {
	if err := config.ValidateWithLimits(tss.DefaultLimitsForAlgorithm(tss.AlgorithmFROSTEd25519)); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	parties := config.SortedParties()
	config.Parties = parties
	poly, err := randomScalarPolynomial(config.Reader(), config.Threshold, nil)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		// Each coefficient commitment lets receivers validate their private share.
		point, err := edcurve.ScalarBaseMult(coeff)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = point.Bytes()
	}
	var chainCode []byte
	if opts.EnableHD {
		chainCode = make([]byte, 32)
		if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
			return nil, nil, err
		}
	}
	s := &KeygenSession{
		cfg:     config,
		log:     config.Logger(),
		commits: map[tss.PartyID][][]byte{config.Self: commitments},
		shares:  map[tss.PartyID]edcurve.Scalar{config.Self: evalScalarPolynomial(poly, config.Self)},
		chainCodes: map[tss.PartyID][]byte{
			config.Self: append([]byte(nil), chainCode...),
		},
		ownPoly: poly,
	}

	out := make([]tss.Envelope, 0, len(parties))
	commitPayload, err := marshalKeygenCommitmentsPayload(keygenCommitmentsPayload{Commitments: commitments, ChainCode: chainCode})
	if err != nil {
		return nil, nil, err
	}
	out = append(out, envelope(config, 1, config.Self, 0, payloadKeygenCommitments, commitPayload, false))
	for _, id := range parties {
		if id == config.Self {
			continue
		}
		share := evalScalarPolynomial(poly, id)
		shareBytes := share.Bytes()
		payload, err := marshalKeygenSharePayload(keygenSharePayload{Share: shareBytes})
		if err != nil {
			return nil, nil, err
		}
		// Shamir shares are secret-bearing and must be delivered over a confidential transport.
		out = append(out, envelope(config, 1, config.Self, id, payloadKeygenShare, payload, true))
	}
	s.ownMessages = append([]tss.Envelope(nil), out...)
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

// HandleKeygenMessage validates and applies one DKG envelope.
func (s *KeygenSession) HandleKeygenMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.aborted = true
		}
	}()
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
		p, err := unmarshalKeygenCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		if existing, ok := s.commits[env.From]; ok {
			if equalByteSlices(existing, p.Commitments) && bytes.Equal(s.chainCodes[env.From], p.ChainCode) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting commitments"))
		}
		s.commits[env.From] = p.Commitments
		if len(p.ChainCode) != 0 && len(p.ChainCode) != 32 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("chain code must be 32 bytes, got %d", len(p.ChainCode)))
		}
		s.chainCodes[env.From] = append([]byte(nil), p.ChainCode...)
	case payloadKeygenShare:
		if err := requireDirectConfidential(env, s.cfg.Self, payloadKeygenShare); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		p, err := unmarshalKeygenSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		scalar, err := edcurve.ScalarFromCanonicalFiat(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if existing, ok := s.shares[env.From]; ok {
			if edcurve.ScalarEqual(existing, scalar) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting share"))
		}
		s.shares[env.From] = scalar
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return nil, s.tryComplete()
}

// KeyShare returns the completed local key share when DKG has finished.
func (s *KeygenSession) KeyShare() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed {
		return nil, false
	}
	return cloneKeyShareValue(s.keyShare), true
}

func (s *KeygenSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.cfg.Parties) || len(s.shares) != len(s.cfg.Parties) || len(s.chainCodes) != len(s.cfg.Parties) {
		return nil
	}
	for dealer, share := range s.shares {
		// Verify f_dealer(self) * B against the dealer's public polynomial commitments.
		if err := edcurve.VerifyScalarShare(s.commits[dealer], uint32(s.cfg.Self), share); err != nil {
			s.log.Warn(s.cfg.Ctx(), "invalid DKG share",
				"party_id", s.cfg.Self,
				"dealer", dealer,
			)
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: frostKeygenBlame(s.cfg, dealer, s.commits[dealer]),
				Err:   err,
			}
		}
	}
	secret := edcurve.ScalarZero()
	for _, dealer := range s.cfg.Parties {
		secret = edcurve.ScalarAdd(secret, s.shares[dealer])
	}
	secretBytes := secret.Bytes()
	groupCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*fed.Point, 0, len(s.cfg.Parties))
		for _, dealer := range s.cfg.Parties {
			p, err := edcurve.PointFromBytesAllowIdentity(s.commits[dealer][degree])
			if err != nil {
				return err
			}
			points = append(points, p)
		}
		// Summing same-degree commitments yields the public polynomial for the group secret.
		groupCommitments[degree] = edcurve.AddPoints(points...).Bytes()
	}
	if _, err := edcurve.PointFromBytes(groupCommitments[0]); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	verificationShares := make([]VerificationShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		pub, err := edcurve.EvalCommitments(groupCommitments, uint32(id))
		if err != nil {
			return err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub})
	}
	chainCode, err := aggregateChainCode(s.cfg.Parties, s.chainCodes)
	if err != nil {
		return err
	}
	keygenTranscriptHash := keygenDomain(s.cfg.SessionID, s.cfg.Threshold, s.cfg.Parties, s.cfg.Self, groupCommitments[0])
	s.keyShare = &KeyShare{
		Version:              tss.Version,
		Party:                s.cfg.Self,
		Threshold:            s.cfg.Threshold,
		Parties:              append([]tss.PartyID(nil), s.cfg.Parties...),
		PublicKey:            append([]byte(nil), groupCommitments[0]...),
		ChainCode:            chainCode,
		secret:               secretBytes,
		GroupCommitments:     groupCommitments,
		VerificationShares:   verificationShares,
		KeygenTranscriptHash: keygenTranscriptHash,
	}
	s.completed = true
	s.log.Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return s.keyShare.ValidateConsistency()
}

func validateCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for i, commitment := range commitments {
		if i == 0 {
			if _, err := edcurve.PointFromBytes(commitment); err != nil {
				return err
			}
			continue
		}
		if _, err := edcurve.PointFromBytesAllowIdentity(commitment); err != nil {
			return err
		}
	}
	return nil
}

// aggregateChainCode XORs all parties' 32-byte chain codes together to produce
// the group chain code. Returns nil when no party provided a chain code (HD disabled).
func aggregateChainCode(parties []tss.PartyID, chainCodes map[tss.PartyID][]byte) ([]byte, error) {
	enabled := false
	for _, id := range parties {
		switch len(chainCodes[id]) {
		case 0:
		case 32:
			enabled = true
		default:
			return nil, fmt.Errorf("invalid chain code for party %d", id)
		}
	}
	if !enabled {
		return nil, nil
	}
	out := make([]byte, 32)
	for _, id := range parties {
		if len(chainCodes[id]) != 32 {
			return nil, fmt.Errorf("missing chain code for party %d", id)
		}
		for i := range out {
			out[i] ^= chainCodes[id][i]
		}
	}
	return out, nil
}

func envelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType string, payload []byte, confidential bool) tss.Envelope {
	return tss.Envelope{
		Protocol:             protocol,
		Version:              tss.Version,
		SessionID:            config.SessionID,
		Round:                round,
		From:                 from,
		To:                   to,
		PayloadType:          payloadType,
		Payload:              payload,
		ConfidentialRequired: confidential,
	}.WithTranscriptHash()
}
