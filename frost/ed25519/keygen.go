package ed25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/wire"
)

// KeygenSession tracks dealerless FROST DKG state for one local party.
type KeygenSession struct {
	mu             sync.Mutex
	cfg            tss.ThresholdConfig
	log            tss.Logger
	commits        map[tss.PartyID][][]byte
	shares         map[tss.PartyID]*fed.Scalar
	chainCodes     map[tss.PartyID][]byte
	chainCodeComms map[tss.PartyID][]byte
	enableHD       bool
	completed      bool
	aborted        bool
	pending        *KeyShare
	confirmations  map[tss.PartyID][]byte
	keyShare       *KeyShare
	ownPoly        []*fed.Scalar
	ownMessages    []tss.Envelope
}

type keygenCommitmentsPayload struct {
	Commitments     [][]byte `json:"commitments"`
	ChainCodeCommit []byte   `json:"chain_code_commit,omitempty"`
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
	if err := config.ValidateWithLimits(DefaultLimits()); err != nil {
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
		point := fed.NewIdentityPoint().ScalarBaseMult(coeff)
		commitments[i] = point.Bytes()
	}
	var chainCode []byte
	var chainCodeCommit []byte
	if opts.EnableHD {
		chainCode = make([]byte, 32)
		if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
			return nil, nil, err
		}
		chainCodeCommit = chainCodeCommitment(config.SessionID, config.Self, chainCode)
	}
	s := &KeygenSession{
		cfg:     config,
		log:     config.Logger(),
		commits: map[tss.PartyID][][]byte{config.Self: commitments},
		shares:  map[tss.PartyID]*fed.Scalar{config.Self: evalScalarPolynomial(poly, config.Self)},
		chainCodes: map[tss.PartyID][]byte{
			config.Self: append([]byte(nil), chainCode...),
		},
		enableHD: opts.EnableHD,
		chainCodeComms: map[tss.PartyID][]byte{
			config.Self: append([]byte(nil), chainCodeCommit...),
		},
		confirmations: make(map[tss.PartyID][]byte, len(parties)),
		ownPoly:       poly,
	}

	out := make([]tss.Envelope, 0, len(parties))
	commitPayload, err := marshalKeygenCommitmentsPayload(keygenCommitmentsPayload{Commitments: commitments, ChainCodeCommit: chainCodeCommit})
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
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, completionOut...)
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
			s.abort()
		}
	}()
	if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.cfg.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if env.To != 0 && env.To != s.cfg.Self {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	if env.PayloadType == payloadKeygenConfirmation {
		return s.handleKeygenConfirmation(env)
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen only accepts round 1 messages and round 2 confirmations"))
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
			if equalByteSlices(existing, p.Commitments) && bytes.Equal(s.chainCodeComms[env.From], p.ChainCodeCommit) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting commitments"))
		}
		s.commits[env.From] = p.Commitments
		if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != sha256.Size {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("chain code commit must be 32 bytes, got %d", len(p.ChainCodeCommit)))
		}
		s.chainCodeComms[env.From] = append([]byte(nil), p.ChainCodeCommit...)
	case payloadKeygenShare:
		if err := requireDirectConfidential(env, s.cfg.Self, payloadKeygenShare); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		p, err := unmarshalKeygenSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		scalar, err := edcurve.ScalarFromCanonical(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if existing, ok := s.shares[env.From]; ok {
			if existing.Equal(scalar) == 1 {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("conflicting share"))
		}
		s.shares[env.From] = scalar
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return s.tryComplete()
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

func (s *KeygenSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.pending != nil {
		if len(s.confirmations) == len(s.cfg.Parties) {
			return nil, s.finalizeConfirmedKeyShare()
		}
		return nil, nil
	}
	if len(s.commits) != len(s.cfg.Parties) || len(s.shares) != len(s.cfg.Parties) || len(s.chainCodeComms) != len(s.cfg.Parties) {
		return nil, nil
	}
	for dealer, share := range s.shares {
		// Verify f_dealer(self) * B against the dealer's public polynomial commitments.
		if err := edcurve.VerifyScalarShare(s.commits[dealer], uint32(s.cfg.Self), share); err != nil {
			s.log.Warn(s.cfg.Ctx(), "invalid DKG share",
				"party_id", s.cfg.Self,
				"dealer", dealer,
			)
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: frostKeygenBlame(s.cfg, dealer, s.commits[dealer]),
				Err:   err,
			}
		}
	}
	secret := fed.NewScalar()
	for _, dealer := range s.cfg.Parties {
		secret.Add(secret, s.shares[dealer])
	}
	secretScalar, err := newEdSecretScalar(secret.Bytes())
	if err != nil {
		return nil, err
	}
	groupCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*fed.Point, 0, len(s.cfg.Parties))
		for _, dealer := range s.cfg.Parties {
			p, err := edcurve.PointFromBytesAllowIdentity(s.commits[dealer][degree])
			if err != nil {
				return nil, err
			}
			points = append(points, p)
		}
		// Summing same-degree commitments yields the public polynomial for the group secret.
		groupCommitments[degree] = edcurve.AddPoints(points...).Bytes()
	}
	if _, err := edcurve.PointFromBytes(groupCommitments[0]); err != nil {
		return nil, fmt.Errorf("invalid group public key: %w", err)
	}
	verificationShares := make([]VerificationShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		pub, err := edcurve.EvalCommitments(groupCommitments, uint32(id))
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: pub})
	}
	// Chain code commitment binds the aggregate of all round-1 chain code
	// commitments into the transcript. Individual chain codes are revealed
	// and verified in round 2 confirmations.
	var chainCodeCommitAggregate []byte
	if s.enableHD {
		agg, err := tss.AggregateChainCode(s.cfg.Parties, s.chainCodeComms)
		if err != nil {
			return nil, err
		}
		chainCodeCommitAggregate = agg
	}
	keygenTranscriptHash := frostKeygenTranscriptHash(s.cfg.SessionID, s.cfg.Threshold, s.cfg.Parties, chainCodeCommitAggregate, s.commits, groupCommitments, verificationShares)
	share := &KeyShare{
		Version:              tss.Version,
		Party:                s.cfg.Self,
		Threshold:            s.cfg.Threshold,
		Parties:              append([]tss.PartyID(nil), s.cfg.Parties...),
		PublicKey:            append([]byte(nil), groupCommitments[0]...),
		ChainCode:            nil, // filled in after confirmation round
		secret:               secretScalar,
		GroupCommitments:     groupCommitments,
		VerificationShares:   verificationShares,
		KeygenSessionID:      s.cfg.SessionID,
		KeygenTranscriptHash: keygenTranscriptHash,
	}
	if err := share.validateConsistencyWithoutConfirmations(); err != nil {
		return nil, err
	}
	// Carry the local chain code into the confirmation for commit-reveal.
	share.ChainCode = append([]byte(nil), s.chainCodes[s.cfg.Self]...)
	confirmation, err := share.KeygenConfirmation()
	// Do not leak the per-party chain code into the KeyShare.
	share.ChainCode = nil
	if err != nil {
		return nil, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.confirmations[s.cfg.Self] = append([]byte(nil), encodedConfirmation...)
	s.pending = share
	out := []tss.Envelope{
		envelope(s.cfg, keygenConfirmationRound, s.cfg.Self, 0, payloadKeygenConfirmation, encodedConfirmation, false),
	}
	s.log.Info(s.cfg.Ctx(), "keygen local material complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if len(s.confirmations) == len(s.cfg.Parties) {
		if err := s.finalizeConfirmedKeyShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

const keygenConfirmationRound = 2

func (s *KeygenSession) handleKeygenConfirmation(env tss.Envelope) ([]tss.Envelope, error) {
	if env.Round != keygenConfirmationRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen confirmation in wrong round"))
	}
	if env.To != 0 {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("keygen confirmation must be broadcast"))
	}
	if env.ConfidentialRequired {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("keygen confirmation must not require confidential transport"))
	}
	confirmation, err := UnmarshalKeygenConfirmation(env.Payload)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if confirmation.Sender != env.From {
		return nil, tss.NewProtocolError(
			tss.ErrCodeInvalidMessage,
			env.Round,
			env.From,
			fmt.Errorf("keygen confirmation sender mismatch: env from %d, payload sender %d", env.From, confirmation.Sender),
		)
	}
	canonical, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical keygen confirmation"))
	}
	if existing, ok := s.confirmations[env.From]; ok {
		if bytes.Equal(existing, canonical) {
			return nil, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting keygen confirmation from party %d", env.From))
	}
	// Verify the revealed chain code against the round 1 hash commitment.
	if !verifyChainCodeCommit(s.cfg.SessionID, env.From, confirmation.ChainCode, s.chainCodeComms[env.From]) {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("keygen confirmation chain code does not match round 1 commit from party %d", env.From))
	}
	// Store the revealed chain code for XOR aggregation.
	s.chainCodes[env.From] = append([]byte(nil), confirmation.ChainCode...)
	if s.pending != nil {
		if err := verifyKeygenConfirmationForShare(s.pending, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	s.confirmations[env.From] = append([]byte(nil), canonical...)
	if s.pending != nil && len(s.confirmations) == len(s.cfg.Parties) {
		return nil, s.finalizeConfirmedKeyShare()
	}
	return nil, nil
}

func (s *KeygenSession) finalizeConfirmedKeyShare() error {
	if s.pending == nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, errors.New("missing pending key share"))
	}
	encoded := make([][]byte, len(s.cfg.Parties))
	for i, id := range s.cfg.Parties {
		confirmation, ok := s.confirmations[id]
		if !ok {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, fmt.Errorf("missing keygen confirmation from party %d", id))
		}
		encoded[i] = append([]byte(nil), confirmation...)
	}
	if err := verifyKeygenConfirmationSet(s.pending, encoded); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	// Aggregate chain codes from all revealed confirmations.
	var chainCode []byte
	if s.enableHD {
		cc, err := tss.AggregateChainCode(s.cfg.Parties, s.chainCodes)
		if err != nil {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
		}
		chainCode = cc
	}
	finalShare := cloneKeyShareValue(s.pending)
	finalShare.ChainCode = chainCode
	finalShare.KeygenConfirmations = cloneKeyShareByteSlices(encoded)
	if err := finalShare.ValidateConsistency(); err != nil {
		finalShare.Destroy()
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	s.pending.Destroy()
	s.pending = nil
	s.keyShare = finalShare
	s.completed = true
	confirmationSetHash := keygenConfirmationSetHash(finalShare.KeygenConfirmations)
	s.log.Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", confirmationSetHash[:8]),
	)
	return nil
}

func (s *KeygenSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	if s.pending != nil {
		s.pending.Destroy()
	}
	s.pending = nil
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

const chainCodeCommitLabel = "frost-ed25519-chain-code-commit-v1"

// chainCodeCommitment produces a hash commitment for a party's HD chain code.
// The chain code is revealed in round 2 (keygen confirmation) and verified
// against this commitment to prevent last-sender bias.
func chainCodeCommitment(sessionID tss.SessionID, partyID tss.PartyID, chainCode []byte) []byte {
	if len(chainCode) == 0 {
		return nil
	}
	h := sha256.New()
	wire.WriteHashPart(h, []byte(chainCodeCommitLabel))
	wire.WriteHashPart(h, sessionID[:])
	wire.WriteHashPart(h, []byte{byte(partyID >> 24), byte(partyID >> 16), byte(partyID >> 8), byte(partyID)})
	wire.WriteHashPart(h, chainCode)
	return h.Sum(nil)
}

// verifyChainCodeCommit checks that a revealed chain code matches its round 1 commit.
func verifyChainCodeCommit(sessionID tss.SessionID, partyID tss.PartyID, chainCode, commit []byte) bool {
	if len(commit) == 0 {
		return len(chainCode) == 0
	}
	if len(commit) != sha256.Size || len(chainCode) != 32 {
		return false
	}
	expected := chainCodeCommitment(sessionID, partyID, chainCode)
	return bytes.Equal(expected, commit)
}
