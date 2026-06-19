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
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/transcript"
)

const (
	keygenStartRound        = 1
	keygenConfirmationRound = 2
)

// keygenPartyData holds all per-party DKG state for a single participant.
// All fields other than confirmation are populated during round 1;
// confirmation is set during round 2 after the chain code is revealed.
type keygenPartyData struct {
	commitments     [][]byte
	share           *fed.Scalar
	chainCode       []byte
	chainCodeCommit []byte
	confirmation    *KeygenConfirmation
}

// KeygenSession tracks dealerless FROST DKG state for one local party.
type KeygenSession struct {
	mu          sync.Mutex
	cfg         tss.ThresholdConfig              // Local threshold runtime view fixed by the keygen plan.
	limits      Limits                           // Local fail-closed resource policy.
	partyData   map[tss.PartyID]*keygenPartyData // Per-party DKG state keyed by sender.
	planHash    []byte                           // Digest every keygen payload must echo.
	completed   bool                             // Terminal success flag after the key share is confirmed.
	aborted     bool                             // Terminal failure/destruction flag.
	pending     *KeyShare                        // Completed but not yet confirmed key share.
	keyShare    *KeyShare                        // Confirmed key share retained by the session.
	ownPoly     []*fed.Scalar                    // Local random polynomial coefficients; secret-bearing.
	ownMessages []tss.Envelope                   // Secret outbound share envelopes retained until completion.
	guard       *tss.EnvelopeGuard               // Transport replay, identity, and policy guard.
}

// GetChainCodeCommitByPartyId gets a copy of chainCodeCommit by partyId
// It returns nil if the id doesn't exist
func (s *KeygenSession) GetChainCodeCommitByPartyId(id tss.PartyID) []byte {
	data, err := s.partyEntry(id)
	if err == nil {
		return bytes.Clone(data.chainCodeCommit)
	}
	return nil
}

type keygenCommitmentsPayload struct {
	Commitments     [][]byte `json:"commitments" wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	ChainCodeCommit []byte   `json:"chain_code_commit,omitempty" wire:"2,bytes"`
	PlanHash        []byte   `json:"plan_hash" wire:"3,bytes,len=32"`
}

const keygenCommitmentsPayloadWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireType() string { return keygenCommitmentsPayloadWireType }

// WireVersion returns the wire format version for keygenCommitmentsPayload.
func (keygenCommitmentsPayload) WireVersion() uint16 {
	return keygenCommitmentsPayloadWireVersion
}

type keygenSharePayload struct {
	Share    []byte `json:"share" wire:"1,bytes,max_bytes=scalar"`
	PlanHash []byte `json:"plan_hash" wire:"2,bytes,len=32"`
}

const keygenSharePayloadWireVersion uint16 = 1

// WireType returns the canonical wire type identifier for keygenSharePayload.
func (keygenSharePayload) WireType() string { return keygenSharePayloadWireType }

// WireVersion returns the wire format version for keygenSharePayload.
func (keygenSharePayload) WireVersion() uint16 { return keygenSharePayloadWireVersion }

// MarshalJSON rejects default JSON encoding of secret DKG shares.
func (keygenSharePayload) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 keygen share payload must use wire encoding (MarshalBinary)")
}

// StartKeygen starts dealerless DKG from a shared immutable lifecycle plan.
func StartKeygen(plan *KeygenPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, local.Self, err)
	}
	limits := plan.limits
	if err := config.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolFROSTEd25519, config.SessionID, config.Self); err != nil {
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
	chainCode := make([]byte, 32)
	if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
		return nil, nil, err
	}
	chainCodeCommit := chainCodeCommitment(config.SessionID, config.Self, chainCode)
	partyData := make(map[tss.PartyID]*keygenPartyData, len(parties))
	for _, id := range parties {
		partyData[id] = &keygenPartyData{}
	}
	partyData[config.Self] = &keygenPartyData{
		commitments:     commitments,
		share:           evalScalarPolynomial(poly, config.Self),
		chainCode:       bytes.Clone(chainCode),
		chainCodeCommit: bytes.Clone(chainCodeCommit),
	}
	s := &KeygenSession{
		cfg:       config,
		limits:    limits,
		partyData: partyData,
		planHash:  bytes.Clone(planHash),
		ownPoly:   poly,
		guard:     guard,
	}

	out := make([]tss.Envelope, 0, len(parties))
	commitPayload, err := marshalKeygenCommitmentsPayloadWithLimits(keygenCommitmentsPayload{Commitments: commitments, ChainCodeCommit: chainCodeCommit, PlanHash: planHash}, limits)
	if err != nil {
		return nil, nil, err
	}
	commitEnv, err := newEnvelope(config, keygenStartRound, config.Self, tss.BroadcastPartyId, payloadKeygenCommitments, commitPayload)
	if err != nil {
		return nil, nil, err
	}
	out = append(out, commitEnv)
	for _, id := range parties {
		if id == config.Self {
			continue
		}
		share := evalScalarPolynomial(poly, id)
		shareBytes := share.Bytes()
		payload, err := marshalKeygenSharePayloadWithLimits(keygenSharePayload{Share: shareBytes, PlanHash: planHash}, limits)
		if err != nil {
			return nil, nil, err
		}
		// Shamir shares are secret-bearing and must be delivered over a confidential transport.
		shareEnv, err := newEnvelope(config, keygenStartRound, config.Self, id, payloadKeygenShare, payload)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, shareEnv)
	}
	s.ownMessages = tss.CloneSlice(out)
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, completionOut...)
	return s, out, nil
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *KeygenSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolFROSTEd25519, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// HandleKeygenMessage validates and applies one DKG envelope.
func (s *KeygenSession) HandleKeygenMessage(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
	base := env.Envelope()
	if s == nil {
		return nil, errors.New("nil keygen session")
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
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	if base.PayloadType == payloadKeygenConfirmation {
		return s.handleKeygenConfirmation(base)
	}
	if base.Round != keygenStartRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("keygen only accepts round 1 messages and round 2 confirmations"))
	}
	payload := base.Payload
	switch base.PayloadType {
	case payloadKeygenCommitments:
		p, err := tss.DecodeBinaryWithLimits[keygenCommitmentsPayload](payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		if err := requirePlanHash("keygen", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
		if err := validateCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
		pd, err := s.partyEntry(base.From)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		if pd.commitments != nil {
			if equalByteSlices(pd.commitments, p.Commitments) && bytes.Equal(pd.chainCodeCommit, p.ChainCodeCommit) {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting commitments"))
		}
		pd.commitments = p.Commitments
		if len(p.ChainCodeCommit) != sha256.Size {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("chain code commit must be 32 bytes, got %d", len(p.ChainCodeCommit)))
		}
		pd.chainCodeCommit = bytes.Clone(p.ChainCodeCommit)
	case payloadKeygenShare:
		p, err := tss.DecodeBinaryWithLimits[keygenSharePayload](payload, s.limits)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		if err := requirePlanHash("keygen", p.PlanHash, s.planHash); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
		scalar, err := edcurve.ScalarFromCanonical(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		pd, err := s.partyEntry(base.From)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, err)
		}
		if pd.share != nil {
			if pd.share.Equal(scalar) == 1 {
				return nil, nil
			}
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting share"))
		}
		pd.share = scalar
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected payload type %q", base.PayloadType))
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

func (s *KeygenSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	if s.pending != nil {
		s.pending.Destroy()
	}
	s.pending = nil
	s.clearIntermediateSecrets()
}

// partyEntry returns the per-party data for id, or an error when id is not in the session.
func (s *KeygenSession) partyEntry(id tss.PartyID) (*keygenPartyData, error) {
	pd, ok := s.partyData[id]
	if !ok {
		return nil, fmt.Errorf("party %d is not a keygen participant", id)
	}
	return pd, nil
}

func newEnvelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType tss.PayloadType, payload []byte) (tss.Envelope, error) {
	return tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   config.SessionID,
		Round:       round,
		From:        from,
		To:          to,
		PayloadType: payloadType,
		Payload:     payload,
	})
}

const chainCodeCommitLabel = "frost-ed25519-chain-code-commit-v1"

// chainCodeCommitment produces a hash commitment for a party's HD chain code.
// The chain code is revealed in round 2 (keygen confirmation) and verified
// against this commitment to prevent last-sender bias.
func chainCodeCommitment(sessionID tss.SessionID, partyID tss.PartyID, chainCode []byte) []byte {
	t := transcript.New(chainCodeCommitLabel)
	t.AppendBytes("session_id", sessionID[:])
	t.AppendUint32("party_id", partyID)
	t.AppendBytes("chain_code", chainCode)
	return t.Sum()
}

// verifyChainCodeCommit checks that a revealed chain code matches its round 1 commit.
func verifyChainCodeCommit(sessionID tss.SessionID, partyID tss.PartyID, chainCode, commit []byte) bool {
	if len(commit) != sha256.Size || len(chainCode) != bip32util.ChainCodeSize {
		return false
	}
	expected := chainCodeCommitment(sessionID, partyID, chainCode)
	return bytes.Equal(expected, commit)
}
