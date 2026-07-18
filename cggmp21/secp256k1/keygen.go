package secp256k1

import (
	"errors"
	"sync"

	"github.com/islishude/tss"
)

const keygenCommitmentsHashLabel = "cggmp21-secp256k1-keygen-commitments-v1"

type keygenState uint8

const (
	keygenCollectingRound1 keygenState = iota
	keygenAwaitingConfirmations
	keygenConfirmed
	keygenAborted
)

// KeygenSession owns the public Figure 6 then Figure 7/F.1 state machine and
// exposes a KeyShare only after the final transcript/chain-code confirmation.
type KeygenSession struct {
	mu sync.Mutex

	cfg                tss.ThresholdConfig
	limits             Limits
	securityParams     SecurityParams
	planHash           []byte
	importPlan         *TrustedDealerImportPlan
	completed          bool
	aborted            bool
	state              keygenState
	pending            *KeyShare
	keyShare           *KeyShare
	guard              *tss.EnvelopeGuard
	figure6            *figure6State
	auxInfo            *auxInfoState
	figure7Failure     *Figure7Failure
	paperConfirmations map[tss.PartyID]*KeygenConfirmation
	paperAccepted      map[paperKeygenMessageKey]struct{}
}

func (s *KeygenSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// Handle validates and applies one Figure 6, Figure 7, or confirmation envelope.
func (s *KeygenSession) Handle(env tss.InboundEnvelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
	base := env.Envelope()
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
			s.abort()
		}
	}()
	if err := tss.ValidateInboundWithoutReplay(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self); err != nil {
		return nil, err
	}
	return s.handlePaperKeygenLocked(env)
}

// KeyShare returns a defensive copy of the confirmed local key share.
func (s *KeygenSession) KeyShare() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != keygenConfirmed || !s.completed || s.keyShare == nil {
		return nil, false
	}
	return cloneKeyShareValue(s.keyShare), true
}

// Figure7Failure returns a public-only terminal Figure 7 accusation result.
func (s *KeygenSession) Figure7Failure() (Figure7Failure, bool) {
	if s == nil {
		return Figure7Failure{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.figure7Failure == nil {
		return Figure7Failure{}, false
	}
	return s.figure7Failure.Clone(), true
}

func (s *KeygenSession) terminalFigure7Failure(failure *Figure7Failure) {
	s.abort()
	s.figure7Failure = cloneFigure7Failure(failure)
	// tssrun.Completed is a terminal-disposition signal. KeyShare still
	// reject this aborted outcome because state is keygenAborted.
	s.completed = true
}

func (s *KeygenSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.completed = false
	s.state = keygenAborted
	if s.figure6 != nil {
		s.figure6.destroy()
		s.figure6 = nil
	}
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
	destroyPaperConfirmationMap(s.paperConfirmations)
	s.paperConfirmations = nil
	s.paperAccepted = nil
	if s.pending != nil {
		s.pending.Destroy()
		s.pending = nil
	}
}
