package ed25519

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*ReshareSession)(nil)
)

// Descriptor returns the keygen run binding.
func (s *KeygenSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolFROSTEd25519, Kind: tssrun.RunKeygen, SessionID: s.cfg.SessionID, Party: s.cfg.Self, PlanDigest: s.planHash}.Clone()
}

// Status returns the keygen lifecycle state.
func (s *KeygenSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return frostSessionState(s.completed, s.aborted, s.closed)
}

// Descriptor returns the signing run binding.
func (s *SignSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	party := tss.BroadcastPartyId
	if s.guard != nil {
		party = s.guard.Self()
	}
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolFROSTEd25519, Kind: tssrun.RunSign, SessionID: s.sessionID, Party: party, PlanDigest: s.planHash}.Clone()
}

// Status returns the signing lifecycle state.
func (s *SignSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return frostSessionState(s.completed, s.aborted, s.closed)
}

// Descriptor returns the refresh or reshare run binding.
func (s *ReshareSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kind := tssrun.RunReshare
	if s.mode == frostReshareModeRefresh {
		kind = tssrun.RunRefresh
	}
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolFROSTEd25519, Kind: kind, SessionID: s.cfg.SessionID, Party: s.selfID, PlanDigest: s.planHash}.Clone()
}

// Status returns the refresh or reshare lifecycle state.
func (s *ReshareSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return frostSessionState(s.completed, s.aborted, s.closed)
}

func frostSessionState(completed, aborted, closed bool) tssrun.SessionState {
	switch {
	case closed:
		return tssrun.SessionClosed
	case aborted:
		return tssrun.SessionAborted
	case completed:
		return tssrun.SessionSucceeded
	default:
		return tssrun.SessionActive
	}
}
