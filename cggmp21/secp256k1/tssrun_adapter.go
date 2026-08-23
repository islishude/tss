package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

var (
	_ tssrun.ProtocolSession = (*KeygenSession)(nil)
	_ tssrun.ProtocolSession = (*PresignSession)(nil)
	_ tssrun.ProtocolSession = (*SignSession)(nil)
	_ tssrun.ProtocolSession = (*RefreshSession)(nil)
	_ tssrun.ProtocolSession = (*ReshareSession)(nil)
	_ tssrun.ProtocolSession = (*ChildDerivationSession)(nil)
)

// Descriptor returns the keygen run binding.
func (s *KeygenSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolCGGMP21Secp256k1, Kind: tssrun.RunKeygen, SessionID: s.cfg.SessionID, Party: s.cfg.Self, PlanDigest: s.planHash}.Clone()
}

// Status returns the keygen lifecycle state.
func (s *KeygenSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cggSessionState(s.completed, s.aborted, s.closed, false, false)
}

// Descriptor returns the presign run binding.
func (s *PresignSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolCGGMP21Secp256k1, Kind: tssrun.RunPresign, SessionID: s.sessionID, Party: s.config.Self, PlanDigest: s.planHash}.Clone()
}

// Status returns the presign lifecycle state.
func (s *PresignSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cggSessionState(s.completed, s.aborted, s.closed, s.closePending, s.lifecycleCandidate != nil)
}

// Descriptor returns the online-sign run binding.
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
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolCGGMP21Secp256k1, Kind: tssrun.RunSign, SessionID: s.sessionID, Party: party, PlanDigest: s.planHash}.Clone()
}

// Status returns the online-sign lifecycle state.
func (s *SignSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cggSessionState(s.completed, s.aborted, s.closed, s.closePending, false)
}

// Descriptor returns the refresh run binding.
func (s *RefreshSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolCGGMP21Secp256k1, Kind: tssrun.RunRefresh, SessionID: s.cfg.SessionID, Party: s.cfg.Self, PlanDigest: s.planHash}.Clone()
}

// Status returns the refresh lifecycle state.
func (s *RefreshSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	commitPending := !s.lifecycleFinished && s.lifecycleFinal != nil
	return cggSessionState(s.completed, s.aborted, s.closed, s.closePending, commitPending)
}

// Descriptor returns the reshare run binding.
func (s *ReshareSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolCGGMP21Secp256k1, Kind: tssrun.RunReshare, SessionID: s.cfg.SessionID, Party: s.selfID, PlanDigest: s.planHash}.Clone()
}

// Status returns the reshare lifecycle state.
func (s *ReshareSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	commitPending := !s.lifecycleFinished && (s.lifecycleFinal != nil || s.lifecycleRetirement != nil)
	return cggSessionState(s.completed, s.aborted, s.closed, s.closePending, commitPending)
}

// Descriptor returns the child-derivation run binding.
func (s *ChildDerivationSession) Descriptor() tssrun.SessionDescriptor {
	if s == nil {
		return tssrun.SessionDescriptor{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return tssrun.SessionDescriptor{Protocol: tss.ProtocolCGGMP21Secp256k1, Kind: tssrun.RunChildDerivation, SessionID: s.cfg.SessionID, Party: s.cfg.Self, PlanDigest: s.planHash}.Clone()
}

// Status returns the child-derivation lifecycle state.
func (s *ChildDerivationSession) Status() tssrun.SessionState {
	if s == nil {
		return tssrun.SessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	commitPending := s.lifecycleFinal != nil
	return cggSessionState(s.completed, s.aborted, s.closed, s.closePending, commitPending)
}

func cggSessionState(completed, aborted, closed, closePending, commitPending bool) tssrun.SessionState {
	switch {
	case closed:
		return tssrun.SessionClosed
	case closePending:
		return tssrun.SessionClosePending
	case commitPending:
		return tssrun.SessionCommitPending
	case aborted:
		return tssrun.SessionAborted
	case completed:
		return tssrun.SessionSucceeded
	default:
		return tssrun.SessionActive
	}
}
