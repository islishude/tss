package secp256k1

func (s *PresignSession) allRound1PayloadsAccepted() bool {
	if s == nil || len(s.parties) == 0 {
		return false
	}
	for i := range s.parties {
		if !s.parties[i].round1.havePayload {
			return false
		}
	}
	return true
}

func (s *PresignSession) allRound1ProofsAccepted() bool {
	if s == nil || len(s.parties) == 0 {
		return false
	}
	for i := range s.parties {
		if s.parties[i].id == s.key.state.Party {
			continue
		}
		if !s.parties[i].round1.haveProof {
			return false
		}
	}
	return true
}

func (s *PresignSession) allRound1Verified() bool {
	if s == nil || len(s.parties) == 0 {
		return false
	}
	for i := range s.parties {
		if !s.parties[i].round1.verified {
			return false
		}
	}
	return true
}

func (s *PresignSession) allRound2Accepted() bool {
	if s == nil || len(s.parties) == 0 {
		return false
	}
	for i := range s.parties {
		if s.parties[i].id == s.key.state.Party {
			continue
		}
		if !s.parties[i].round2.havePayload {
			return false
		}
	}
	return true
}

func (s *PresignSession) allRound3Accepted() bool {
	if s == nil || len(s.parties) == 0 {
		return false
	}
	for i := range s.parties {
		if !s.parties[i].round3.haveDelta || !s.parties[i].round3.haveVerifyShare {
			return false
		}
	}
	return true
}
