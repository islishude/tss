package ed25519

type frostReshareMode uint8

const (
	frostReshareModeReshare frostReshareMode = iota + 1
	frostReshareModeRefresh
)

type frostReshareRole uint8

const (
	frostReshareRoleDealerOnly frostReshareRole = iota + 1
	frostReshareRoleRecipientOnly
	frostReshareRoleDealerAndRecipient
)

func (s *ReshareSession) isDealer() bool {
	if s == nil {
		return false
	}
	return s.role == frostReshareRoleDealerOnly || s.role == frostReshareRoleDealerAndRecipient
}

func (s *ReshareSession) isRecipient() bool {
	if s == nil {
		return false
	}
	return s.role == frostReshareRoleRecipientOnly || s.role == frostReshareRoleDealerAndRecipient
}

func (s *ReshareSession) requiresInboundShares() bool {
	return s.isRecipient()
}

func (s *ReshareSession) requiresOutboundShares() bool {
	return s.isDealer()
}

func (s *ReshareSession) isRefresh() bool {
	return s != nil && s.mode == frostReshareModeRefresh
}
