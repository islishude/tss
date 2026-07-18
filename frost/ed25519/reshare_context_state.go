package ed25519

type frostReshareMode uint8

const (
	frostReshareModeReshare frostReshareMode = iota + 1
	frostReshareModeRefresh
)

type frostReshareRole uint8

const (
	frostReshareRoleDealerOnly frostReshareRole = iota + 1
	frostReshareRoleReceiverOnly
	frostReshareRoleDealerAndReceiver
)

func (s *ReshareSession) isDealer() bool {
	if s == nil {
		return false
	}
	return s.role == frostReshareRoleDealerOnly || s.role == frostReshareRoleDealerAndReceiver
}

func (s *ReshareSession) isReceiver() bool {
	if s == nil {
		return false
	}
	return s.role == frostReshareRoleReceiverOnly || s.role == frostReshareRoleDealerAndReceiver
}

func (s *ReshareSession) requiresInboundShares() bool {
	return s.isReceiver()
}

func (s *ReshareSession) requiresOutboundShares() bool {
	return s.isDealer()
}

func (s *ReshareSession) isRefresh() bool {
	return s != nil && s.mode == frostReshareModeRefresh
}
