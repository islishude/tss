package secp256k1

import "github.com/islishude/tss"

// StartKeygen starts Figure 6 followed by Figure 7/F.1 from a shared keygen
// plan. The returned initial effect is the local Figure 6 commitment only.
func StartKeygen(plan *KeygenPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	config, limits, securityParams, planHash, err := resolveKeygenStart(plan, local, guard)
	if err != nil {
		return nil, nil, err
	}
	return startPaperKeygenResolved(config, limits, securityParams, planHash, nil, nil, nil, guard)
}

func resolveKeygenStart(
	plan *KeygenPlan,
	local tss.LocalConfig,
	guard *tss.EnvelopeGuard,
) (tss.ThresholdConfig, Limits, SecurityParams, []byte, error) {
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, local.Self, err)
	}
	limits := plan.limits
	if err := config.ValidateWithLimits(limits.ThresholdLimits()); err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, config.SessionID, config.Self); err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	if err := requireLocalEnvelopeSigner(guard, local.EnvelopeSigner); err != nil {
		return tss.ThresholdConfig{}, Limits{}, SecurityParams{}, nil,
			tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, config.Self, err)
	}
	config.Parties = config.SortedParties()
	return config, limits, plan.securityParams, planHash, nil
}
