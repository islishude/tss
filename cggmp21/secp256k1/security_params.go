package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// SecurityParams controls the CGGMP21 ZK and Paillier proof profile. It is
// shared protocol intent and is committed into plans and persisted artifacts.
type SecurityParams = zkpai.SecurityParams

// DefaultSecurityParams returns the production CGGMP21 security profile.
func DefaultSecurityParams() SecurityParams {
	return zkpai.DefaultSecurityParams()
}

// UnmarshalSecurityParams decodes and validates a canonical security profile.
func UnmarshalSecurityParams(raw []byte) (SecurityParams, error) {
	return tss.DecodeBinaryValue[SecurityParams](raw)
}

func securityParamsOrDefault(params *SecurityParams) SecurityParams {
	if params == nil {
		return DefaultSecurityParams()
	}
	return *params
}

func validSecurityParams(params SecurityParams) bool {
	return params.Validate() == nil
}

func securityParamsForArtifact(artifact SecurityParams, explicit *SecurityParams) SecurityParams {
	if explicit != nil {
		return *explicit
	}
	if validSecurityParams(artifact) {
		return artifact
	}
	return DefaultSecurityParams()
}

func isProductionSecurityParams(params SecurityParams) bool {
	return params == DefaultSecurityParams()
}

func appendSecurityParamsTranscript(t *transcript.Builder, params SecurityParams) {
	t.AppendUint32("zk_ell", params.Ell)
	t.AppendUint32("zk_ell_prime", params.EllPrime)
	t.AppendUint32("zk_epsilon", params.Epsilon)
	t.AppendUint32("zk_challenge_bits", params.ChallengeBits)
	t.AppendUint32("zk_min_paillier_bits", params.MinPaillierBits)
}
