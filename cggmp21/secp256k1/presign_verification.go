package secp256k1

import "errors"

// VerifyCryptographicMaterial revalidates the complete normalized Figure 8
// artifact using the production profile.
func (p *Presign) VerifyCryptographicMaterial() error {
	if p == nil || p.state == nil {
		return errors.New("nil presign")
	}
	if !isProductionSecurityParams(p.state.SecurityParams) {
		return errors.New("presign uses non-production security params")
	}
	return p.VerifyCryptographicMaterialWithLimits(DefaultLimits())
}

// VerifyCryptographicMaterialWithLimits validates the canonical record, local
// normalized secret openings, and both aggregate Figure 8 commitment
// equations. No one-use lifecycle state is changed.
func (p *Presign) VerifyCryptographicMaterialWithLimits(limits Limits) error {
	return p.ValidateWithLimits(limits)
}
