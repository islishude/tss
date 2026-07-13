package secp256k1

import (
	"bytes"

	"github.com/islishude/tss"
)

// Figure7FailureClass identifies a terminal, publicly attributable Figure 7
// decryption-error outcome without retaining the DH witness that proved it.
type Figure7FailureClass string

const (
	// Figure7FailureDecryptionError means an authenticated direct ciphertext
	// decrypts to a share that does not match the sender's public polynomial.
	Figure7FailureDecryptionError Figure7FailureClass = "figure7_decryption_error"
	// Figure7FailureFalseAccusation means the reporter supplied an invalid DH
	// witness or the authenticated direct ciphertext actually decrypts to the
	// committed share.
	Figure7FailureFalseAccusation Figure7FailureClass = "figure7_false_accusation"
)

// Figure7Failure is the public-only terminal disposition of the dedicated
// Figure 7 decryption-error accusation path. It deliberately retains neither
// the revealed DH exponent nor the masked share.
type Figure7Failure struct {
	Class                Figure7FailureClass
	Reporter             tss.PartyID
	Accused              tss.PartyID
	DirectEnvelopeDigest []byte
}

// Clone returns an independently owned public failure disposition.
func (f Figure7Failure) Clone() Figure7Failure {
	return Figure7Failure{
		Class:                f.Class,
		Reporter:             f.Reporter,
		Accused:              f.Accused,
		DirectEnvelopeDigest: bytes.Clone(f.DirectEnvelopeDigest),
	}
}

func cloneFigure7Failure(f *Figure7Failure) *Figure7Failure {
	if f == nil {
		return nil
	}
	clone := f.Clone()
	return &clone
}
