// Package planvalidation centralizes lifecycle-plan validation shared by
// protocol packages.
package planvalidation

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
)

// RequireHash validates the canonical size and expected value of a lifecycle
// plan hash.
func RequireHash(label string, got, want []byte) error {
	if len(got) != sha256.Size {
		return fmt.Errorf("%s plan hash must be %d bytes", label, sha256.Size)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s: %w", label, tss.ErrPlanHashMismatch)
	}
	return nil
}

// InvalidConfig wraps err as an invalid-configuration protocol error while
// preserving an existing invalid-configuration error unchanged.
func InvalidConfig(party tss.PartyID, err error) error {
	if err == nil {
		return nil
	}
	var protocolErr *tss.ProtocolError
	if errors.As(err, &protocolErr) && protocolErr.Code == tss.ErrCodeInvalidConfig {
		return err
	}
	return tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, party, err)
}
