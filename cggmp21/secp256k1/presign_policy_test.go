//go:build integration

package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
)

func TestPresignContextRejectsReuseAcrossBoundDomains(t *testing.T) {
	shares := CachedKeygenShares(t, 1, 1, true)
	signers := []tss.PartyID{1}
	ctx := testPresignContext()
	ctx.DerivationPath = []uint32{0}
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	presign := presigns[1]

	for _, tc := range []struct {
		name   string
		mutate func(*PresignContext)
	}{
		{name: "key id", mutate: func(c *PresignContext) { c.KeyID = "other-key" }},
		{name: "chain id", mutate: func(c *PresignContext) { c.ChainID = "other-chain" }},
		{name: "derivation path", mutate: func(c *PresignContext) { c.DerivationPath = []uint32{1} }},
		{name: "policy domain", mutate: func(c *PresignContext) { c.PolicyDomain = "other-policy" }},
		{name: "message domain", mutate: func(c *PresignContext) { c.MessageDomain = "other-message" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requestCtx := ctx
			requestCtx.DerivationPath = append([]uint32(nil), ctx.DerivationPath...)
			tc.mutate(&requestCtx)
			signID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			candidate := clonePresignForTest(presign)
			session, out, err := startCGGMP21Sign(shares[1], candidate, signID, SignRequest{
				Context: requestCtx,
				Message: []byte("presign policy"),
				LowS:    true,
			})
			if err == nil || session != nil || out != nil {
				t.Fatalf("StartSign accepted mismatched %s context", tc.name)
			}
			if IsPresignConsumed(candidate) {
				t.Fatalf("mismatched %s context consumed presign", tc.name)
			}
		})
	}
}
