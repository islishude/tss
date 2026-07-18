//go:build integration

package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestThresholdECDSADeriveMatchesPublicMetadata(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	share := shares[1]
	metadata, ok := share.PublicMetadata()
	if !ok {
		t.Fatal("missing public metadata")
	}
	path := tss.DerivationPath{0, 11}

	fromShare, err := share.Derive(path)
	if err != nil {
		t.Fatal(err)
	}
	fromMetadata, err := DeriveNonHardenedBIP32(metadata.PublicKey, metadata.ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fromShare.ChildPublicKey, fromMetadata.ChildPublicKey) {
		t.Fatal("KeyShare.Derive child public key differs from public metadata derivation")
	}
	if fromShare.Scheme != tss.DerivationSchemeBIP32Secp256k1 {
		t.Fatalf("scheme = %q, want %q", fromShare.Scheme, tss.DerivationSchemeBIP32Secp256k1)
	}
}

func TestBIP32RejectsHardened(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	_, err := DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), []uint32{tss.HardenedKeyStart})
	if err == nil {
		t.Fatal("expected error for hardened index")
	}
	_, err = DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), []uint32{0, tss.HardenedKeyStart + 1})
	if err == nil {
		t.Fatal("expected error for hardened index in path")
	}
}

func TestSignWithEmptyBIP32PathMatchesCurrentGeneration(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	signers := tss.NewPartySet(1)
	ctx := testPresignContext()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := tss.SignRequest{Context: ctx, Message: []byte("empty path signing")}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := startCGGMP21Sign(shares[1], presigns[1], signID, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("expected sign partial")
	}
	sig, ok := session.Signature()
	if !ok {
		t.Fatal("signature not completed")
	}
	if !VerifySignature(mustKeySharePublicKey(t, shares[1]), request, sig) {
		t.Fatal("empty-path signature did not verify against current generation")
	}
}

func TestPresignRejectsRequestTimeBIP32Paths(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*tss.SigningContext)
	}{
		{name: "requested", mutate: func(ctx *tss.SigningContext) { ctx.Derivation.Path = tss.DerivationPath{0} }},
		{name: "resolved", mutate: func(ctx *tss.SigningContext) { ctx.Derivation.ResolvedPath = tss.DerivationPath{0} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testPresignContext()
			tc.mutate(&ctx)
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			presignID := bytes.Repeat([]byte{0x51}, 32)
			if _, err := NewPresignPlan(PresignPlanOption{
				Key: shares[1], SessionID: sessionID, PresignID: presignID,
				Signers: tss.NewPartySet(1, 2), Context: ctx, Limits: testLimitsPtr(), SecurityParams: testSecurityParamsPtr(),
			}); err == nil {
				t.Fatal("request-time HD path was accepted by presign planning")
			}
		})
	}
}
