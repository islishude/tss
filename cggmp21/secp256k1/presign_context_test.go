package secp256k1

import (
	"bytes"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestFast_PreparePresignContextBindsCurrentGenerationWithoutDeriving(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	publicKey, err := secp.PointBytes(presign.state.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := &KeyShare{state: &keyShareState{
		PublicKey: bytes.Clone(publicKey),
		ChainCode: bytes.Clone(presign.state.Derivation.ChildChainCode),
	}}
	ctx := testPresignContext()
	normalized, contextHash, derivation, err := preparePresignContext(key, ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer derivation.Destroy()
	if len(normalized.Derivation.Path) != 0 || len(normalized.Derivation.ResolvedPath) != 0 {
		t.Fatal("normalized presign context retained a request-time path")
	}
	if len(contextHash) != 32 || !bytes.Equal(contextHash, presignContextHash(normalized)) {
		t.Fatal("unexpected normalized context hash")
	}
	shift, err := secp.ScalarFromBytesAllowZero(derivation.AdditiveShift)
	if err != nil || !shift.IsZero() {
		t.Fatal("current-generation derivation binding does not use a zero shift")
	}
	if !bytes.Equal(derivation.ChildPublicKey, key.state.PublicKey) || !bytes.Equal(derivation.ChildChainCode, key.state.ChainCode) {
		t.Fatal("derivation result does not bind the current generation")
	}
}

func TestFast_PreparePresignContextRejectsRequestedAndResolvedPaths(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	publicKey, err := secp.PointBytes(presign.state.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := &KeyShare{state: &keyShareState{
		PublicKey: bytes.Clone(publicKey),
		ChainCode: bytes.Clone(presign.state.Derivation.ChildChainCode),
	}}
	for _, tc := range []struct {
		name   string
		mutate func(*tss.SigningContext)
	}{
		{name: "requested", mutate: func(ctx *tss.SigningContext) { ctx.Derivation.Path = tss.DerivationPath{1} }},
		{name: "resolved", mutate: func(ctx *tss.SigningContext) { ctx.Derivation.ResolvedPath = tss.DerivationPath{1} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testPresignContext()
			tc.mutate(&ctx)
			_, _, derivation, err := preparePresignContext(key, ctx)
			if err == nil || derivation != nil || !strings.Contains(err.Error(), "request-time HD derivation is not allowed") {
				t.Fatalf("preparePresignContext = derivation %v, err %v", derivation, err)
			}
		})
	}
}
