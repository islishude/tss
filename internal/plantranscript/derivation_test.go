package plantranscript

import (
	"encoding/hex"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

func TestAppendDerivationResultDigest(t *testing.T) {
	t.Parallel()
	result := &tss.DerivationResult{
		Scheme:            tss.DerivationSchemeBIP32Secp256k1,
		RequestedPath:     tss.DerivationPath{1, 2},
		ResolvedPath:      tss.DerivationPath{1, 3},
		ChildPublicKey:    []byte{0x02, 0x03},
		ChildChainCode:    []byte{0x04, 0x05},
		Depth:             2,
		ParentFingerprint: [4]byte{0x06, 0x07, 0x08, 0x09},
		ChildNumber:       3,
		AdditiveShift:     []byte{0x0a, 0x0b},
	}
	builder := transcript.New("plantranscript-derivation-test-v1")
	AppendDerivationResult(builder, result)
	got := hex.EncodeToString(builder.Sum())
	const want = "a7d57b1b7f626f60f21c9428150d667369b56a4606caace2353e7c5630260067"
	if got != want {
		t.Fatalf("derivation transcript digest = %s, want %s", got, want)
	}
}

func TestAppendNilDerivationResultDigest(t *testing.T) {
	t.Parallel()
	builder := transcript.New("plantranscript-derivation-test-v1")
	AppendDerivationResult(builder, nil)
	got := hex.EncodeToString(builder.Sum())
	const want = "ff69c9de2f719aceba1d970e881a1271f947e7b0ae453c03ef94c735de5a2ad0"
	if got != want {
		t.Fatalf("nil derivation transcript digest = %s, want %s", got, want)
	}
}
