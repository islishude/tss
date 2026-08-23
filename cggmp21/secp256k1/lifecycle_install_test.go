package secp256k1

import (
	"context"
	"testing"

	"github.com/islishude/tss/tssrun"
)

func TestCGGMP21InstallKeyShareUsesProtocolEpoch(t *testing.T) {
	shares := CachedKeygenShares(t, 2, 2)
	key := shares[1]
	binding, err := GenerationBindingForKeyShare(key, "cgg-key", "gen-1")
	if err != nil {
		t.Fatal(err)
	}
	metadata, ok := key.PublicMetadata()
	if !ok {
		t.Fatal("missing key metadata")
	}
	wantEpoch, err := tssrun.NewEpochID(metadata.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.EpochID != wantEpoch {
		t.Fatal("lifecycle binding did not use the protocol authorization epoch")
	}
	store := tssrun.NewMemoryLifecycleStore()
	record, err := InstallKeyShareWithLimits(context.Background(), store, "cgg-key", "gen-1", key, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if record.Binding != binding || record.Status != tssrun.GenerationCurrent {
		t.Fatal("installed CGGMP21 generation has the wrong binding")
	}
}
