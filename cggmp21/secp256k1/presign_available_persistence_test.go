package secp256k1

import (
	"bytes"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestFast_PresignAvailablePersistenceIsSideEffectFree(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()

	first, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if IsPresignConsumed(presign) {
		t.Fatal("persisting an available presign changed its lifecycle state")
	}
	second, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("side-effect-free presign persistence is not deterministic")
	}

	var restored Presign
	if err := restored.UnmarshalBinaryWithLimits(first, testLimits()); err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	if IsPresignConsumed(&restored) {
		t.Fatal("a persisted available presign did not restore as available")
	}
	reencoded, err := restored.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reencoded) {
		t.Fatal("restored available presign did not canonically re-encode")
	}
}

func TestFast_PresignUnmarshalRevalidatesNormalizedOpenings(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	raw, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	// Scalar two is canonical and structurally valid, but it no longer opens
	// the local DeltaTilde commitment stored in the artifact.
	mutated, err := testutil.RewriteWireField(raw, presignWireType, 8, secp.ScalarFromUint64(2).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var restored Presign
	if err := restored.UnmarshalBinaryWithLimits(mutated, testLimits()); err == nil {
		restored.Destroy()
		t.Fatal("presign unmarshal accepted a normalized secret that does not open its public commitment")
	}
}

func TestFast_PresignBoundOrDestroyedCannotBePersistedAsAvailable(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	if !bindPresignToAttempt(presign, bytes.Repeat([]byte{0x42}, 32), false) {
		t.Fatal("bind test presign")
	}
	if _, err := presign.MarshalBinaryWithLimits(testLimits()); err == nil {
		t.Fatal("bound presign serialized as an available record")
	}
	presign.Destroy()
	if _, err := presign.MarshalBinaryWithLimits(testLimits()); err == nil {
		t.Fatal("destroyed presign serialized as an available record")
	}
}
