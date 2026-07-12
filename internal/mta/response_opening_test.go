package mta

import (
	"bytes"
	"testing"

	"github.com/islishude/tss/internal/secret"
)

func TestResponseOpeningPrivateEncodingRoundTrip(t *testing.T) {
	t.Parallel()
	x, err := secret.NewScalar(bytes.Repeat([]byte{1}, 32), 32)
	if err != nil {
		t.Fatal(err)
	}
	y, err := secret.NewSignedInt(true, bytes.Repeat([]byte{2}, 64), 64)
	if err != nil {
		t.Fatal(err)
	}
	rho, err := secret.NewScalar(bytes.Repeat([]byte{3}, 64), 64)
	if err != nil {
		t.Fatal(err)
	}
	rhoY, err := secret.NewScalar(bytes.Repeat([]byte{4}, 64), 64)
	if err != nil {
		t.Fatal(err)
	}
	original := &ResponseOpening{x: x, y: y, rho: rho, rhoY: rhoY}
	t.Cleanup(original.Destroy)
	raw, err := original.MarshalPrivateBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded ResponseOpening
	if err := decoded.UnmarshalPrivateBinary(raw); err != nil {
		t.Fatal(err)
	}
	defer decoded.Destroy()
	if !decoded.x.Equal(original.x) || !decoded.y.Equal(original.y) || !decoded.rho.Equal(original.rho) || !decoded.rhoY.Equal(original.rhoY) {
		t.Fatal("private response opening changed across canonical encoding")
	}
	if err := decoded.UnmarshalPrivateBinary(append(raw, 0)); err == nil {
		t.Fatal("private response opening accepted trailing bytes")
	}
}
