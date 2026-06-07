package secp256k1

import (
	"os"
	"strings"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// TestFast_StaticNoSecretShareRegression scans sign.go for forbidden
// regression markers that would indicate secret material leaking into
// the public API surface. No cryptographic operations are performed.
func TestFast_StaticNoSecretShareRegression(t *testing.T) {
	body, err := os.ReadFile("sign.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{"SecretShare", "NonceShare", "InterpolateConstant"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("sign.go still contains forbidden regression marker %q", forbidden)
		}
	}
}

func TestFast_RefreshCommitmentsRejectNonzeroConstant(t *testing.T) {
	const threshold = 2
	commitments := make([][]byte, threshold)
	var err error
	commitments[0], err = secp.PointBytes(secp.G)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRefreshCommitments(commitments, threshold); err == nil || !strings.Contains(err.Error(), "constant commitment") {
		t.Fatalf("expected refresh constant commitment rejection, got %v", err)
	}
}
