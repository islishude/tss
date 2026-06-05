package secp256k1

import (
	"os"
	"strings"
	"testing"
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
