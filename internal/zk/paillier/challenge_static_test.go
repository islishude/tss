package paillier

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionProofsDoNotDeriveRawOrModReducedChallenges(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		source := string(raw)
		for _, forbidden := range []string{
			"sha256.New(",
			"sha256.Sum256(",
			"Mod(secp.Order(",
			"Mod( secp.Order(",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s derives a Fiat-Shamir candidate outside the canonical challenge helper: %q", name, forbidden)
			}
		}
		if name != "transcript.go" && name != "elog.go" && strings.Contains(source, "internal/zk/challenge") {
			t.Fatalf("%s bypasses the package Transcript challenge wrapper", name)
		}
	}
}
