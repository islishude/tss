//go:build vectorgen

package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/islishude/tss/internal/testvectors"
)

func TestGenerateKeygenFixtures(t *testing.T) {
	fixtures := make([]keygenFixtureFile, 0, len(requiredKeygenFixtureOrder))
	for _, key := range requiredKeygenFixtureOrder {
		shares := secpKeygen(t, key.threshold, key.n)
		parties := keygenFixtureParties(key.n)
		fixture := keygenFixtureFile{
			Description:  fmt.Sprintf("CGGMP21 secp256k1 %d-of-%d keygen fixture", key.threshold, key.n),
			Threshold:    key.threshold,
			N:            key.n,
			Parties:      make([]int, len(parties)),
			KeygenShares: make([]string, len(parties)),
		}
		for i, id := range parties {
			fixture.Parties[i] = int(id)
			share := shares[id]
			if fixture.GroupPublicKey == "" {
				fixture.GroupPublicKey = hex.EncodeToString(mustKeySharePublicKey(t, share))
			}
			raw, err := share.MarshalBinaryWithLimits(testLimits())
			if err != nil {
				t.Fatalf("%d-of-%d party %d marshal: %v", key.threshold, key.n, id, err)
			}
			fixture.KeygenShares[i] = hex.EncodeToString(raw)
		}
		fixtures = append(fixtures, fixture)
	}

	raw, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path, err := testvectors.Path(keygenFixtureVector)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, key := range requiredKeygenFixtureOrder {
		shares, ok, err := loadKeygenFixture(key.threshold, key.n)
		if err != nil {
			t.Fatalf("%d-of-%d reload: %v", key.threshold, key.n, err)
		}
		if !ok {
			t.Fatalf("%d-of-%d reload missing", key.threshold, key.n)
		}
		for _, id := range keygenFixtureParties(key.n) {
			if err := shares[id].ValidateWithLimits(testLimits()); err != nil {
				t.Fatalf("%d-of-%d party %d reload validate: %v", key.threshold, key.n, id, err)
			}
		}
	}
	t.Logf("wrote %d keygen fixtures to %s", len(fixtures), path)
}
