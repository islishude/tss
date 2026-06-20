package secp256k1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testvectors"
)

const keygenFixtureVector = "fixtures/cggmp21-secp256k1/keygen_fixtures.json"

// keygenFixtureVector points at committed test-only fixtures. These records
// contain reduced-parameter private share material and must never be used as
// production keys or printed in failure output.
var requiredKeygenFixtureOrder = []fixtureKey{
	{threshold: 1, n: 1},
	{threshold: 2, n: 2},
	{threshold: 2, n: 3},
	{threshold: 3, n: 5},
}

var requiredKeygenFixtures = func() map[fixtureKey]struct{} {
	out := make(map[fixtureKey]struct{}, len(requiredKeygenFixtureOrder))
	for _, key := range requiredKeygenFixtureOrder {
		out[key] = struct{}{}
	}
	return out
}()

type keygenFixtureFile struct {
	Description    string   `json:"description"`
	Threshold      int      `json:"threshold"`
	N              int      `json:"n"`
	Parties        []int    `json:"parties"`
	GroupPublicKey string   `json:"group_public_key"`
	KeygenShares   []string `json:"keygen_shares"`
}

func loadOrGenerateKeygenFixture(threshold, n int) (map[tss.PartyID]*KeyShare, bool, error) {
	key := fixtureKey{threshold: threshold, n: n}

	shares, ok, err := loadKeygenFixture(threshold, n)
	if err != nil {
		return nil, false, err
	}
	if ok {
		return shares, true, nil
	}

	if _, required := requiredKeygenFixtures[key]; required {
		return nil, false, fmt.Errorf("missing committed keygen fixture for %d-of-%d", threshold, n)
	}

	shares, err = runSecpKeygen(threshold, n)
	if err != nil {
		return nil, false, err
	}
	return shares, false, nil
}

func loadKeygenFixture(threshold, n int) (map[tss.PartyID]*KeyShare, bool, error) {
	fixtures, err := readKeygenFixtureFile()
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	matched, ok, err := findKeygenFixture(fixtures, threshold, n)
	if err != nil || !ok {
		return nil, ok, err
	}

	shares, err := decodeKeygenFixture(*matched)
	if err != nil {
		return nil, false, err
	}
	return shares, true, nil
}

func readKeygenFixtureFile() ([]keygenFixtureFile, error) {
	data, err := testvectors.ReadFile(keygenFixtureVector)
	if err != nil {
		return nil, err
	}

	var fixtures []keygenFixtureFile
	if err := json.Unmarshal(data, &fixtures); err != nil {
		return nil, fmt.Errorf("decode keygen fixture file: %w", err)
	}
	return fixtures, nil
}

func findKeygenFixture(fixtures []keygenFixtureFile, threshold, n int) (*keygenFixtureFile, bool, error) {
	var matched *keygenFixtureFile
	for i := range fixtures {
		fixture := &fixtures[i]
		if fixture.Threshold == threshold && fixture.N == n {
			if matched != nil {
				return nil, false, fmt.Errorf("duplicate keygen fixture for %d-of-%d", threshold, n)
			}
			matched = fixture
		}
	}
	if matched == nil {
		return nil, false, nil
	}
	return matched, true, nil
}

func decodeKeygenFixture(fixture keygenFixtureFile) (map[tss.PartyID]*KeyShare, error) {
	if fixture.Threshold <= 0 {
		return nil, fmt.Errorf("%s: invalid threshold", fixture.Description)
	}
	if fixture.N <= 0 {
		return nil, fmt.Errorf("%s: invalid party count", fixture.Description)
	}
	if len(fixture.Parties) != fixture.N {
		return nil, fmt.Errorf("%d-of-%d fixture parties count mismatch", fixture.Threshold, fixture.N)
	}
	if len(fixture.KeygenShares) != fixture.N {
		return nil, fmt.Errorf("%d-of-%d fixture key-share count mismatch", fixture.Threshold, fixture.N)
	}
	groupPublicKey, err := hex.DecodeString(fixture.GroupPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%d-of-%d fixture group public key: %w", fixture.Threshold, fixture.N, err)
	}

	parties := make(tss.PartySet, fixture.N)
	for i, id := range fixture.Parties {
		if id != i+1 {
			return nil, fmt.Errorf("%d-of-%d fixture party order mismatch at index %d", fixture.Threshold, fixture.N, i)
		}
		parties[i] = tss.PartyID(id)
	}

	shares := make(map[tss.PartyID]*KeyShare, fixture.N)
	for i, encoded := range fixture.KeygenShares {
		id := parties[i]
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%d-of-%d fixture party %d key share: %w", fixture.Threshold, fixture.N, id, err)
		}
		share, err := tss.DecodeBinaryWithLimits[KeyShare](raw, testLimits())
		if err != nil {
			return nil, fmt.Errorf("%d-of-%d fixture party %d unmarshal: %w", fixture.Threshold, fixture.N, id, err)
		}
		if err := validateDecodedKeygenFixtureShare(share, id, fixture, parties, groupPublicKey, raw); err != nil {
			return nil, fmt.Errorf("%d-of-%d fixture party %d: %w", fixture.Threshold, fixture.N, id, err)
		}
		shares[id] = share
	}
	return shares, nil
}

func validateDecodedKeygenFixtureShare(share *KeyShare, expectedID tss.PartyID, fixture keygenFixtureFile, parties tss.PartySet, groupPublicKey, original []byte) error {
	if share.PartyID() != expectedID {
		return fmt.Errorf("party id mismatch: got %d, want %d", share.PartyID(), expectedID)
	}
	if share.Threshold() != fixture.Threshold {
		return fmt.Errorf("threshold mismatch: got %d, want %d", share.Threshold(), fixture.Threshold)
	}
	meta, ok := share.PublicMetadata()
	if !ok {
		return errors.New("missing key share metadata")
	}
	if !slices.Equal(meta.Parties, parties) {
		return errors.New("participant set mismatch")
	}
	if !bytes.Equal(meta.PublicKey, groupPublicKey) {
		return errors.New("group public key mismatch")
	}
	if err := share.ValidateWithLimits(testLimits()); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	reencoded, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		return fmt.Errorf("re-marshal failed: %w", err)
	}
	if !bytes.Equal(reencoded, original) {
		return errors.New("canonical re-encoding changed")
	}
	return nil
}

func keygenFixtureParties(n int) tss.PartySet {
	parties := make(tss.PartySet, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	return parties
}

func TestCommittedKeygenFixturesCoverCachedCombinations(t *testing.T) {
	for _, key := range requiredKeygenFixtureOrder {
		t.Run(fmt.Sprintf("%d-of-%d", key.threshold, key.n), func(t *testing.T) {
			shares, ok, err := loadKeygenFixture(key.threshold, key.n)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("missing fixture for %d-of-%d", key.threshold, key.n)
			}
			if len(shares) != key.n {
				t.Fatalf("got %d shares, want %d", len(shares), key.n)
			}
		})
	}
}

func TestKeygenFixtureCanonicalRoundTrip(t *testing.T) {
	fixtures, err := readKeygenFixtureFile()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range requiredKeygenFixtureOrder {
		t.Run(fmt.Sprintf("%d-of-%d", key.threshold, key.n), func(t *testing.T) {
			fixture, ok, err := findKeygenFixture(fixtures, key.threshold, key.n)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("missing fixture for %d-of-%d", key.threshold, key.n)
			}
			if len(fixture.Parties) != key.n || len(fixture.KeygenShares) != key.n {
				t.Fatalf("%d-of-%d fixture has %d parties and %d shares", key.threshold, key.n, len(fixture.Parties), len(fixture.KeygenShares))
			}
			for i, encoded := range fixture.KeygenShares {
				id := tss.PartyID(fixture.Parties[i])
				raw, err := hex.DecodeString(encoded)
				if err != nil {
					t.Fatalf("party %d fixture decode: %v", id, err)
				}
				decoded, err := tss.DecodeBinaryWithLimits[KeyShare](raw, testLimits())
				if err != nil {
					t.Fatalf("party %d unmarshal: %v", id, err)
				}
				reencoded, err := decoded.MarshalBinaryWithLimits(testLimits())
				if err != nil {
					t.Fatalf("party %d re-marshal: %v", id, err)
				}
				if !bytes.Equal(reencoded, raw) {
					t.Fatalf("party %d re-encoding changed", id)
				}
			}
		})
	}
}

func TestCachedKeygenSharesReturnsIndependentClones(t *testing.T) {
	a := CachedKeygenShares(t, 2, 3)
	b := CachedKeygenShares(t, 2, 3)

	if a[1] == b[1] {
		t.Fatal("expected independent KeyShare pointers")
	}

	a[1].state.publicKey[0] ^= 1
	a[1].state.chainCode[0] ^= 1
	a[1].state.parties[0] = 99

	if err := b[1].ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("second clone was affected by first clone mutation: %v", err)
	}

	c := CachedKeygenShares(t, 2, 3)
	if err := c[1].ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("cache was polluted: %v", err)
	}
}
