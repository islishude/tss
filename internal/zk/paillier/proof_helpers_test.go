package paillier

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

func testSecretScalarFixed(t *testing.T, x *big.Int, fixedLen int) *secret.Scalar {
	t.Helper()
	out, err := secretScalarFromBig(x, fixedLen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(out.Destroy)
	return out
}

func testSecpSecretScalar(t *testing.T, x *big.Int) *secret.Scalar {
	t.Helper()
	return testSecretScalarFixed(t, x, secp.ScalarSize)
}

func testSignedSecret(t *testing.T, x *big.Int, fixedLen int) *secret.SignedInt {
	t.Helper()
	out, err := signedSecretFromBig(x, fixedLen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(out.Destroy)
	return out
}

func mustFixedModNBytes(t *testing.T, x *big.Int, fixedLen int) []byte {
	t.Helper()
	out, err := fixedModNBytes(x, fixedLen)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// testPaillierKeyEntry wraps a sync.Once to prevent duplicate key generation
// under parallel test execution. The cached key is immutable after construction.
type testPaillierKeyEntry struct {
	once sync.Once
	sk   *pai.PrivateKey
}

var testPaillierKeyCache sync.Map // map[int]*testPaillierKeyEntry

func testPaillierKey(tb testing.TB, bits int) *pai.PrivateKey {
	tb.Helper()

	entryAny, _ := testPaillierKeyCache.LoadOrStore(bits, &testPaillierKeyEntry{})
	entry := entryAny.(*testPaillierKeyEntry)

	entry.once.Do(func() {
		sk, err := pai.GenerateKeyForTest(context.Background(), nil, bits)
		if err != nil {
			// Don't poison the cache; delete the entry so a later caller retries.
			testPaillierKeyCache.Delete(bits)
			tb.Fatal(err)
		}
		entry.sk = sk
	})

	if entry.sk == nil {
		tb.Fatalf("paillier key cache poisoned for bits=%d", bits)
	}

	// Return a deep clone so callers cannot mutate the cached original.
	return entry.sk.Clone()
}

func mustWireProof(t *testing.T, typeID string, fields []wire.Field) []byte {
	t.Helper()
	raw, err := wire.MarshalFields(modulusProofWireVersion, typeID, fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func prependZeroToWireField(raw []byte, typeID string, model any, fieldName string) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, typeID)
	if err != nil {
		return nil, err
	}
	tag, err := wire.FieldTag(model, fieldName)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			value := make([]byte, 0, len(fields[i].Value)+1)
			value = append(value, 0)
			value = append(value, fields[i].Value...)
			fields[i].Value = value
			return wire.MarshalFields(version, typeID, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %q", fieldName)
}
