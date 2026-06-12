package paillier

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/wire"
)

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

func mtaResponseForTest(t *testing.T, sk *pai.PrivateKey, encA, b, beta *big.Int) (*big.Int, *big.Int) {
	t.Helper()
	encBeta, betaRandomness, err := sk.Encrypt(nil, beta)
	if err != nil {
		t.Fatal(err)
	}
	nLen := modulusBytes(sk.N)
	nSquaredLen := 2 * nLen
	encPowBytes, err := paillierct.ExpCT(
		paillierct.FixedEncode(sk.NSquared, nSquaredLen),
		paillierct.FixedEncode(encA, nSquaredLen),
		secp.ScalarFromBigInt(b).Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	response := new(big.Int).SetBytes(encPowBytes)
	response.Mul(response, encBeta)
	response.Mod(response, sk.NSquared)
	return response, betaRandomness
}

func prependZero(in []byte) []byte {
	out := make([]byte, 0, len(in)+1)
	out = append(out, 0)
	out = append(out, in...)
	return out
}

func mustWireProof(t *testing.T, typeID string, fields []wire.Field) []byte {
	t.Helper()
	raw, err := wire.MarshalFields(proofVersion, typeID, fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertEncryptionProofRoundTrip(t *testing.T, proof *EncryptionProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalEncryptionProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("encryption proof encoding is not deterministic")
	}
	if _, err := UnmarshalEncryptionProof(append(raw, 0)); err == nil {
		t.Fatal("encryption proof accepted trailing bytes")
	}
}

func prependZeroToWireField(raw []byte, typeID string, tag uint16) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, typeID)
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
	return nil, fmt.Errorf("missing wire field %d", tag)
}
