package paillier

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// TestGenerateKeyCustomReaderSafety verifies that GenerateKey works correctly
// with a custom reader even though prime-search goroutines access it concurrently.
// The lockedReader wrapper serialises Read calls so the reader implementation
// never sees overlapping calls.
func TestGenerateKeyCustomReaderSafety(t *testing.T) {
	t.Parallel()

	reader := new(concurrencyDetectingReader)
	sk, err := GenerateKeyForTest(context.Background(), reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	// The lockedReader mutex ensures Read calls are serialised, so the
	// concurrencyDetectingReader never observes overlapping calls.
	if reader.concurrent.Load() {
		t.Fatal("lockedReader should serialise Read calls, but concurrent access was detected")
	}
	if err := sk.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeyForTestRejectsNonTestProcess(t *testing.T) {
	t.Parallel()

	if _, err := generateKeyForTest(context.Background(), nil, MinModulusBits, false); err == nil {
		t.Fatal("generateKeyForTest accepted a non-test process")
	}
}

func TestSameReaderHandlesNonComparableValues(t *testing.T) {
	t.Parallel()

	if !sameReader(crand.Reader, crand.Reader) {
		t.Fatal("identical non-comparable readers should compare equal")
	}

	if !sameReader(nil, nil) {
		t.Fatal("nil readers should not compare equal")
	}

	a := nonComparableReader{buf: make([]byte, 1), source: crand.Reader}
	b := nonComparableReader{buf: make([]byte, 1), source: crand.Reader}
	if sameReader(a, b) {
		t.Fatal("non-comparable reader values must not compare equal")
	}
}

func TestGenerateKeyReturnsContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := &cancelAfterFirstReadReader{cancel: cancel}

	_, err := GenerateKeyForTest(ctx, reader, 512)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateKey error = %v, want context.Canceled", err)
	}
}

func TestGeneratePrimePairRetriesOnlyQOnDuplicate(t *testing.T) {
	t.Parallel()

	var pCalls atomic.Int32
	var qCalls atomic.Int32
	search := func(ctx context.Context, side primeSide, bits, workers int) (*big.Int, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch side {
		case primeSideP:
			pCalls.Add(1)
			return big.NewInt(11), nil
		case primeSideQ:
			call := qCalls.Add(1)
			if call == 1 {
				return big.NewInt(11), nil
			}
			return big.NewInt(13), nil
		default:
			return nil, fmt.Errorf("unexpected prime side %d", side)
		}
	}

	p, q, err := generatePrimePairWithSearch(context.Background(), 2048, search)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cmp(big.NewInt(11)) != 0 || q.Cmp(big.NewInt(13)) != 0 {
		t.Fatalf("generatePrimePairWithSearch returned p=%s q=%s, want 11 and 13", p, q)
	}
	if got := pCalls.Load(); got != 1 {
		t.Fatalf("p search called %d times, want 1", got)
	}
	if got := qCalls.Load(); got != 2 {
		t.Fatalf("q search called %d times, want 2", got)
	}
}

// func TestGenerateKeyTimeCost(t *testing.T) {
// 	for range 10 {
// 		start := time.Now()
// 		_, err := GenerateKey(context.Background(), nil, 3072)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		duration := time.Since(start)
// 		t.Logf("GenerateKey(%d) took %s", 3072, duration)
// 	}
// }

func assertSafePrimeFactor(t *testing.T, p *big.Int, bits int) {
	t.Helper()
	if p == nil {
		t.Fatal("nil safe-prime factor")
	}
	if p.BitLen() != bits {
		t.Fatalf("factor has %d bits, want %d", p.BitLen(), bits)
	}
	if new(big.Int).Mod(p, big.NewInt(4)).Cmp(big.NewInt(3)) != 0 {
		t.Fatal("factor is not a Blum prime")
	}
	if !p.ProbablyPrime(64) {
		t.Fatal("factor is not prime")
	}
	sophie := new(big.Int).Sub(p, big.NewInt(1))
	sophie.Rsh(sophie, 1)
	if sophie.BitLen() != bits-1 {
		t.Fatalf("Sophie Germain factor has %d bits, want %d", sophie.BitLen(), bits-1)
	}
	if !sophie.ProbablyPrime(64) {
		t.Fatal("Sophie Germain factor is not prime")
	}
}

type concurrencyDetectingReader struct {
	active     atomic.Int32
	concurrent atomic.Bool
}

func (r *concurrencyDetectingReader) Read(p []byte) (int, error) {
	if !r.active.CompareAndSwap(0, 1) {
		r.concurrent.Store(true)
	}
	defer r.active.Store(0)

	time.Sleep(time.Millisecond)
	return crand.Read(p)
}

type cancelAfterFirstReadReader struct {
	cancel context.CancelFunc
	reads  atomic.Int32
}

func (r *cancelAfterFirstReadReader) Read(p []byte) (int, error) {
	clear(p)
	if r.reads.Add(1) == 1 {
		r.cancel()
	}
	return len(p), nil
}
