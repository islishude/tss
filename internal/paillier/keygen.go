package paillier

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"runtime"
	"sync"

	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
)

// MinProductionModulusBits is the production Paillier modulus security floor
// (3072 bits ≈ 128-bit classical security, matching secp256k1). This is the
// minimum accepted by GenerateKey. Tests must use GenerateKeyForTest for
// smaller sizes.
const MinProductionModulusBits = 3072

// minKeyBits is the absolute minimum Paillier modulus size — a structural
// floor, not a security recommendation.
const minKeyBits = 512

// GenerateKey creates a Paillier key using safe primes (Sophie Germain primes)
// where p = 2p' + 1, q = 2q' + 1 with p', q' also prime, and the g=n+1 variant.
// Safe primes ensure the Blum condition p ≡ q ≡ 3 (mod 4) automatically.
// The context is checked in each prime-search iteration to support cancellation.
//
// GenerateKey enforces a production minimum of MinProductionModulusBits (3072).
// Protocol callers that need smaller keys for testing must use GenerateKeyForTest.
//
// crypto/rand.Reader is documented as safe for concurrent use and is used
// directly. Any other reader is wrapped with an internal mutex so that Read
// calls are serialized safely across prime-search goroutines; the mutex
// overhead is negligible compared to primality testing.
func GenerateKey(ctx context.Context, reader io.Reader, bits int) (*PrivateKey, error) {
	if bits < MinProductionModulusBits {
		return nil, fmt.Errorf("paillier modulus must be at least %d bits", MinProductionModulusBits)
	}
	return generateKeyInner(ctx, reader, bits)
}

// GenerateKeyForTest creates a Paillier key with a reduced modulus size suitable
// for testing. The minimum is 512 bits. This function must not be used in
// production code.
func GenerateKeyForTest(ctx context.Context, reader io.Reader, bits int) (*PrivateKey, error) {
	if bits < minKeyBits {
		return nil, fmt.Errorf("paillier modulus must be at least %d bits", minKeyBits)
	}
	return generateKeyInner(ctx, reader, bits)
}

// generateKeyInner contains the shared key-generation logic. It normalizes
// the reader (nil → crypto/rand.Reader, non-crypto/rand → lockedReader) before
// the prime-search loop.
func generateKeyInner(ctx context.Context, reader io.Reader, bits int) (*PrivateKey, error) {
	// normalizeReader defaults nil to crypto/rand.Reader and wraps non-crypto/rand
	// readers with a mutex for concurrent-safe use across prime-search goroutines.
	if reader == nil {
		reader = rand.Reader
	} else if !sameReader(reader, rand.Reader) {
		reader = &lockedReader{r: reader}
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		p, q, err := generatePrimePair(ctx, reader, bits)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).Mul(p, q)
		nSquared := new(big.Int).Mul(n, n)
		// g = n + 1 gives the common simplified Paillier variant.
		g := new(big.Int).Add(n, big.NewInt(1))
		lambdaBig := lcm(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		// (n+1)^λ ≡ 1 + λ·n (mod n²) via the binomial theorem when g = n+1.
		// This avoids math/big.Int.Exp with the secret exponent λ.
		u := new(big.Int).Mul(lambdaBig, n)
		u.Add(u, big.NewInt(1))
		u.Mod(u, nSquared)
		lu := L(u, n)
		muBig := new(big.Int).ModInverse(lu, n)
		if muBig == nil {
			continue
		}
		nLen := (n.BitLen() + 7) / 8
		lambdaSec, err := secret.NewScalar(paillierct.FixedEncode(lambdaBig, nLen), nLen)
		if err != nil {
			continue
		}
		muSec, err := secret.NewScalar(paillierct.FixedEncode(muBig, nLen), nLen)
		if err != nil {
			continue
		}
		return &PrivateKey{
			PublicKey: PublicKey{
				N:        n,
				NSquared: nSquared,
				G:        g,
			},
			Lambda: lambdaSec,
			Mu:     muSec,
			P:      p,
			Q:      q,
		}, nil
	}
}

type primeResult struct {
	prime *big.Int
	err   error
}

type primeSide uint8

const (
	primeSideP primeSide = iota + 1
	primeSideQ
)

type primeSearchResult struct {
	side  primeSide
	prime *big.Int
	err   error
}

type primeSearchFunc func(context.Context, primeSide, int, int) (*big.Int, error)

func generatePrimePair(ctx context.Context, reader io.Reader, bits int) (*big.Int, *big.Int, error) {
	return generatePrimePairWithSearch(ctx, bits, func(ctx context.Context, _ primeSide, bits int, workers int) (*big.Int, error) {
		return safePrimeWithWorkers(ctx, reader, bits, workers)
	})
}

func generatePrimePairWithSearch(ctx context.Context, bits int, search primeSearchFunc) (*big.Int, *big.Int, error) {
	pBits := bits / 2
	qBits := bits - bits/2

	totalWorkers := max(min(runtime.GOMAXPROCS(0), 8), 2)
	pWorkers := max(totalWorkers/2, 1)
	qWorkers := max(totalWorkers-pWorkers, 1)

	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan primeSearchResult, 2)
	launch := func(side primeSide, bits int, workers int) {
		go func() {
			prime, err := search(searchCtx, side, bits, workers)
			resultCh <- primeSearchResult{side: side, prime: prime, err: err}
		}()
	}
	launch(primeSideP, pBits, pWorkers)
	launch(primeSideQ, qBits, qWorkers)

	var p, q *big.Int
	for {
		var result primeSearchResult
		select {
		case result = <-resultCh:
		case <-ctx.Done():
			cancel()
			return nil, nil, ctx.Err()
		}

		if result.err != nil {
			cancel()
			return nil, nil, result.err
		}
		switch result.side {
		case primeSideP:
			p = result.prime
		case primeSideQ:
			q = result.prime
		}

		if p == nil || q == nil {
			continue
		}
		if p.Cmp(q) != 0 {
			return p, q, nil
		}
		// Equal factors are overwhelmingly unlikely, but if they occur keep
		// the first factor and refresh only q instead of discarding both.
		q = nil
		launch(primeSideQ, qBits, qWorkers)
	}
}

func sameReader(a, b io.Reader) bool {
	if a == nil || b == nil {
		return a == b
	}
	aType := reflect.TypeOf(a)
	bType := reflect.TypeOf(b)
	if aType != bType || !aType.Comparable() {
		return false
	}
	return a == b
}

// lockedReader serializes Read calls with a mutex so that an arbitrary
// reader can be used concurrently by prime-search goroutines. The mutex
// overhead is negligible compared to the cost of primality testing.
type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

// Read implements io.Reader by serializing calls to the underlying reader with a mutex.
func (lr *lockedReader) Read(p []byte) (int, error) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.r.Read(p)
}

func safePrimeWithWorkers(ctx context.Context, reader io.Reader, bits, workers int) (*big.Int, error) {
	if workers <= 1 {
		workers = 2
	}
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan primeResult, workers)
	for range workers {
		go func() {
			prime, err := safePrime(searchCtx, reader, bits)
			results <- primeResult{prime: prime, err: err}
		}()
	}

	var firstErr error
	for range workers {
		result := <-results
		if result.err == nil {
			cancel()
			return result.prime, nil
		}
		if firstErr == nil {
			firstErr = result.err
		}
		if err := ctx.Err(); err != nil {
			cancel()
			return nil, err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, context.Canceled
}

// safePrime generates a safe prime p = 2p' + 1 where p' is also prime.
// For bits >= 1024, safe primes are enforced because they are required for
// the CGGMP21 security proof. For smaller sizes (tests), a random Blum prime
// is returned directly for speed — the modulus will still be validated against
// safe-prime structural constraints by ValidateBits.
func safePrime(ctx context.Context, reader io.Reader, bits int) (*big.Int, error) {
	if bits < 1024 {
		return randomBlumPrime(ctx, reader, bits)
	}

	qBytes := make([]byte, (bits-1+7)/8)
	q := new(big.Int)
	p := new(big.Int)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(reader, qBytes); err != nil {
			return nil, err
		}
		setPrimeCandidateBits(qBytes, bits-1, false)
		if !passesSophieGermainSieve(qBytes) {
			continue
		}
		q.SetBytes(qBytes)
		if !q.ProbablyPrime(0) {
			continue
		}
		p.Lsh(q, 1)
		p.SetBit(p, 0, 1)
		if p.BitLen() != bits || !p.ProbablyPrime(0) {
			continue
		}
		if !q.ProbablyPrime(64) || !p.ProbablyPrime(64) {
			continue
		}
		return new(big.Int).Set(p), nil
	}
}

func randomBlumPrime(ctx context.Context, reader io.Reader, bits int) (*big.Int, error) {
	candidateBytes := make([]byte, (bits+7)/8)
	candidate := new(big.Int)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(reader, candidateBytes); err != nil {
			return nil, err
		}
		setPrimeCandidateBits(candidateBytes, bits, true)
		if !passesPrimeSieve(candidateBytes) {
			continue
		}
		candidate.SetBytes(candidateBytes)
		if candidate.ProbablyPrime(20) {
			return new(big.Int).Set(candidate), nil
		}
	}
}

func setPrimeCandidateBits(candidate []byte, bits int, blum bool) {
	topBits := uint(bits % 8)
	if topBits == 0 {
		topBits = 8
	}
	candidate[0] &= uint8(int(1<<topBits) - 1)
	// Set the top two bits so products of equal-width factors do not lose
	// a modulus bit. This mirrors crypto/rand.Prime's key-size invariant.
	if topBits >= 2 {
		candidate[0] |= 3 << (topBits - 2)
	} else {
		candidate[0] |= 1
		if len(candidate) > 1 {
			candidate[1] |= 0x80
		}
	}
	if blum {
		candidate[len(candidate)-1] |= 3
		return
	}
	candidate[len(candidate)-1] |= 1
}

func passesPrimeSieve(candidate []byte) bool {
	for _, group := range smallPrimeSieveGroups {
		remainder := bigEndianModUint64(candidate, group.product)
		for _, prime := range group.primes {
			if remainder%uint64(prime) == 0 {
				return false
			}
		}
	}
	return true
}

func passesSophieGermainSieve(qCandidate []byte) bool {
	for _, group := range smallPrimeSieveGroups {
		remainder := bigEndianModUint64(qCandidate, group.product)
		for _, prime := range group.primes {
			qMod := remainder % uint64(prime)
			if qMod == 0 || (2*qMod+1)%uint64(prime) == 0 {
				return false
			}
		}
	}
	return true
}

func bigEndianModUint64(encoded []byte, modulus uint64) uint64 {
	var remainder uint64
	for _, b := range encoded {
		remainder = ((remainder << 8) + uint64(b)) % modulus
	}
	return remainder
}

type smallPrimeSieveGroup struct {
	product uint64
	primes  []uint16
}

var smallPrimeSieveGroups = buildSmallPrimeSieveGroups()

func buildSmallPrimeSieveGroups() []smallPrimeSieveGroup {
	const maxProduct = ^uint64(0) >> 8
	groups := make([]smallPrimeSieveGroup, 0, 24)
	product := uint64(1)
	start := 0
	for i, prime := range smallPrimeSievePrimes {
		p := uint64(prime)
		if product > maxProduct/p {
			groups = append(groups, smallPrimeSieveGroup{
				product: product,
				primes:  smallPrimeSievePrimes[start:i],
			})
			product = 1
			start = i
		}
		product *= p
	}
	groups = append(groups, smallPrimeSieveGroup{
		product: product,
		primes:  smallPrimeSievePrimes[start:],
	})
	return groups
}

var smallPrimeSievePrimes = [...]uint16{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
	127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
	191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
	257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
	331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
	401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
	467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
	563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
	631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
	709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
	797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
	877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
	967, 971, 977, 983, 991, 997,
}
