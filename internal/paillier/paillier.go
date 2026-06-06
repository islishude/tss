package paillier

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"runtime"
	"sync"

	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

// DefaultMinModulusBits is the minimum modulus size accepted outside tests.
// 3072 bits provides ~128-bit classical security matching secp256k1 (NIST SP 800-57).
const DefaultMinModulusBits = 3072

var minModulusBits = DefaultMinModulusBits

// PublicKey contains Paillier public parameters and cached n^2.
type PublicKey struct {
	N        *big.Int
	NSquared *big.Int
	G        *big.Int
}

// PrivateKey contains Paillier secret factors and decryption exponents.
// Lambda and Mu use fixed-length secret.Scalar to prevent accidental logging,
// variable-length encoding, and non-constant-time conversion of secret material.
type PrivateKey struct {
	PublicKey
	Lambda *secret.Scalar
	Mu     *secret.Scalar
	P      *big.Int
	Q      *big.Int
}

// MarshalJSON rejects default JSON encoding of Paillier private keys.
func (sk PrivateKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("paillier private key contains secret material; use MarshalBinary")
}

// Destroy clears Paillier private exponents and factors in place.
func (sk *PrivateKey) Destroy() {
	if sk == nil {
		return
	}
	sk.Lambda.Destroy()
	sk.Mu.Destroy()
	secret.ClearBigInt(sk.P)
	secret.ClearBigInt(sk.Q)
}

const paillierWireVersion = 1

const (
	publicKeyWireType  = "paillier.public-key"
	privateKeyWireType = "paillier.private-key"
)

const (
	publicKeyFieldN uint16 = iota + 1
	publicKeyFieldG
)

const (
	privateKeyFieldN uint16 = iota + 1
	privateKeyFieldG
	privateKeyFieldLambda
	privateKeyFieldMu
	privateKeyFieldP
	privateKeyFieldQ
)

// MinimumModulusBits is the minimum Paillier modulus size GenerateKey accepts.
const MinimumModulusBits = 512

// GenerateKey creates a Paillier key using safe primes (Sophie Germain primes)
// where p = 2p' + 1, q = 2q' + 1 with p', q' also prime, and the g=n+1 variant.
// Safe primes ensure the Blum condition p ≡ q ≡ 3 (mod 4) automatically.
// The context is checked in each prime-search iteration to support cancellation.
//
// crypto/rand.Reader is documented as safe for concurrent use and is used
// directly. Any other reader is wrapped with an internal mutex so that Read
// calls are serialized safely across prime-search goroutines; the mutex
// overhead is negligible compared to primality testing.
func GenerateKey(ctx context.Context, reader io.Reader, bits int) (*PrivateKey, error) {
	if bits < MinimumModulusBits {
		return nil, fmt.Errorf("paillier modulus must be at least %d bits", MinimumModulusBits)
	}

	// crypto/rand.Reader is documented as concurrent-safe; serialise all
	// other readers so the parallel prime search is safe regardless of
	// the reader implementation.
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
	return generatePrimePairWithSearch(ctx, bits, func(ctx context.Context, _ primeSide, bits, workers int) (*big.Int, error) {
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
	launch := func(side primeSide, bits, workers int) {
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

// SetMinimumModulusBitsForTesting overrides validation policy for tests.
func SetMinimumModulusBitsForTesting(bits int) func() {
	old := minModulusBits
	minModulusBits = bits
	return func() { minModulusBits = old }
}

// Validate checks the public key against the package minimum modulus size.
func (pk PublicKey) Validate() error {
	return pk.ValidateBits(minModulusBits)
}

// ValidateBits checks public key structure against an explicit minimum size.
func (pk PublicKey) ValidateBits(minBits int) error {
	if pk.N == nil || pk.N.Sign() <= 0 {
		return errors.New("invalid modulus")
	}
	if pk.N.Bit(0) == 0 {
		return errors.New("paillier modulus must be odd")
	}
	if minBits > 0 && pk.N.BitLen() < minBits {
		return fmt.Errorf("paillier modulus has %d bits, need at least %d", pk.N.BitLen(), minBits)
	}
	if pk.N.ProbablyPrime(64) {
		return errors.New("paillier modulus must be composite")
	}
	// Safe-prime structural checks: for p = 2p'+1, q = 2q'+1, we have
	// N ≡ 1 (mod 4) and N mod 3 ≠ 0 (excludes p=3 or q=3 which makes
	// (p-1)/2 = 1 not prime).
	four := big.NewInt(4)
	three := big.NewInt(3)
	if new(big.Int).Mod(pk.N, four).Cmp(big.NewInt(1)) != 0 {
		return errors.New("paillier modulus must be ≡ 1 mod 4 for safe primes")
	}
	if new(big.Int).Mod(pk.N, three).Sign() == 0 {
		return errors.New("paillier modulus must not be divisible by 3")
	}
	if pk.NSquared == nil || pk.NSquared.Cmp(new(big.Int).Mul(pk.N, pk.N)) != 0 {
		return errors.New("invalid n squared")
	}
	if pk.G == nil || pk.G.Sign() <= 0 || pk.G.Cmp(pk.NSquared) >= 0 {
		return errors.New("invalid generator")
	}
	if pk.G.Cmp(new(big.Int).Add(pk.N, big.NewInt(1))) != 0 {
		return errors.New("paillier generator must be n+1")
	}
	return nil
}

// Validate checks both public Paillier parameters and private CRT material.
func (sk PrivateKey) Validate() error {
	if err := sk.PublicKey.Validate(); err != nil {
		return err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return errors.New("invalid secret scalar")
	}
	for name, value := range map[string]*big.Int{
		"p": sk.P,
		"q": sk.Q,
	} {
		if value == nil || value.Sign() <= 0 {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if sk.P.Cmp(sk.Q) == 0 {
		return errors.New("paillier factors must differ")
	}
	if new(big.Int).Mul(sk.P, sk.Q).Cmp(sk.N) != 0 {
		return errors.New("paillier factors do not multiply to modulus")
	}
	if !sk.P.ProbablyPrime(64) || !sk.Q.ProbablyPrime(64) {
		return errors.New("paillier factors must be prime")
	}
	lambdaBig := scalarToBig(sk.Lambda)
	wantLambda := lcm(new(big.Int).Sub(sk.P, big.NewInt(1)), new(big.Int).Sub(sk.Q, big.NewInt(1)))
	if lambdaBig.Cmp(wantLambda) != 0 {
		return errors.New("invalid paillier lambda")
	}
	// For the enforced g=n+1 variant, L(g^lambda mod n^2) = lambda mod n.
	// This avoids variable-time modular exponentiation with secret lambda.
	wantMu := new(big.Int).ModInverse(lambdaBig, sk.N)
	if wantMu == nil || scalarToBig(sk.Mu).Cmp(wantMu) != 0 {
		return errors.New("invalid paillier mu")
	}
	return nil
}

// scalarToBig converts a fixed-length secret.Scalar to a *big.Int.
// This is unexported; callers outside the paillier package must use
// the constant-time paths provided by paillierct.
func scalarToBig(s *secret.Scalar) *big.Int {
	if s == nil {
		return nil
	}
	return new(big.Int).SetBytes(s.FixedBytes())
}

// MarshalBinary returns a deterministic TLV public-key record.
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	n, err := encodePositiveInt(pk.N)
	if err != nil {
		return nil, err
	}
	g, err := encodePositiveInt(pk.G)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(paillierWireVersion, publicKeyWireType, []wire.Field{
		{Tag: publicKeyFieldN, Value: n},
		{Tag: publicKeyFieldG, Value: g},
	})
}

// UnmarshalPublicKey decodes and rejects non-canonical public-key encodings.
func UnmarshalPublicKey(in []byte) (*PublicKey, error) {
	version, fields, err := wire.Unmarshal(in, publicKeyWireType)
	if err != nil {
		return nil, err
	}
	if version != paillierWireVersion {
		return nil, fmt.Errorf("unexpected Paillier public-key version %d", version)
	}
	if err := requireExactKeyTags(fields, publicKeyFieldN, publicKeyFieldG); err != nil {
		return nil, err
	}
	n, err := decodePositiveIntField(fields, publicKeyFieldN)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntField(fields, publicKeyFieldG)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	pk := &PublicKey{
		N:        n,
		NSquared: new(big.Int).Mul(n, n),
		G:        g,
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	return pk, nil
}

// MarshalBinary returns a deterministic TLV private-key record.
func (sk PrivateKey) MarshalBinary() ([]byte, error) {
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	n, err := encodePositiveInt(sk.N)
	if err != nil {
		return nil, err
	}
	g, err := encodePositiveInt(sk.G)
	if err != nil {
		return nil, err
	}
	lambda, err := encodePositiveInt(scalarToBig(sk.Lambda))
	if err != nil {
		return nil, err
	}
	mu, err := encodePositiveInt(scalarToBig(sk.Mu))
	if err != nil {
		return nil, err
	}
	p, err := encodePositiveInt(sk.P)
	if err != nil {
		return nil, err
	}
	q, err := encodePositiveInt(sk.Q)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(paillierWireVersion, privateKeyWireType, []wire.Field{
		{Tag: privateKeyFieldN, Value: n},
		{Tag: privateKeyFieldG, Value: g},
		{Tag: privateKeyFieldLambda, Value: lambda},
		{Tag: privateKeyFieldMu, Value: mu},
		{Tag: privateKeyFieldP, Value: p},
		{Tag: privateKeyFieldQ, Value: q},
	})
}

// UnmarshalPrivateKey decodes and rejects non-canonical private-key encodings.
func UnmarshalPrivateKey(in []byte) (*PrivateKey, error) {
	version, fields, err := wire.Unmarshal(in, privateKeyWireType)
	if err != nil {
		return nil, err
	}
	if version != paillierWireVersion {
		return nil, fmt.Errorf("unexpected Paillier private-key version %d", version)
	}
	if err := requireExactKeyTags(fields, privateKeyFieldN, privateKeyFieldG, privateKeyFieldLambda, privateKeyFieldMu, privateKeyFieldP, privateKeyFieldQ); err != nil {
		return nil, err
	}
	n, err := decodePositiveIntField(fields, privateKeyFieldN)
	if err != nil {
		return nil, fmt.Errorf("invalid public modulus: %w", err)
	}
	g, err := decodePositiveIntField(fields, privateKeyFieldG)
	if err != nil {
		return nil, fmt.Errorf("invalid public generator: %w", err)
	}
	lambdaBig, err := decodePositiveIntField(fields, privateKeyFieldLambda)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	muBig, err := decodePositiveIntField(fields, privateKeyFieldMu)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	p, err := decodePositiveIntField(fields, privateKeyFieldP)
	if err != nil {
		return nil, fmt.Errorf("invalid p: %w", err)
	}
	q, err := decodePositiveIntField(fields, privateKeyFieldQ)
	if err != nil {
		return nil, fmt.Errorf("invalid q: %w", err)
	}
	nLen := (n.BitLen() + 7) / 8
	lambdaSec, err := secret.NewScalar(paillierct.FixedEncode(lambdaBig, nLen), nLen)
	if err != nil {
		return nil, fmt.Errorf("invalid lambda: %w", err)
	}
	muSec, err := secret.NewScalar(paillierct.FixedEncode(muBig, nLen), nLen)
	if err != nil {
		return nil, fmt.Errorf("invalid mu: %w", err)
	}
	sk := &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        g,
		},
		Lambda: lambdaSec,
		Mu:     muSec,
		P:      p,
		Q:      q,
	}
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	return sk, nil
}

// Encrypt encrypts message with fresh random invertible Paillier randomness.
func (pk PublicKey) Encrypt(reader io.Reader, message *big.Int) (*big.Int, *big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, nil, err
	}
	if message == nil {
		return nil, nil, errors.New("nil message")
	}
	// r must be invertible modulo n; otherwise encryption is not in Z*_n^2.
	r, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, nil, err
	}
	c, err := pk.EncryptWithRandomness(message, r)
	if err != nil {
		return nil, nil, err
	}
	return c, r, nil
}

// EncryptWithRandomness encrypts message using caller-provided randomness r.
func (pk PublicKey) EncryptWithRandomness(message, r *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if message == nil || r == nil {
		return nil, errors.New("nil encryption input")
	}
	if new(big.Int).GCD(nil, nil, r, pk.N).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("paillier randomness is not invertible")
	}
	m := mod(message, pk.N)
	gm := new(big.Int).Exp(pk.G, m, pk.NSquared)
	rn := new(big.Int).Exp(r, pk.N, pk.NSquared)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.NSquared)
	return c, nil
}

// Decrypt recovers a plaintext representative from a Paillier ciphertext.
// The ciphertext must be a member of Z*_{n^2} — callers that have not already
// validated the ciphertext through a proof or explicit check should use
// ValidateCiphertext first. The c^λ mod n² step uses constant-time modular
// exponentiation via filippo.io/bigmod with ciphertext blinding to defeat
// side-channel attacks on the secret exponent λ.
func (sk PrivateKey) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if err := sk.Validate(); err != nil {
		return nil, err
	}
	if sk.Lambda == nil || sk.Mu == nil {
		return nil, errors.New("invalid private key")
	}
	if err := sk.ValidateCiphertext(ciphertext); err != nil {
		return nil, fmt.Errorf("invalid ciphertext for decryption: %w", err)
	}

	nLen := (sk.N.BitLen() + 7) / 8
	nBytes := paillierct.FixedEncode(sk.N, nLen)
	nSquaredBytes := paillierct.FixedEncode(sk.NSquared, 2*nLen)

	// u = c^λ mod n² via constant-time exponentiation with ciphertext blinding.
	ct, err := paillierct.NewPrivateModExp(nSquaredBytes, nLen)
	if err != nil {
		return nil, fmt.Errorf("paillierct init: %w", err)
	}
	cBytes := paillierct.FixedEncode(ciphertext, len(nSquaredBytes))
	lambdaBytes := sk.Lambda.FixedBytes()
	uBytes, err := ct.ExpSecretBlinded(rand.Reader, cBytes, lambdaBytes, nBytes)
	if err != nil {
		return nil, fmt.Errorf("paillier decryption: %w", err)
	}

	// L(u) = (u - 1) / n. The division is exact for valid Paillier ciphertexts
	// and only depends on the public modulus n.
	u := new(big.Int).SetBytes(uBytes)
	l := L(u, sk.N)

	// m = L(u) * μ mod n using math/big. The exponentiation is already
	// constant-time and ciphertext-blinded; the marginal timing variation
	// from a single multiplication is not practically exploitable.
	muBig := scalarToBig(sk.Mu)
	m := new(big.Int).Mul(l, muBig)
	m.Mod(m, sk.N)
	return m, nil
}

// ValidateCiphertext checks ciphertext membership in Z*_{n^2}.
func (pk PublicKey) ValidateCiphertext(ciphertext *big.Int) error {
	if err := pk.Validate(); err != nil {
		return err
	}
	if ciphertext == nil || ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return errors.New("ciphertext out of range")
	}
	if new(big.Int).GCD(nil, nil, ciphertext, pk.NSquared).Cmp(big.NewInt(1)) != 0 {
		return errors.New("ciphertext is not in Z*_{n^2}")
	}
	return nil
}

// AddCiphertexts homomorphically adds two encrypted plaintexts.
// Both inputs must be in Z*_{n^2}; use AddCiphertextsUnchecked when
// membership has already been verified upstream.
func (pk PublicKey) AddCiphertexts(a, b *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if a == nil || b == nil {
		return nil, errors.New("nil ciphertext")
	}
	if err := pk.ValidateCiphertext(a); err != nil {
		return nil, err
	}
	if err := pk.ValidateCiphertext(b); err != nil {
		return nil, err
	}
	return pk.AddCiphertextsUnchecked(a, b)
}

// AddCiphertextsUnchecked homomorphically adds two encrypted plaintexts
// without validating ciphertext membership in Z*_{n^2}. Callers must ensure
// both inputs have been validated through upstream proof checks. Basic
// range checks are still enforced to catch nil, zero, and out-of-range values.
func (pk PublicKey) AddCiphertextsUnchecked(a, b *big.Int) (*big.Int, error) {
	if a == nil || b == nil {
		return nil, errors.New("nil ciphertext")
	}
	if a.Sign() <= 0 || a.Cmp(pk.NSquared) >= 0 || b.Sign() <= 0 || b.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	out := new(big.Int).Mul(a, b)
	out.Mod(out, pk.NSquared)
	return out, nil
}

// AddPlaintext homomorphically adds plaintext to an encrypted value.
// The ciphertext must be in Z*_{n^2}; use AddPlaintextUnchecked when
// membership has already been verified upstream.
func (pk PublicKey) AddPlaintext(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, err
	}
	return pk.AddPlaintextUnchecked(ciphertext, plaintext)
}

// AddPlaintextUnchecked homomorphically adds plaintext to an encrypted value
// without validating ciphertext membership in Z*_{n^2}. Callers must ensure
// the ciphertext has been validated through upstream proof checks. Basic
// range checks are still enforced to catch nil, zero, and out-of-range values.
func (pk PublicKey) AddPlaintextUnchecked(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	gm := new(big.Int).Exp(pk.G, mod(plaintext, pk.N), pk.NSquared)
	out := new(big.Int).Mul(ciphertext, gm)
	out.Mod(out, pk.NSquared)
	return out, nil
}

// MulPlaintext homomorphically multiplies an encrypted value by public plaintext.
// The plaintext argument must not contain secret scalar or nonce material; this
// helper uses variable-time public exponentiation and is not a secret-exponent
// protocol primitive. The ciphertext must be in Z*_{n^2}; use
// MulPlaintextUnchecked when membership has already been verified upstream.
func (pk PublicKey) MulPlaintext(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, err
	}
	return pk.MulPlaintextUnchecked(ciphertext, plaintext)
}

// MulPlaintextUnchecked homomorphically multiplies an encrypted value by public
// plaintext without validating ciphertext membership in Z*_{n^2}. Callers must
// ensure the ciphertext has been validated through upstream proof checks. Basic
// range checks are still enforced to catch nil, zero, and out-of-range values.
func (pk PublicKey) MulPlaintextUnchecked(ciphertext, plaintext *big.Int) (*big.Int, error) {
	if ciphertext == nil || plaintext == nil {
		return nil, errors.New("nil input")
	}
	if ciphertext.Sign() <= 0 || ciphertext.Cmp(pk.NSquared) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	out := new(big.Int).Exp(ciphertext, mod(plaintext, pk.N), pk.NSquared)
	return out, nil
}

// L computes Paillier's L(u) = (u - 1) / n helper.
func L(u, n *big.Int) *big.Int {
	// L(u) = (u - 1) / n in Paillier decryption.
	out := new(big.Int).Sub(u, big.NewInt(1))
	out.Div(out, n)
	return out
}

func randomCoprime(reader io.Reader, n *big.Int) (*big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	one := big.NewInt(1)
	for {
		r, err := rand.Int(reader, n)
		if err != nil {
			return nil, err
		}
		if r.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, r, n).Cmp(one) == 0 {
			return r, nil
		}
	}
}

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	out := new(big.Int).Div(new(big.Int).Mul(a, b), g)
	return out.Abs(out)
}

func mod(x, m *big.Int) *big.Int {
	out := new(big.Int).Mod(x, m)
	if out.Sign() < 0 {
		out.Add(out, m)
	}
	return out
}

func requireExactKeyTags(fields []wire.Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("got %d fields, want %d", len(fields), len(tags))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected field tag %d at index %d", fields[i].Tag, i)
		}
	}
	return nil
}

func encodePositiveInt(x *big.Int) ([]byte, error) {
	if x == nil || x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x.Bytes(), nil
}

func decodePositiveIntField(fields []wire.Field, tag uint16) (*big.Int, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty integer")
	}
	if raw[0] == 0 {
		return nil, errors.New("non-minimal integer encoding")
	}
	x := new(big.Int).SetBytes(raw)
	if x.Sign() <= 0 {
		return nil, errors.New("integer must be positive")
	}
	return x, nil
}
