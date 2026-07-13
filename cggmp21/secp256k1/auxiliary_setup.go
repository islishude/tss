package secp256k1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// ringPedersenDomainBuilder constructs the lifecycle-specific Πprm domain
// after the independently generated public parameters are known.
type ringPedersenDomainBuilder func(*zkpai.RingPedersenParams) ([]byte, error)

// generateIndependentRingPedersen creates an auxiliary modulus independently
// from forbiddenPaillierN. The temporary factors and discrete-log witness are
// destroyed before this function returns; only public parameters and Πprm
// leave the ownership boundary.
func generateIndependentRingPedersen(
	ctx context.Context,
	reader io.Reader,
	bits int,
	forbiddenPaillierN *big.Int,
	party tss.PartyID,
	buildDomain ringPedersenDomainBuilder,
) (*zkpai.RingPedersenParams, *zkpai.RingPedersenProof, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil auxiliary setup context")
	}
	if reader == nil {
		return nil, nil, errors.New("nil auxiliary setup randomness")
	}
	if forbiddenPaillierN == nil || forbiddenPaillierN.Sign() <= 0 {
		return nil, nil, errors.New("invalid forbidden Paillier modulus")
	}
	if party == tss.BroadcastPartyId {
		return nil, nil, errors.New("invalid auxiliary setup party")
	}
	if buildDomain == nil {
		return nil, nil, errors.New("nil auxiliary setup domain builder")
	}

	auxiliaryKey, err := generatePaillierKey(ctx, reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate independent auxiliary modulus: %w", err)
	}
	return proveIndependentRingPedersen(reader, forbiddenPaillierN, party, buildDomain, auxiliaryKey)
}

// proveIndependentRingPedersen consumes auxiliaryKey on every return path.
// Keeping this ownership boundary separate makes equality and cleanup failures
// directly testable without replacing a package-wide randomness dependency.
func proveIndependentRingPedersen(
	reader io.Reader,
	forbiddenPaillierN *big.Int,
	party tss.PartyID,
	buildDomain ringPedersenDomainBuilder,
	auxiliaryKey *pai.PrivateKey,
) (*zkpai.RingPedersenParams, *zkpai.RingPedersenProof, error) {
	if auxiliaryKey == nil {
		return nil, nil, errors.New("nil auxiliary factor key")
	}
	defer auxiliaryKey.Destroy()
	if auxiliaryKey.PublicKey == nil || auxiliaryKey.N == nil {
		return nil, nil, errors.New("invalid auxiliary factor key")
	}
	if reader == nil {
		return nil, nil, errors.New("nil auxiliary setup randomness")
	}
	if forbiddenPaillierN == nil || forbiddenPaillierN.Sign() <= 0 {
		return nil, nil, errors.New("invalid forbidden Paillier modulus")
	}
	if party == tss.BroadcastPartyId {
		return nil, nil, errors.New("invalid auxiliary setup party")
	}
	if buildDomain == nil {
		return nil, nil, errors.New("nil auxiliary setup domain builder")
	}
	if auxiliaryKey.N.Cmp(forbiddenPaillierN) == 0 {
		return nil, nil, errors.New("paillier and Ring-Pedersen auxiliary moduli must be independent")
	}

	params, lambda, err := zkpai.GenerateRingPedersenParams(reader, auxiliaryKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ring-Pedersen parameters: %w", err)
	}
	defer lambda.Destroy()
	if params.N.Cmp(forbiddenPaillierN) == 0 {
		return nil, nil, errors.New("paillier and Ring-Pedersen auxiliary moduli must differ")
	}

	domain, err := buildDomain(params)
	if err != nil {
		return nil, nil, fmt.Errorf("build Ring-Pedersen proof domain: %w", err)
	}
	proof, err := zkpai.ProveRingPedersen(reader, domain, auxiliaryKey, params, lambda, party)
	if err != nil {
		return nil, nil, fmt.Errorf("prove Ring-Pedersen parameters: %w", err)
	}
	return params, proof, nil
}
