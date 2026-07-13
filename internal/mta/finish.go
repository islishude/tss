package mta

import (
	"errors"
	"fmt"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// Finish verifies the AffG response proof and decrypts the alpha share.
//
// Parameters:
//   - skA: initiator's Paillier private key
//   - pkB: responder's Paillier public key (Ni in Πaff-g)
//   - verifierAux: initiator's own Ring-Pedersen parameters
func Finish(params zkpai.SecurityParams, responseDomain []byte, start StartMessage, response ResponseMessage, bCommitment []byte, skA *pai.PrivateKey, pkB *pai.PublicKey, verifierAux *zkpai.RingPedersenParams) (*secret.Scalar, error) {
	if skA == nil {
		return nil, errors.New("nil Paillier private key")
	}
	if pkB == nil {
		return nil, errors.New("nil Paillier public key")
	}
	if verifierAux == nil {
		return nil, errors.New("nil RingPedersenParams")
	}
	if err := VerifyResponse(params, responseDomain, start, response, bCommitment, skA.PublicKey, pkB, verifierAux); err != nil {
		return nil, err
	}
	resp := new(big.Int).SetBytes(response.Ciphertext)
	alpha, err := skA.Decrypt(resp)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(alpha)
	// Paillier decryption returns the canonical residue in [0, N), while the
	// CGGMP21 affine relation uses a signed plaintext in the centered interval.
	// A negative x*k+y therefore decrypts as N-|x*k+y| and must be restored
	// before reducing the initiator's additive share modulo the curve order.
	halfN := new(big.Int).Rsh(new(big.Int).Set(skA.N), 1)
	defer secret.ClearBigInt(halfN)
	if alpha.Cmp(halfN) > 0 {
		alpha.Sub(alpha, skA.N)
	}
	alpha.Mod(alpha, secp.Order())
	return secret.NewScalar(alpha.FillBytes(make([]byte, secp.ScalarSize)), secp.ScalarSize)
}

// VerifyResponse verifies an MtA affine response without decrypting it.
func VerifyResponse(params zkpai.SecurityParams, responseDomain []byte, start StartMessage, response ResponseMessage, bCommitment []byte, pkA, pkB *pai.PublicKey, verifierAux *zkpai.RingPedersenParams) error {
	if pkA == nil || pkB == nil {
		return errors.New("nil Paillier public key")
	}
	if verifierAux == nil {
		return errors.New("nil RingPedersenParams")
	}
	if err := start.Validate(); err != nil {
		return err
	}
	if err := response.Validate(); err != nil {
		return err
	}
	bCommit, err := secp.PointFromBytes(bCommitment)
	if err != nil {
		return fmt.Errorf("invalid b commitment: %w", err)
	}
	stmt := zkpai.AffGStatement{
		ReceiverPaillierN: pkA,
		ProverPaillierN:   pkB,
		C:                 new(big.Int).SetBytes(start.Ciphertext),
		D:                 new(big.Int).SetBytes(response.Ciphertext),
		Y:                 new(big.Int).SetBytes(response.F),
		X:                 bCommit,
		VerifierAux:       verifierAux,
	}
	if err := zkpai.VerifyAffG(params, responseDomain, stmt, &response.Proof); err != nil {
		return fmt.Errorf("invalid MtA response proof: %w", err)
	}
	return nil
}
