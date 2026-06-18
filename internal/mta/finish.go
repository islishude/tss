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
func Finish(params zkpai.SecurityParams, responseDomain []byte, start StartMessage, response ResponseMessage, bCommitment []byte, skA *pai.PrivateKey, pkB *pai.PublicKey, verifierAux zkpai.RingPedersenParams) (*secret.Scalar, error) {
	if skA == nil {
		return nil, errors.New("nil Paillier private key")
	}
	if err := start.Validate(); err != nil {
		return nil, err
	}
	proof, err := zkpai.UnmarshalAffGProof(response.Proof)
	if err != nil {
		return nil, err
	}
	encA := new(big.Int).SetBytes(start.Ciphertext)
	resp := new(big.Int).SetBytes(response.Ciphertext)

	bCommit, err := secp.PointFromBytes(bCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid b commitment: %w", err)
	}

	stmt := zkpai.AffGStatement{
		ReceiverPaillierN: &skA.PublicKey,
		ProverPaillierN:   pkB,
		C:                 encA,
		D:                 resp,
		Y:                 proof.Y, // Y is carried in the proof
		X:                 bCommit,
		VerifierAux:       verifierAux,
	}

	if err := zkpai.VerifyAffG(params, responseDomain, stmt, proof); err != nil {
		return nil, fmt.Errorf("invalid MtA response proof: %w", err)
	}
	alpha, err := skA.Decrypt(resp)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(alpha)
	alpha.Mod(alpha, secp.Order())
	return secret.NewScalar(alpha.FillBytes(make([]byte, secp.ScalarSize)), secp.ScalarSize)
}
