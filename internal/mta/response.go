package mta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	responseMessageWireType    = "mta.response-message"
	responseMessageWireVersion = 1
)

// ResponseMessage carries an MtA ciphertext response and transcript proof.
type ResponseMessage struct {
	Ciphertext []byte          `json:"ciphertext" wire:"1,bytes"`
	Proof      zkpai.AffGProof `json:"proof" wire:"2,nested,max_bytes=zk_proof"`
}

// WireType returns the canonical wire type identifier for ResponseMessage.
func (ResponseMessage) WireType() string { return responseMessageWireType }

// WireVersion returns the wire format version for ResponseMessage.
func (ResponseMessage) WireVersion() uint16 { return responseMessageWireVersion }

// MarshalBinary encodes the MtA response message using the object-level wire codec.
func (m ResponseMessage) MarshalBinary() ([]byte, error) {
	return wire.Marshal(m, wire.WithFieldLimitsForMarshal(responseMessageFieldLimits()))
}

// UnmarshalResponseMessage decodes a TLV MtA response message using the object-level wire codec.
func UnmarshalResponseMessage(in []byte) (*ResponseMessage, error) {
	msg := new(ResponseMessage)
	if err := msg.UnmarshalBinary(in); err != nil {
		return nil, err
	}
	return msg, nil
}

// UnmarshalBinary decodes a TLV MtA response message.
func (m *ResponseMessage) UnmarshalBinary(in []byte) error {
	var decoded ResponseMessage
	if err := wire.Unmarshal(in, &decoded, wire.WithFieldLimits(responseMessageFieldLimits())); err != nil {
		return err
	}
	*m = decoded
	return nil
}

// Validate checks the canonical AffG proof record and ciphertext integer.
func (m ResponseMessage) Validate() error {
	if err := validatePositiveIntegerBytes(m.Ciphertext); err != nil {
		return fmt.Errorf("invalid MtA response ciphertext: %w", err)
	}
	if err := m.Proof.Validate(); err != nil {
		return fmt.Errorf("invalid MtA response proof: %w", err)
	}
	return nil
}

func responseMessageFieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"zk_proof":         tss.DefaultMaxZKProofBytes,
		"paillier_modulus": tss.DefaultMaxPaillierCiphertextBytes,
		"point":            tss.DefaultMaxPointBytes,
		"signed_response":  tss.DefaultMaxPaillierCiphertextBytes,
		"paillier_signed":  tss.DefaultMaxPaillierCiphertextBytes,
	}
}

// Respond creates Enc(a*b+beta) under the initiator's Paillier key and proves
// the response is correctly formed using a Πaff-g proof. It also encrypts beta
// under the responder's own Paillier key for the Y component of the proof.
//
// Parameters:
//   - pkA: initiator's Paillier public key (Nj in Πaff-g)
//   - pkB: responder's own Paillier public key (Ni in Πaff-g)
//   - startVerifierAux: responder's Ring-Pedersen parameters for checking Πenc
//   - affGVerifierAux: initiator's Ring-Pedersen parameters for Πaff-g
//
// Returns the response message and the negated local beta share (-beta mod q).
func Respond(params zkpai.SecurityParams, reader io.Reader, startProofDomain, responseDomain []byte, start StartMessage, startProof *zkpai.EncProof, b *secret.Scalar, bCommitment []byte, pkA, pkB *pai.PublicKey, startVerifierAux, affGVerifierAux zkpai.RingPedersenParams) (*ResponseMessage, *secret.Scalar, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if err := VerifyStart(params, startProofDomain, start, pkA, startVerifierAux, startProof); err != nil {
		return nil, nil, err
	}
	bScalar, err := secpScalarFromSecret(b)
	if err != nil {
		return nil, nil, errors.New("b out of range")
	}

	encA := new(big.Int).SetBytes(start.Ciphertext)
	beta, err := randomSecretScalar(reader)
	if err != nil {
		return nil, nil, err
	}
	defer beta.Destroy()
	encBeta, betaRandomness, err := pkA.EncryptSecret(reader, beta)
	if err != nil {
		return nil, nil, err
	}
	defer betaRandomness.Destroy()

	// encA^b mod N² via constant-time modular exponentiation.
	// Ciphertext blinding is NOT applied here because the ZK proof
	// verifies the exact relationship response = encA^b * encBeta mod N².
	nLen := (pkA.N.BitLen() + 7) / 8
	nSquaredLen := 2 * nLen
	nSquaredBytes := paillierct.FixedEncode(pkA.NSquared, nSquaredLen)
	encABytes := paillierct.FixedEncode(encA, nSquaredLen)
	bBytes := b.FixedBytes()
	defer clear(bBytes)

	encRespBytes, err := paillierct.ExpCT(nSquaredBytes, encABytes, bBytes)
	if err != nil {
		return nil, nil, err
	}
	response := new(big.Int).SetBytes(encRespBytes)
	response.Mul(response, encBeta)
	response.Mod(response, pkA.NSquared)

	// Encrypt beta under the responder's own key for the Y commitment.
	yCiphertext, yRandomness, err := pkB.EncryptSecret(reader, beta)
	if err != nil {
		return nil, nil, err
	}
	defer yRandomness.Destroy()

	// Curve commitment X = b * G.
	X := secp.ScalarBaseMult(bScalar)

	stmt := zkpai.AffGStatement{
		ReceiverPaillierN: pkA,
		ProverPaillierN:   pkB,
		C:                 encA,
		D:                 response,
		Y:                 yCiphertext,
		X:                 X,
		VerifierAux:       affGVerifierAux,
	}
	witness := zkpai.AffGWitness{
		X:    b,
		Y:    beta,
		Rho:  betaRandomness,
		RhoY: yRandomness,
	}

	proof, err := zkpai.ProveAffG(params, responseDomain, stmt, witness, reader)
	if err != nil {
		return nil, nil, err
	}
	betaShareScalar := secp.ScalarNeg(mustSecpScalar(beta))
	betaShare, err := secret.NewScalar(betaShareScalar.Bytes(), secp.ScalarSize)
	if err != nil {
		return nil, nil, err
	}
	return &ResponseMessage{Ciphertext: response.Bytes(), Proof: *proof}, betaShare, nil
}
