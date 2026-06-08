package mta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	responseMessageWireType = "mta.response-message"
)

const (
	responseMessageFieldCiphertext uint16 = iota + 1
	responseMessageFieldProof
)

// ResponseMessage carries an MtA ciphertext response and transcript proof.
type ResponseMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	Proof      []byte `json:"proof"`
}

// MarshalBinary encodes the MtA response message as an exact-field TLV record.
func (m ResponseMessage) MarshalBinary() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(messageVersion, responseMessageWireType, []wire.Field{
		{Tag: responseMessageFieldCiphertext, Value: m.Ciphertext},
		{Tag: responseMessageFieldProof, Value: m.Proof},
	})
}

// UnmarshalResponseMessage decodes an exact-field TLV MtA response message.
func UnmarshalResponseMessage(in []byte) (*ResponseMessage, error) {
	version, fields, err := wire.Unmarshal(in, responseMessageWireType)
	if err != nil {
		return nil, err
	}
	if version != messageVersion {
		return nil, fmt.Errorf("unexpected MtA response message version %d", version)
	}
	if err := wire.RequireExactTags(fields, responseMessageFieldCiphertext, responseMessageFieldProof); err != nil {
		return nil, err
	}
	msg := &ResponseMessage{
		Ciphertext: fields[0].Value,
		Proof:      fields[1].Value,
	}
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	return msg, nil
}

// Validate checks the canonical proof record and ciphertext integer.
// The proof must be a valid AffGProof. Legacy MTAResponseProof payloads are
// rejected rather than supported as a fallback.
func (m ResponseMessage) Validate() error {
	if err := validatePositiveIntegerBytes(m.Ciphertext); err != nil {
		return fmt.Errorf("invalid MtA response ciphertext: %w", err)
	}
	if _, err := zkpai.UnmarshalAffGProof(m.Proof); err != nil {
		return fmt.Errorf("invalid MtA response proof: %w", err)
	}
	return nil
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
func Respond(reader io.Reader, startProofDomain, responseDomain []byte, start StartMessage, startProof []byte, b *big.Int, bCommitment []byte, pkA, pkB *pai.PublicKey, startVerifierAux, affGVerifierAux zkpai.RingPedersenParams) (*ResponseMessage, *big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if err := VerifyStart(startProofDomain, start, pkA, startVerifierAux, startProof); err != nil {
		return nil, nil, err
	}
	if b == nil || b.Sign() <= 0 || b.Cmp(secp.Order()) >= 0 {
		return nil, nil, errors.New("b out of range")
	}

	encA := new(big.Int).SetBytes(start.Ciphertext)
	beta, err := randomScalar(reader)
	if err != nil {
		return nil, nil, err
	}
	encBeta, betaRandomness, err := pkA.Encrypt(reader, beta)
	if err != nil {
		return nil, nil, err
	}

	// encA^b mod N² via constant-time modular exponentiation.
	// Ciphertext blinding is NOT applied here because the ZK proof
	// verifies the exact relationship response = encA^b * encBeta mod N².
	nLen := (pkA.N.BitLen() + 7) / 8
	nSquaredLen := 2 * nLen
	nSquaredBytes := paillierct.FixedEncode(pkA.NSquared, nSquaredLen)
	encABytes := paillierct.FixedEncode(encA, nSquaredLen)
	bBytes := scalarFixedBytes(b)

	encRespBytes, err := paillierct.ExpCT(nSquaredBytes, encABytes, bBytes)
	if err != nil {
		return nil, nil, err
	}
	response := new(big.Int).SetBytes(encRespBytes)
	response.Mul(response, encBeta)
	response.Mod(response, pkA.NSquared)

	// Encrypt beta under the responder's own key for the Y commitment.
	yCiphertext, yRandomness, err := pkB.Encrypt(reader, beta)
	if err != nil {
		return nil, nil, err
	}

	// Curve commitment X = b * G.
	X := secp.ScalarBaseMult(secp.ScalarFromBigInt(b))

	params := zkpai.ActiveSecurityParams()
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
		X:    new(big.Int).Set(b),
		Y:    new(big.Int).Set(beta),
		Rho:  new(big.Int).Set(betaRandomness),
		RhoY: new(big.Int).Set(yRandomness),
	}

	proof, err := zkpai.ProveAffG(params, responseDomain, stmt, witness, reader)
	if err != nil {
		return nil, nil, err
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	betaShare := new(big.Int).Neg(beta)
	betaShare.Mod(betaShare, secp.Order())
	return &ResponseMessage{Ciphertext: response.Bytes(), Proof: proofBytes}, betaShare, nil
}
