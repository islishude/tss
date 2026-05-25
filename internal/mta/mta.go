package mta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const messageVersion = 1

const (
	startMessageWireType    = "mta.start-message"
	responseMessageWireType = "mta.response-message"
)

const (
	startMessageFieldCiphertext uint16 = iota + 1
	startMessageFieldEncProof
	startMessageFieldRangeProof
)

const (
	responseMessageFieldCiphertext uint16 = iota + 1
	responseMessageFieldProof
)

// StartMessage carries an encrypted multiplicand and its public proofs.
type StartMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	EncProof   []byte `json:"enc_proof"`
	RangeProof []byte `json:"range_proof"`
}

// ResponseMessage carries an MtA ciphertext response and transcript proof.
type ResponseMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	Proof      []byte `json:"proof"`
}

// MarshalBinary encodes the MtA start message as an exact-field TLV record.
func (m StartMessage) MarshalBinary() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(messageVersion, startMessageWireType, []wire.Field{
		{Tag: startMessageFieldCiphertext, Value: m.Ciphertext},
		{Tag: startMessageFieldEncProof, Value: m.EncProof},
		{Tag: startMessageFieldRangeProof, Value: m.RangeProof},
	})
}

// UnmarshalStartMessage decodes an exact-field TLV MtA start message.
func UnmarshalStartMessage(in []byte) (*StartMessage, error) {
	version, fields, err := wire.Unmarshal(in, startMessageWireType)
	if err != nil {
		return nil, err
	}
	if version != messageVersion {
		return nil, fmt.Errorf("unexpected MtA start message version %d", version)
	}
	if err := requireExactMessageTags(fields, startMessageFieldCiphertext, startMessageFieldEncProof, startMessageFieldRangeProof); err != nil {
		return nil, err
	}
	msg := &StartMessage{
		Ciphertext: mustMessageField(fields, startMessageFieldCiphertext),
		EncProof:   mustMessageField(fields, startMessageFieldEncProof),
		RangeProof: mustMessageField(fields, startMessageFieldRangeProof),
	}
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	return msg, nil
}

// Validate checks the canonical proof records and ciphertext integer.
func (m StartMessage) Validate() error {
	if err := validatePositiveIntegerBytes(m.Ciphertext); err != nil {
		return fmt.Errorf("invalid MtA start ciphertext: %w", err)
	}
	if _, err := zkpai.UnmarshalEncScalarProof(m.EncProof); err != nil {
		return fmt.Errorf("invalid MtA encrypted scalar proof: %w", err)
	}
	if _, err := zkpai.UnmarshalEncRangeProof(m.RangeProof); err != nil {
		return fmt.Errorf("invalid MtA range proof: %w", err)
	}
	return nil
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
	if err := requireExactMessageTags(fields, responseMessageFieldCiphertext, responseMessageFieldProof); err != nil {
		return nil, err
	}
	msg := &ResponseMessage{
		Ciphertext: mustMessageField(fields, responseMessageFieldCiphertext),
		Proof:      mustMessageField(fields, responseMessageFieldProof),
	}
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	return msg, nil
}

// Validate checks the canonical proof record and ciphertext integer.
func (m ResponseMessage) Validate() error {
	if err := validatePositiveIntegerBytes(m.Ciphertext); err != nil {
		return fmt.Errorf("invalid MtA response ciphertext: %w", err)
	}
	if _, err := zkpai.UnmarshalMTAResponseProof(m.Proof); err != nil {
		return fmt.Errorf("invalid MtA response proof: %w", err)
	}
	return nil
}

// Start encrypts scalar a and proves it is a valid secp256k1 scalar.
func Start(reader io.Reader, domain []byte, a *big.Int, pk *pai.PublicKey) (*StartMessage, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if a == nil || a.Sign() <= 0 || a.Cmp(secp.Order()) >= 0 {
		return nil, errors.New("a out of range")
	}
	c, r, err := pk.Encrypt(reader, a)
	if err != nil {
		return nil, err
	}
	encProof, rangeProof, err := zkpai.ProveEncScalarAndRange(reader, domain, pk, c, a, r)
	if err != nil {
		return nil, err
	}
	encProofBytes, err := zkpai.Marshal(encProof)
	if err != nil {
		return nil, err
	}
	rangeProofBytes, err := zkpai.Marshal(rangeProof)
	if err != nil {
		return nil, err
	}
	return &StartMessage{Ciphertext: c.Bytes(), EncProof: encProofBytes, RangeProof: rangeProofBytes}, nil
}

// VerifyStart checks the encrypted scalar and range proofs from Start.
func VerifyStart(domain []byte, msg StartMessage, pk *pai.PublicKey) bool {
	c := new(big.Int).SetBytes(msg.Ciphertext)
	encProof, err := zkpai.UnmarshalEncScalarProof(msg.EncProof)
	if err != nil {
		return false
	}
	rangeProof, err := zkpai.UnmarshalEncRangeProof(msg.RangeProof)
	if err != nil {
		return false
	}
	return zkpai.VerifyEncScalarAndRange(domain, pk, c, encProof, rangeProof)
}

// Respond creates Enc(a*b+beta) and returns the local beta share as -beta.
func Respond(reader io.Reader, startDomain, responseDomain []byte, start StartMessage, b *big.Int, bCommitment []byte, pkA *pai.PublicKey) (*ResponseMessage, *big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if !VerifyStart(startDomain, start, pkA) {
		return nil, nil, errors.New("invalid MtA start proof")
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
	response := new(big.Int).Exp(encA, b, pkA.NSquared)
	response.Mul(response, encBeta)
	response.Mod(response, pkA.NSquared)
	proof, err := zkpai.ProveMTAResponse(reader, responseDomain, pkA, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		return nil, nil, err
	}
	proofBytes, err := zkpai.Marshal(proof)
	if err != nil {
		return nil, nil, err
	}
	betaShare := new(big.Int).Neg(beta)
	betaShare.Mod(betaShare, secp.Order())
	return &ResponseMessage{Ciphertext: response.Bytes(), Proof: proofBytes}, betaShare, nil
}

// Finish verifies the response proof and decrypts the alpha share.
func Finish(startDomain, responseDomain []byte, start StartMessage, response ResponseMessage, bCommitment []byte, skA *pai.PrivateKey) (*big.Int, error) {
	if skA == nil {
		return nil, errors.New("nil Paillier private key")
	}
	if !VerifyStart(startDomain, start, &skA.PublicKey) {
		return nil, errors.New("invalid MtA start proof")
	}
	proof, err := zkpai.UnmarshalMTAResponseProof(response.Proof)
	if err != nil {
		return nil, err
	}
	encA := new(big.Int).SetBytes(start.Ciphertext)
	resp := new(big.Int).SetBytes(response.Ciphertext)
	if !zkpai.VerifyMTAResponse(responseDomain, &skA.PublicKey, encA, resp, bCommitment, proof) {
		return nil, fmt.Errorf("invalid MtA response proof")
	}
	alpha, err := skA.Decrypt(resp)
	if err != nil {
		return nil, err
	}
	alpha.Mod(alpha, secp.Order())
	return alpha, nil
}

func randomScalar(reader io.Reader) (*big.Int, error) {
	for {
		x, err := rand.Int(reader, secp.Order())
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}

func requireExactMessageTags(fields []wire.Field, tags ...uint16) error {
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

func mustMessageField(fields []wire.Field, tag uint16) []byte {
	value, _ := wire.Require(fields, tag)
	return value
}

func validatePositiveIntegerBytes(in []byte) error {
	if len(in) == 0 {
		return errors.New("empty integer")
	}
	if in[0] == 0 {
		return errors.New("non-minimal integer encoding")
	}
	if new(big.Int).SetBytes(in).Sign() <= 0 {
		return errors.New("integer must be positive")
	}
	return nil
}
