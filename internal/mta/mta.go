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

const messageVersion = 1

const (
	startMessageWireType    = "mta.start-message"
	responseMessageWireType = "mta.response-message"
)

const (
	startMessageFieldCiphertext uint16 = iota + 1
	_                                  // 2: reserved (was EncProof)
	_                                  // 3: reserved (was RangeProof)
	startMessageFieldEncrProof         // 4
)

const (
	responseMessageFieldCiphertext uint16 = iota + 1
	responseMessageFieldProof
)

// StartMessage carries an encrypted multiplicand and its public proofs.
type StartMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	EncrProof  []byte `json:"encr_proof,omitempty"`
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
		{Tag: startMessageFieldEncrProof, Value: m.EncrProof},
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
	if err := requireExactMessageTags(fields, startMessageFieldCiphertext, startMessageFieldEncrProof); err != nil {
		return nil, err
	}
	msg := &StartMessage{
		Ciphertext: mustMessageField(fields, startMessageFieldCiphertext),
		EncrProof:  mustMessageField(fields, startMessageFieldEncrProof),
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
	if len(m.EncrProof) == 0 {
		return errors.New("missing MtA encryption proof")
	}
	if _, err := zkpai.UnmarshalEncryptionProof(m.EncrProof); err != nil {
		return fmt.Errorf("invalid MtA encryption proof: %w", err)
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
	encrProof, err := zkpai.ProveEncryption(reader, domain, pk, c, a, r)
	if err != nil {
		return nil, err
	}
	encrProofBytes, err := zkpai.Marshal(encrProof)
	if err != nil {
		return nil, err
	}
	return &StartMessage{Ciphertext: c.Bytes(), EncrProof: encrProofBytes}, nil
}

// VerifyStart checks the unified encryption proof from Start.
func VerifyStart(domain []byte, msg StartMessage, pk *pai.PublicKey) bool {
	c := new(big.Int).SetBytes(msg.Ciphertext)
	encrProof, err := zkpai.UnmarshalEncryptionProof(msg.EncrProof)
	if err != nil {
		return false
	}
	return zkpai.VerifyEncryption(domain, pk, c, encrProof)
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

	// encA^b mod N² via constant-time modular exponentiation.
	// Ciphertext blinding is NOT applied here because the ZK proof
	// (ProveMTAResponse) verifies the exact relationship
	// response = encA^b * encBeta mod N²; a blinded base would
	// change the ciphertext and break the proof. The constant-time
	// bigmod.Exp provides the primary side-channel protection for
	// the secret scalar b.
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

// scalarFixedBytes encodes a secp256k1 scalar as fixed-length 32-byte big-endian.
func scalarFixedBytes(x *big.Int) []byte {
	const scalarByteLen = 32
	b := x.Bytes()
	if len(b) >= scalarByteLen {
		return b[len(b)-scalarByteLen:]
	}
	out := make([]byte, scalarByteLen)
	copy(out[scalarByteLen-len(b):], b)
	return out
}
