package mta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	startMessageWireType = "mta.start-message"
)

const (
	startMessageFieldCiphertext uint16 = iota + 1
	_                                  // 2: reserved (was EncProof)
	_                                  // 3: reserved (was RangeProof)
	_                                  // 4: reserved (was EncrProof)
)

// StartMessage carries an encrypted multiplicand.
type StartMessage struct {
	Ciphertext []byte `json:"ciphertext"`
}

// StartOpening carries the local witness for an MtA start ciphertext.
type StartOpening struct {
	Message StartMessage
	k       *big.Int
	rho     *big.Int
}

// MarshalBinary encodes the MtA start message as an exact-field TLV record.
func (m StartMessage) MarshalBinary() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(messageVersion, startMessageWireType, []wire.Field{
		{Tag: startMessageFieldCiphertext, Value: m.Ciphertext},
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
	if err := wire.RequireExactTags(fields, startMessageFieldCiphertext); err != nil {
		return nil, err
	}
	msg := &StartMessage{
		Ciphertext: fields[0].Value,
	}
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	return msg, nil
}

// Validate checks the canonical ciphertext integer.
func (m StartMessage) Validate() error {
	if err := validatePositiveIntegerBytes(m.Ciphertext); err != nil {
		return fmt.Errorf("invalid MtA start ciphertext: %w", err)
	}
	return nil
}

// Start encrypts scalar a and retains the opening for per-verifier proofs.
func Start(reader io.Reader, a *big.Int, pk *pai.PublicKey) (*StartOpening, error) {
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
	return &StartOpening{
		Message: StartMessage{Ciphertext: c.Bytes()},
		k:       new(big.Int).Set(a),
		rho:     new(big.Int).Set(r),
	}, nil
}

// Destroy clears the witness retained by StartOpening.
func (o *StartOpening) Destroy() {
	if o == nil {
		return
	}
	clear(o.Message.Ciphertext)
	secret.ClearBigInt(o.k)
	secret.ClearBigInt(o.rho)
	o.k = nil
	o.rho = nil
}

// String returns a redacted representation of the MtA start opening.
func (o *StartOpening) String() string {
	if o == nil {
		return "<nil>"
	}
	return "StartOpening{Message:<public>, witness:<redacted>}"
}

// GoString returns a redacted representation of the MtA start opening.
func (o *StartOpening) GoString() string {
	return o.String()
}

// ProveStartForVerifier proves an MtA start ciphertext for one verifier.
func ProveStartForVerifier(reader io.Reader, domain []byte, opening *StartOpening, proverPK *pai.PublicKey, verifierAux zkpai.RingPedersenParams) ([]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if opening == nil {
		return nil, errors.New("nil MtA start opening")
	}
	if err := opening.Message.Validate(); err != nil {
		return nil, err
	}
	stmt := zkpai.EncStatement{
		ProverPaillierN: proverPK,
		CiphertextK:     new(big.Int).SetBytes(opening.Message.Ciphertext),
		VerifierAux:     verifierAux,
	}
	witness := zkpai.EncWitness{
		K:   opening.k,
		Rho: opening.rho,
	}
	proof, err := zkpai.ProveEnc(zkpai.ActiveSecurityParams(), domain, stmt, witness, reader)
	if err != nil {
		return nil, err
	}
	return proof.MarshalBinary()
}

// VerifyStart checks a verifier-specific Πenc proof for an MtA start message.
func VerifyStart(domain []byte, msg StartMessage, proverPK *pai.PublicKey, verifierAux zkpai.RingPedersenParams, proofBytes []byte) error {
	if len(proofBytes) == 0 {
		return errors.New("missing MtA start proof")
	}
	if err := msg.Validate(); err != nil {
		return err
	}
	proof, err := zkpai.UnmarshalEncProof(proofBytes)
	if err != nil {
		return fmt.Errorf("invalid MtA start proof: %w", err)
	}
	stmt := zkpai.EncStatement{
		ProverPaillierN: proverPK,
		CiphertextK:     new(big.Int).SetBytes(msg.Ciphertext),
		VerifierAux:     verifierAux,
	}
	if err := zkpai.VerifyEnc(zkpai.ActiveSecurityParams(), domain, stmt, proof); err != nil {
		return fmt.Errorf("invalid MtA start proof: %w", err)
	}
	return nil
}
