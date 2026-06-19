package mta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	startMessageWireType    = "mta.start-message"
	startMessageWireVersion = 1
)

// StartMessage carries an encrypted multiplicand.
type StartMessage struct {
	Ciphertext []byte `json:"ciphertext" wire:"1,bytes"`
}

// WireType returns the canonical wire type identifier for StartMessage.
func (StartMessage) WireType() string { return startMessageWireType }

// WireVersion returns the wire format version for StartMessage.
func (StartMessage) WireVersion() uint16 { return startMessageWireVersion }

// StartOpening carries the local witness for an MtA start ciphertext.
type StartOpening struct {
	Message StartMessage
	k       *secret.Scalar
	rho     *secret.Scalar
}

// MarshalBinary encodes the MtA start message using the object-level wire codec.
func (m StartMessage) MarshalBinary() ([]byte, error) {
	return wire.Marshal(m)
}

// UnmarshalStartMessage decodes a TLV MtA start message using the object-level wire codec.
func UnmarshalStartMessage(in []byte) (*StartMessage, error) {
	msg := new(StartMessage)
	if err := msg.UnmarshalBinary(in); err != nil {
		return nil, err
	}
	return msg, nil
}

// UnmarshalBinary decodes a TLV MtA start message.
func (m *StartMessage) UnmarshalBinary(in []byte) error {
	var decoded StartMessage
	if err := wire.Unmarshal(in, &decoded); err != nil {
		return err
	}
	*m = decoded
	return nil
}

// Validate checks the canonical ciphertext integer.
func (m StartMessage) Validate() error {
	if err := validatePositiveIntegerBytes(m.Ciphertext); err != nil {
		return fmt.Errorf("invalid MtA start ciphertext: %w", err)
	}
	return nil
}

// Start encrypts scalar a and retains the opening for per-verifier proofs.
func Start(reader io.Reader, a *secret.Scalar, pk *pai.PublicKey) (*StartOpening, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if _, err := secpScalarFromSecret(a); err != nil {
		return nil, errors.New("a out of range")
	}
	c, r, err := pk.EncryptSecret(reader, a)
	if err != nil {
		return nil, err
	}
	return &StartOpening{
		Message: StartMessage{Ciphertext: c.Bytes()},
		k:       a.Clone(),
		rho:     r,
	}, nil
}

// Destroy clears the witness retained by StartOpening.
func (o *StartOpening) Destroy() {
	if o == nil {
		return
	}
	clear(o.Message.Ciphertext)
	o.k.Destroy()
	o.rho.Destroy()
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
func ProveStartForVerifier(params zkpai.SecurityParams, reader io.Reader, domain []byte, opening *StartOpening, proverPK *pai.PublicKey, verifierAux zkpai.RingPedersenParams) (*zkpai.EncProof, error) {
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
	proof, err := zkpai.ProveEnc(params, domain, stmt, witness, reader)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// VerifyStart checks a verifier-specific Πenc proof for an MtA start message.
func VerifyStart(params zkpai.SecurityParams, domain []byte, msg StartMessage, proverPK *pai.PublicKey, verifierAux zkpai.RingPedersenParams, proof *zkpai.EncProof) error {
	if proof == nil {
		return errors.New("missing MtA start proof")
	}
	if err := msg.Validate(); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return fmt.Errorf("invalid MtA start proof: %w", err)
	}
	stmt := zkpai.EncStatement{
		ProverPaillierN: proverPK,
		CiphertextK:     new(big.Int).SetBytes(msg.Ciphertext),
		VerifierAux:     verifierAux,
	}
	if err := zkpai.VerifyEnc(params, domain, stmt, proof); err != nil {
		return fmt.Errorf("invalid MtA start proof: %w", err)
	}
	return nil
}
