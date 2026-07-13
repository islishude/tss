package mta

import (
	"bytes"
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
	startMessageWireType    = "mta.start-message"
	startMessageWireVersion = 1
)

// StartMessage carries an encrypted multiplicand.
type StartMessage struct {
	Ciphertext []byte `json:"ciphertext" wire:"1,bytes,max_bytes=paillier_ciphertext"`
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
	return wire.Marshal(m, wire.WithFieldLimitsForMarshal(startMessageFieldLimits()))
}

// UnmarshalBinary decodes a TLV MtA start message.
func (m *StartMessage) UnmarshalBinary(in []byte) error {
	var decoded StartMessage
	if err := wire.Unmarshal(
		in,
		&decoded,
		wire.WithFrameLimits(mtaMessageFrameLimits()),
		wire.WithFieldLimits(startMessageFieldLimits()),
	); err != nil {
		return err
	}
	*m = decoded
	return nil
}

func startMessageFieldLimits() wire.FieldLimits {
	return wire.FieldLimits{"paillier_ciphertext": tss.DefaultMaxPaillierCiphertextBytes}
}

func mtaMessageFrameLimits() wire.FrameLimits {
	return wire.FrameLimits{
		MaxTotalBytes: tss.DefaultMaxMTAResponseBytes,
		MaxFields:     tss.DefaultMaxWireFields,
		MaxFieldBytes: tss.DefaultMaxZKProofBytes,
	}
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

// ProveProduct constructs H=Enc(a*b) from two retained start openings and
// proves the multiplication relation with Πmul. The returned ciphertext and
// proof are public; temporary product randomness is destroyed internally.
func (o *StartOpening) ProveProduct(params zkpai.SecurityParams, reader io.Reader, state []byte, other *StartOpening, pk *pai.PublicKey) (*big.Int, *zkpai.MulProof, error) {
	if o == nil || other == nil || o.k == nil || o.rho == nil || other.k == nil || other.rho == nil {
		return nil, nil, errors.New("destroyed MtA start opening")
	}
	if pk == nil {
		return nil, nil, errors.New("nil Paillier public key")
	}
	if reader == nil {
		reader = rand.Reader
	}
	if !bytes.Equal(o.Message.Ciphertext, new(big.Int).SetBytes(o.Message.Ciphertext).Bytes()) ||
		!bytes.Equal(other.Message.Ciphertext, new(big.Int).SetBytes(other.Message.Ciphertext).Bytes()) {
		return nil, nil, errors.New("non-canonical MtA start ciphertext")
	}
	kBytes := o.k.FixedBytes()
	defer clear(kBytes)
	kSigned, err := secret.NewSignedInt(false, kBytes, len(kBytes))
	if err != nil {
		return nil, nil, err
	}
	defer kSigned.Destroy()
	product, err := zkpai.OMulCT(pk, kSigned, new(big.Int).SetBytes(other.Message.Ciphertext), len(kBytes))
	if err != nil {
		return nil, nil, err
	}
	zero, randomness, err := pk.Encrypt(reader, big.NewInt(0))
	if err != nil {
		return nil, nil, err
	}
	product, err = zkpai.OAdd(pk, product, zero)
	if err != nil {
		secret.ClearBigInt(randomness)
		return nil, nil, err
	}
	nLen := (pk.N.BitLen() + 7) / 8
	randomnessBytes, err := paillierct.FixedEncodeStrict(randomness, nLen)
	secret.ClearBigInt(randomness)
	if err != nil {
		return nil, nil, err
	}
	defer clear(randomnessBytes)
	randomnessSecret, err := secret.NewScalar(randomnessBytes, nLen)
	if err != nil {
		return nil, nil, err
	}
	defer randomnessSecret.Destroy()
	proof, err := zkpai.ProveMul(params, state, zkpai.MulStatement{
		PaillierN: pk,
		X:         new(big.Int).SetBytes(o.Message.Ciphertext),
		Y:         new(big.Int).SetBytes(other.Message.Ciphertext),
		C:         product,
	}, zkpai.MulWitness{X: o.k, RhoX: o.rho, RhoC: randomnessSecret}, reader)
	if err != nil {
		return nil, nil, err
	}
	return product, proof, nil
}

// ProveStartForVerifier proves an MtA start ciphertext for one verifier.
func ProveStartForVerifier(params zkpai.SecurityParams, reader io.Reader, domain []byte, opening *StartOpening, aCommitment []byte, proverPK *pai.PublicKey, verifierAux *zkpai.RingPedersenParams) (*zkpai.LogStarProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if opening == nil {
		return nil, errors.New("nil MtA start opening")
	}
	if proverPK == nil {
		return nil, errors.New("nil prover public key")
	}
	if verifierAux == nil {
		return nil, errors.New("nil RingPedersenParams")
	}
	if err := opening.Message.Validate(); err != nil {
		return nil, err
	}
	aPoint, err := secp.PointFromBytes(aCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid MtA start commitment: %w", err)
	}
	stmt := zkpai.LogStarStatement{
		PaillierN:   proverPK,
		C:           new(big.Int).SetBytes(opening.Message.Ciphertext),
		X:           aPoint,
		B:           secp.ScalarBaseMult(secp.ScalarOne()),
		VerifierAux: verifierAux,
	}
	witness := zkpai.LogStarWitness{X: opening.k, Rho: opening.rho}
	proof, err := zkpai.ProveLogStar(params, domain, stmt, witness, reader)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// VerifyStart checks a verifier-specific Πlog* relation for an MtA start message.
func VerifyStart(params zkpai.SecurityParams, domain []byte, msg StartMessage, aCommitment []byte, proverPK *pai.PublicKey, verifierAux *zkpai.RingPedersenParams, proof *zkpai.LogStarProof) error {
	if proof == nil {
		return errors.New("missing MtA start proof")
	}
	if verifierAux == nil {
		return errors.New("missing RingPedersenParams for verifierAux")
	}
	if err := msg.Validate(); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return fmt.Errorf("invalid MtA start proof: %w", err)
	}
	aPoint, err := secp.PointFromBytes(aCommitment)
	if err != nil {
		return fmt.Errorf("invalid MtA start commitment: %w", err)
	}
	stmt := zkpai.LogStarStatement{
		PaillierN:   proverPK,
		C:           new(big.Int).SetBytes(msg.Ciphertext),
		X:           aPoint,
		B:           secp.ScalarBaseMult(secp.ScalarOne()),
		VerifierAux: verifierAux,
	}
	if err := zkpai.VerifyLogStar(params, domain, stmt, proof); err != nil {
		return fmt.Errorf("invalid MtA start proof: %w", err)
	}
	return nil
}

// ProveEncElgForVerifier proves the retained start ciphertext and the Figure 8
// ElGamal relation for one verifier without exposing the ciphertext opening.
func (o *StartOpening) ProveEncElgForVerifier(
	params zkpai.SecurityParams,
	reader io.Reader,
	domain []byte,
	elGamalBase, exponentCommitment, combinedCommitment []byte,
	exponent *secret.Scalar,
	proverPK *pai.PublicKey,
	verifierAux *zkpai.RingPedersenParams,
) (*zkpai.EncElgProof, error) {
	if o == nil || o.k == nil || o.rho == nil {
		return nil, errors.New("destroyed MtA start opening")
	}
	if err := o.Message.Validate(); err != nil {
		return nil, err
	}
	stmt, err := encElgStartStatement(o.Message, elGamalBase, exponentCommitment, combinedCommitment, proverPK, verifierAux)
	if err != nil {
		return nil, err
	}
	return zkpai.ProveEncElg(params, domain, stmt, zkpai.EncElgWitness{
		Plaintext:  o.k,
		Randomness: o.rho,
		Exponent:   exponent,
	}, reader)
}

// VerifyStartEncElg verifies a Figure 8 Πenc-elg proof for an MtA start
// ciphertext and the supplied public ElGamal relation.
func VerifyStartEncElg(
	params zkpai.SecurityParams,
	domain []byte,
	msg StartMessage,
	elGamalBase, exponentCommitment, combinedCommitment []byte,
	proverPK *pai.PublicKey,
	verifierAux *zkpai.RingPedersenParams,
	proof *zkpai.EncElgProof,
) error {
	if proof == nil {
		return errors.New("missing MtA start enc-elg proof")
	}
	if err := msg.Validate(); err != nil {
		return err
	}
	stmt, err := encElgStartStatement(msg, elGamalBase, exponentCommitment, combinedCommitment, proverPK, verifierAux)
	if err != nil {
		return err
	}
	if err := zkpai.VerifyEncElg(params, domain, stmt, proof); err != nil {
		return fmt.Errorf("invalid MtA start enc-elg proof: %w", err)
	}
	return nil
}

func encElgStartStatement(
	msg StartMessage,
	elGamalBase, exponentCommitment, combinedCommitment []byte,
	proverPK *pai.PublicKey,
	verifierAux *zkpai.RingPedersenParams,
) (zkpai.EncElgStatement, error) {
	if proverPK == nil {
		return zkpai.EncElgStatement{}, errors.New("nil prover public key")
	}
	if verifierAux == nil {
		return zkpai.EncElgStatement{}, errors.New("nil RingPedersenParams")
	}
	base, err := secp.PointFromBytes(elGamalBase)
	if err != nil {
		return zkpai.EncElgStatement{}, fmt.Errorf("invalid ElGamal base: %w", err)
	}
	exponentPoint, err := secp.PointFromBytes(exponentCommitment)
	if err != nil {
		return zkpai.EncElgStatement{}, fmt.Errorf("invalid exponent commitment: %w", err)
	}
	combinedPoint, err := secp.PointFromBytes(combinedCommitment)
	if err != nil {
		return zkpai.EncElgStatement{}, fmt.Errorf("invalid combined commitment: %w", err)
	}
	return zkpai.EncElgStatement{
		Generator:          secp.Clone(secp.G),
		PaillierN:          proverPK,
		Ciphertext:         new(big.Int).SetBytes(msg.Ciphertext),
		ElGamalBase:        base,
		ExponentCommitment: exponentPoint,
		CombinedCommitment: combinedPoint,
		VerifierAux:        verifierAux,
	}, nil
}
