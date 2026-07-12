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
	responseOpeningWireType    = "mta.response-opening-private"
	responseOpeningWireVersion = 1
)

// ResponseMessage carries an MtA ciphertext response and transcript proof.
type ResponseMessage struct {
	Ciphertext []byte          `json:"ciphertext" wire:"1,bytes,max_bytes=paillier_ciphertext"`
	Proof      zkpai.AffGProof `json:"proof" wire:"2,nested,max_bytes=zk_proof"`
}

// Clone returns an independent copy of the public MtA response.
func (m ResponseMessage) Clone() ResponseMessage {
	proof := m.Proof.Clone()
	if proof == nil {
		return ResponseMessage{Ciphertext: append([]byte(nil), m.Ciphertext...)}
	}
	return ResponseMessage{
		Ciphertext: append([]byte(nil), m.Ciphertext...),
		Proof:      *proof,
	}
}

// Destroy clears witness-derived response material retained in memory.
func (m *ResponseMessage) Destroy() {
	if m == nil {
		return
	}
	clear(m.Ciphertext)
	m.Proof.Destroy()
	*m = ResponseMessage{}
}

// WireType returns the canonical wire type identifier for ResponseMessage.
func (ResponseMessage) WireType() string { return responseMessageWireType }

// WireVersion returns the wire format version for ResponseMessage.
func (ResponseMessage) WireVersion() uint16 { return responseMessageWireVersion }

// MarshalBinary encodes the MtA response message using the object-level wire codec.
func (m ResponseMessage) MarshalBinary() ([]byte, error) {
	return wire.Marshal(m, wire.WithFieldLimitsForMarshal(responseMessageFieldLimits()))
}

// UnmarshalBinary decodes a TLV MtA response message.
func (m *ResponseMessage) UnmarshalBinary(in []byte) error {
	var decoded ResponseMessage
	if err := wire.Unmarshal(
		in,
		&decoded,
		wire.WithFrameLimits(mtaMessageFrameLimits()),
		wire.WithFieldLimits(responseMessageFieldLimits()),
	); err != nil {
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
		"paillier_ciphertext": tss.DefaultMaxPaillierCiphertextBytes,
		"zk_proof":            tss.DefaultMaxZKProofBytes,
		"paillier_modulus":    tss.DefaultMaxPaillierCiphertextBytes,
		"point":               tss.DefaultMaxPointBytes,
		"signed_response":     tss.DefaultMaxPaillierCiphertextBytes,
		"paillier_signed":     tss.DefaultMaxPaillierCiphertextBytes,
	}
}

// ResponseOpening retains the secret witness needed to reprove one accepted
// MtA response during an identifiable-abort flow.
type ResponseOpening struct {
	x    *secret.Scalar
	y    *secret.SignedInt
	rho  *secret.Scalar
	rhoY *secret.Scalar
}

type responseOpeningWire struct {
	X     []byte `wire:"1,bytes,len=32"`
	YSign []byte `wire:"2,bytes,len=1"`
	Y     []byte `wire:"3,bytes,max_bytes=paillier_signed"`
	Rho   []byte `wire:"4,bytes,max_bytes=paillier_signed"`
	RhoY  []byte `wire:"5,bytes,max_bytes=paillier_signed"`
}

// WireType returns the private opening wire type.
func (responseOpeningWire) WireType() string { return responseOpeningWireType }

// WireVersion returns the private opening wire version.
func (responseOpeningWire) WireVersion() uint16 { return responseOpeningWireVersion }

// MarshalPrivateBinary encodes the witness for encrypted private storage. The
// returned bytes must never be logged or placed in public evidence.
func (o *ResponseOpening) MarshalPrivateBinary() ([]byte, error) {
	if o == nil || o.x == nil || o.y == nil || o.rho == nil || o.rhoY == nil {
		return nil, errors.New("destroyed MtA response opening")
	}
	x := o.x.FixedBytes()
	y := o.y.FixedMagnitude()
	rho := o.rho.FixedBytes()
	rhoY := o.rhoY.FixedBytes()
	sign, err := o.y.SelectBySign([]byte{0}, []byte{1})
	if err != nil {
		clear(x)
		clear(y)
		clear(rho)
		clear(rhoY)
		return nil, err
	}
	record := responseOpeningWire{X: x, YSign: sign, Y: y, Rho: rho, RhoY: rhoY}
	defer func() {
		clear(record.X)
		clear(record.YSign)
		clear(record.Y)
		clear(record.Rho)
		clear(record.RhoY)
	}()
	return wire.Marshal(record, wire.WithFieldLimitsForMarshal(responseMessageFieldLimits()))
}

// UnmarshalPrivateBinary decodes a witness obtained from encrypted private
// storage. Callers must still enforce one-use lifecycle state before use.
func (o *ResponseOpening) UnmarshalPrivateBinary(in []byte) error {
	if o == nil {
		return errors.New("nil MtA response opening")
	}
	var record responseOpeningWire
	if err := wire.Unmarshal(in, &record,
		wire.WithFrameLimits(mtaMessageFrameLimits()),
		wire.WithFieldLimits(responseMessageFieldLimits()),
	); err != nil {
		return err
	}
	defer func() {
		clear(record.X)
		clear(record.YSign)
		clear(record.Y)
		clear(record.Rho)
		clear(record.RhoY)
	}()
	if len(record.X) != secp.ScalarSize || len(record.YSign) != 1 || record.YSign[0] > 1 || len(record.Y) == 0 || len(record.Rho) == 0 || len(record.RhoY) == 0 {
		return errors.New("invalid private MtA response opening")
	}
	x, err := secret.NewScalar(record.X, len(record.X))
	if err != nil {
		return err
	}
	y, err := secret.NewSignedInt(record.YSign[0] == 1, record.Y, len(record.Y))
	if err != nil {
		x.Destroy()
		return err
	}
	rho, err := secret.NewScalar(record.Rho, len(record.Rho))
	if err != nil {
		x.Destroy()
		y.Destroy()
		return err
	}
	rhoY, err := secret.NewScalar(record.RhoY, len(record.RhoY))
	if err != nil {
		x.Destroy()
		y.Destroy()
		rho.Destroy()
		return err
	}
	o.Destroy()
	o.x, o.y, o.rho, o.rhoY = x, y, rho, rhoY
	return nil
}

// Clone returns an independent witness copy.
func (o *ResponseOpening) Clone() *ResponseOpening {
	if o == nil {
		return nil
	}
	return &ResponseOpening{x: o.x.Clone(), y: o.y.Clone(), rho: o.rho.Clone(), rhoY: o.rhoY.Clone()}
}

// Destroy clears all retained witness material.
func (o *ResponseOpening) Destroy() {
	if o == nil {
		return
	}
	if o.x != nil {
		o.x.Destroy()
	}
	if o.y != nil {
		o.y.Destroy()
	}
	if o.rho != nil {
		o.rho.Destroy()
	}
	if o.rhoY != nil {
		o.rhoY.Destroy()
	}
	*o = ResponseOpening{}
}

// Reprove creates a fresh verifier-specific Πaff-g proof for the exact public
// response bound to this opening.
func (o *ResponseOpening) Reprove(params zkpai.SecurityParams, reader io.Reader, domain []byte, start StartMessage, response ResponseMessage, aCommitment, bCommitment []byte, pkA, pkB *pai.PublicKey, verifierAux *zkpai.RingPedersenParams) (*zkpai.AffGProof, error) {
	if o == nil || o.x == nil || o.y == nil || o.rho == nil || o.rhoY == nil {
		return nil, errors.New("destroyed MtA response opening")
	}
	aPoint, err := secp.PointFromBytes(aCommitment)
	if err != nil {
		return nil, err
	}
	bPoint, err := secp.PointFromBytes(bCommitment)
	if err != nil {
		return nil, err
	}
	stmt := zkpai.AffGStatement{
		ReceiverPaillierN: pkA,
		ProverPaillierN:   pkB,
		C:                 new(big.Int).SetBytes(start.Ciphertext),
		D:                 new(big.Int).SetBytes(response.Ciphertext),
		Y:                 response.Proof.Y,
		X:                 bPoint,
		K:                 aPoint,
		VerifierAux:       verifierAux,
	}
	return zkpai.ProveAffG(params, domain, stmt, zkpai.AffGWitness{X: o.x, Y: o.y, Rho: o.rho, RhoY: o.rhoY}, reader)
}

// Respond creates Enc(a*b+beta) under the initiator's Paillier key and proves
// the response is correctly formed using a Πaff-g proof. It also encrypts beta
// under the responder's own Paillier key for the Y component of the proof.
//
// Parameters:
//   - pkA: initiator's Paillier public key (Nj in Πaff-g)
//   - pkB: responder's own Paillier public key (Ni in Πaff-g)
//   - startVerifierAux: responder's Ring-Pedersen parameters for checking Πlog*
//   - affGVerifierAux: initiator's Ring-Pedersen parameters for Πaff-g
//
// Returns the response message and the negated local beta share (-beta mod q).
func Respond(
	params zkpai.SecurityParams, reader io.Reader,
	startProofDomain, responseDomain []byte,
	start StartMessage, startProof *zkpai.LogStarProof, aCommitment []byte,
	b *secret.Scalar, bCommitment []byte,
	pkA, pkB *pai.PublicKey,
	startVerifierAux, affGVerifierAux *zkpai.RingPedersenParams,
) (*ResponseMessage, *secret.Scalar, error) {
	response, beta, opening, err := RespondWithOpening(params, reader, startProofDomain, responseDomain, start, startProof, aCommitment, b, bCommitment, pkA, pkB, startVerifierAux, affGVerifierAux)
	if opening != nil {
		opening.Destroy()
	}
	return response, beta, err
}

// RespondWithOpening is Respond plus ownership of the identification witness.
func RespondWithOpening(
	params zkpai.SecurityParams, reader io.Reader,
	startProofDomain, responseDomain []byte,
	start StartMessage, startProof *zkpai.LogStarProof, aCommitment []byte,
	b *secret.Scalar, bCommitment []byte,
	pkA, pkB *pai.PublicKey,
	startVerifierAux, affGVerifierAux *zkpai.RingPedersenParams,
) (*ResponseMessage, *secret.Scalar, *ResponseOpening, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if startVerifierAux == nil || affGVerifierAux == nil {
		return nil, nil, nil, errors.New("nil RingPedersenParams")
	}
	plaintextBits := max(params.Ell*2, params.EllPrime) + 1
	if pkA == nil || pkA.N == nil || uint32(pkA.N.BitLen()) <= plaintextBits {
		return nil, nil, nil, errors.New("initiator Paillier modulus is too small for unwrapped MtA plaintext")
	}
	if pkB == nil || pkB.N == nil || uint32(pkB.N.BitLen()) <= params.EllPrime {
		return nil, nil, nil, errors.New("responder Paillier modulus is too small for affine mask")
	}
	if err := VerifyStart(params, startProofDomain, start, aCommitment, pkA, startVerifierAux, startProof); err != nil {
		return nil, nil, nil, err
	}
	bScalar, err := secpScalarFromSecret(b)
	if err != nil {
		return nil, nil, nil, errors.New("b out of range")
	}

	encA := new(big.Int).SetBytes(start.Ciphertext)
	beta, err := randomWideMask(reader, params.EllPrime)
	if err != nil {
		return nil, nil, nil, err
	}
	defer beta.Destroy()
	encBeta, betaRandomness, err := pkA.EncryptSignedSecret(reader, beta)
	if err != nil {
		return nil, nil, nil, err
	}
	defer betaRandomness.Destroy()

	// encA^b mod N² via constant-time modular exponentiation.
	// Ciphertext blinding is NOT applied here because the ZK proof
	// verifies the exact relationship response = encA^b * encBeta mod N².
	nLen := (pkA.N.BitLen() + 7) / 8
	nSquaredLen := 2 * nLen
	nSquaredBytes, err := paillierct.FixedEncodeStrict(pkA.NSquared, nSquaredLen)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode Paillier modulus: %w", err)
	}
	encABytes, err := paillierct.FixedEncodeStrict(encA, nSquaredLen)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode start ciphertext: %w", err)
	}
	bBytes := b.FixedBytes()
	defer clear(bBytes)

	encRespBytes, err := paillierct.ExpCT(nSquaredBytes, encABytes, bBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	response := new(big.Int).SetBytes(encRespBytes)
	response.Mul(response, encBeta)
	response.Mod(response, pkA.NSquared)

	// Encrypt beta under the responder's own key for the Y commitment.
	yCiphertext, yRandomness, err := pkB.EncryptSignedSecret(reader, beta)
	if err != nil {
		return nil, nil, nil, err
	}
	defer yRandomness.Destroy()

	// Curve commitment X = b * G.
	X := secp.ScalarBaseMult(bScalar)
	K, err := secp.PointFromBytes(aCommitment)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid initiator commitment: %w", err)
	}

	stmt := zkpai.AffGStatement{
		ReceiverPaillierN: pkA,
		ProverPaillierN:   pkB,
		C:                 encA,
		D:                 response,
		Y:                 yCiphertext,
		X:                 X,
		K:                 K,
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
		return nil, nil, nil, err
	}
	betaScalar, err := signedSecretScalarModOrder(beta)
	if err != nil {
		return nil, nil, nil, err
	}
	betaShareScalar := secp.ScalarNeg(betaScalar)
	betaShare, err := secret.NewScalar(betaShareScalar.Bytes(), secp.ScalarSize)
	if err != nil {
		return nil, nil, nil, err
	}
	opening := &ResponseOpening{x: b.Clone(), y: beta.Clone(), rho: betaRandomness.Clone(), rhoY: yRandomness.Clone()}
	return &ResponseMessage{Ciphertext: response.Bytes(), Proof: *proof}, betaShare, opening, nil
}
