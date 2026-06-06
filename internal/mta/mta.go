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
	"github.com/islishude/tss/internal/secret"
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
	_                                  // 4: reserved (was EncrProof)
)

const (
	responseMessageFieldCiphertext uint16 = iota + 1
	responseMessageFieldProof
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
	if err := requireExactMessageTags(fields, startMessageFieldCiphertext); err != nil {
		return nil, err
	}
	msg := &StartMessage{
		Ciphertext: mustMessageField(fields, startMessageFieldCiphertext),
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

// Finish verifies the AffG response proof and decrypts the alpha share.
//
// Parameters:
//   - skA: initiator's Paillier private key
//   - pkB: responder's Paillier public key (Ni in Πaff-g)
//   - verifierAux: initiator's own Ring-Pedersen parameters
func Finish(responseDomain []byte, start StartMessage, response ResponseMessage, bCommitment []byte, skA *pai.PrivateKey, pkB *pai.PublicKey, verifierAux zkpai.RingPedersenParams) (*big.Int, error) {
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

	params := zkpai.ActiveSecurityParams()
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
