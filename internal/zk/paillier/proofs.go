package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
)

const proofVersion = 1

const (
	modulusProofWireType     = "zk.paillier.modulus-proof"
	encScalarProofWireType   = "zk.paillier.enc-scalar-proof"
	encRangeProofWireType    = "zk.paillier.enc-range-proof"
	mtaResponseProofWireType = "zk.paillier.mta-response-proof"
)

const (
	modulusProofFieldNBits uint16 = iota + 1
	modulusProofFieldSmallFactorCheck
	modulusProofFieldTranscriptHash
	modulusProofFieldDigest
)

const (
	encScalarProofFieldScalarCommitment uint16 = iota + 1
	encScalarProofFieldCipherCommitment
	encScalarProofFieldPointCommitment
	encScalarProofFieldResponse
	encScalarProofFieldRandomness
	encScalarProofFieldTranscriptHash
)

const (
	encRangeProofFieldBound uint16 = iota + 1
	encRangeProofFieldChallenge
	encRangeProofFieldResponse
	encRangeProofFieldTranscriptHash
	encRangeProofFieldDigest
)

const (
	mtaResponseProofFieldTranscriptHash uint16 = iota + 1
	mtaResponseProofFieldBetaCommitment
	mtaResponseProofFieldCipherCommitment
	mtaResponseProofFieldBCommitment
	mtaResponseProofFieldBetaNonce
	mtaResponseProofFieldBResponse
	mtaResponseProofFieldBetaResponse
	mtaResponseProofFieldRandomness
)

const (
	modulusTranscriptLabel   = "paillier-modulus-transcript-v2"
	modulusProofDigestLabel  = "paillier-modulus-proof-v2"
	encScalarTranscriptLabel = "paillier-enc-scalar-transcript-v2"
	encScalarChallengeLabel  = "paillier-enc-scalar-challenge-v2"
	encRangeDigestLabel      = "paillier-enc-range-proof-v2"
	mtaTranscriptLabel       = "paillier-mta-response-transcript-v2"
	mtaChallengeLabel        = "paillier-mta-response-challenge-v2"
)

// ModulusProof binds a Paillier modulus to a session transcript.
type ModulusProof struct {
	Version          uint16 `json:"version"`
	NBits            int    `json:"n_bits"`
	SmallFactorCheck []byte `json:"small_factor_check"`
	TranscriptHash   []byte `json:"transcript_hash"`
	Digest           []byte `json:"digest"`
}

// EncScalarProof proves a ciphertext encrypts a committed scalar.
type EncScalarProof struct {
	Version          uint16 `json:"version"`
	ScalarCommitment []byte `json:"scalar_commitment"`
	CipherCommitment []byte `json:"cipher_commitment"`
	PointCommitment  []byte `json:"point_commitment"`
	Response         []byte `json:"response"`
	Randomness       []byte `json:"randomness"`
	TranscriptHash   []byte `json:"transcript_hash"`
}

// EncRangeProof records the range check paired with EncScalarProof.
type EncRangeProof struct {
	Version        uint16 `json:"version"`
	Bound          []byte `json:"bound"`
	Challenge      []byte `json:"challenge"`
	Response       []byte `json:"response"`
	TranscriptHash []byte `json:"transcript_hash"`
	Digest         []byte `json:"digest"`
}

// MTAResponseProof binds an MtA response to ciphertexts and commitments.
type MTAResponseProof struct {
	Version          uint16 `json:"version"`
	TranscriptHash   []byte `json:"transcript_hash"`
	BetaCommitment   []byte `json:"beta_commitment"`
	CipherCommitment []byte `json:"cipher_commitment"`
	BCommitment      []byte `json:"b_commitment"`
	BetaNonce        []byte `json:"beta_nonce"`
	BResponse        []byte `json:"b_response"`
	BetaResponse     []byte `json:"beta_response"`
	Randomness       []byte `json:"randomness"`
}

// ProveModulus creates the current unaudited modulus proof structure.
func ProveModulus(domain []byte, pk *pai.PublicKey, party uint32) (*ModulusProof, error) {
	if pk == nil {
		return nil, errors.New("nil paillier public key")
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	raw, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	transcript := hashParts([]byte(modulusTranscriptLabel), domain, partyBytes(party), raw)
	smallFactors := smallFactorDigest(pk.N)
	return &ModulusProof{
		Version:          proofVersion,
		NBits:            pk.N.BitLen(),
		SmallFactorCheck: smallFactors,
		TranscriptHash:   transcript,
		Digest:           hashParts([]byte(modulusProofDigestLabel), transcript, smallFactors),
	}, nil
}

// VerifyModulus checks a modulus proof against a public key and transcript.
func VerifyModulus(domain []byte, pk *pai.PublicKey, party uint32, proof *ModulusProof) bool {
	if validateModulusProof(proof) != nil || pk == nil {
		return false
	}
	if err := pk.Validate(); err != nil {
		return false
	}
	if proof.NBits != pk.N.BitLen() {
		return false
	}
	if pk.N.ProbablyPrime(64) || pk.N.Bit(0) == 0 {
		return false
	}
	want, err := ProveModulus(domain, pk, party)
	if err != nil {
		return false
	}
	return bytes.Equal(want.SmallFactorCheck, proof.SmallFactorCheck) &&
		bytes.Equal(want.TranscriptHash, proof.TranscriptHash) &&
		bytes.Equal(want.Digest, proof.Digest)
}

// Marshal returns deterministic canonical binary proof payloads.
func Marshal(v any) ([]byte, error) {
	switch p := v.(type) {
	case *ModulusProof:
		return marshalModulusProof(p)
	case ModulusProof:
		return marshalModulusProof(&p)
	case *EncScalarProof:
		return marshalEncScalarProof(p)
	case EncScalarProof:
		return marshalEncScalarProof(&p)
	case *EncRangeProof:
		return marshalEncRangeProof(p)
	case EncRangeProof:
		return marshalEncRangeProof(&p)
	case *MTAResponseProof:
		return marshalMTAResponseProof(p)
	case MTAResponseProof:
		return marshalMTAResponseProof(&p)
	default:
		return nil, fmt.Errorf("unsupported Paillier proof type %T", v)
	}
}

// UnmarshalModulusProof decodes and structurally validates a modulus proof.
func UnmarshalModulusProof(in []byte) (*ModulusProof, error) {
	version, fields, err := wire.Unmarshal(in, modulusProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected modulus proof version %d", version)
	}
	if err := requireExactProofTags(fields, modulusProofFieldNBits, modulusProofFieldSmallFactorCheck, modulusProofFieldTranscriptHash, modulusProofFieldDigest); err != nil {
		return nil, err
	}
	nBits, err := wire.Uint32Field(fields, modulusProofFieldNBits)
	if err != nil {
		return nil, err
	}
	p := &ModulusProof{
		Version:          proofVersion,
		NBits:            int(nBits),
		SmallFactorCheck: wire.MustField(fields, modulusProofFieldSmallFactorCheck),
		TranscriptHash:   wire.MustField(fields, modulusProofFieldTranscriptHash),
		Digest:           wire.MustField(fields, modulusProofFieldDigest),
	}
	if err := validateModulusProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalEncScalarProof decodes and validates an encrypted scalar proof shell.
func UnmarshalEncScalarProof(in []byte) (*EncScalarProof, error) {
	version, fields, err := wire.Unmarshal(in, encScalarProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected encrypted scalar proof version %d", version)
	}
	if err := requireExactProofTags(fields, encScalarProofFieldScalarCommitment, encScalarProofFieldCipherCommitment, encScalarProofFieldPointCommitment, encScalarProofFieldResponse, encScalarProofFieldRandomness, encScalarProofFieldTranscriptHash); err != nil {
		return nil, err
	}
	p := &EncScalarProof{
		Version:          proofVersion,
		ScalarCommitment: wire.MustField(fields, encScalarProofFieldScalarCommitment),
		CipherCommitment: wire.MustField(fields, encScalarProofFieldCipherCommitment),
		PointCommitment:  wire.MustField(fields, encScalarProofFieldPointCommitment),
		Response:         wire.MustField(fields, encScalarProofFieldResponse),
		Randomness:       wire.MustField(fields, encScalarProofFieldRandomness),
		TranscriptHash:   wire.MustField(fields, encScalarProofFieldTranscriptHash),
	}
	if err := validateEncScalarProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalEncRangeProof decodes and validates an encrypted range proof shell.
func UnmarshalEncRangeProof(in []byte) (*EncRangeProof, error) {
	version, fields, err := wire.Unmarshal(in, encRangeProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected encrypted range proof version %d", version)
	}
	if err := requireExactProofTags(fields, encRangeProofFieldBound, encRangeProofFieldChallenge, encRangeProofFieldResponse, encRangeProofFieldTranscriptHash, encRangeProofFieldDigest); err != nil {
		return nil, err
	}
	p := &EncRangeProof{
		Version:        proofVersion,
		Bound:          wire.MustField(fields, encRangeProofFieldBound),
		Challenge:      wire.MustField(fields, encRangeProofFieldChallenge),
		Response:       wire.MustField(fields, encRangeProofFieldResponse),
		TranscriptHash: wire.MustField(fields, encRangeProofFieldTranscriptHash),
		Digest:         wire.MustField(fields, encRangeProofFieldDigest),
	}
	if err := validateEncRangeProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// UnmarshalMTAResponseProof decodes and validates an MtA response proof shell.
func UnmarshalMTAResponseProof(in []byte) (*MTAResponseProof, error) {
	version, fields, err := wire.Unmarshal(in, mtaResponseProofWireType)
	if err != nil {
		return nil, err
	}
	if version != proofVersion {
		return nil, fmt.Errorf("unexpected MtA response proof version %d", version)
	}
	if err := requireExactProofTags(fields, mtaResponseProofFieldTranscriptHash, mtaResponseProofFieldBetaCommitment, mtaResponseProofFieldCipherCommitment, mtaResponseProofFieldBCommitment, mtaResponseProofFieldBetaNonce, mtaResponseProofFieldBResponse, mtaResponseProofFieldBetaResponse, mtaResponseProofFieldRandomness); err != nil {
		return nil, err
	}
	p := &MTAResponseProof{
		Version:          proofVersion,
		TranscriptHash:   wire.MustField(fields, mtaResponseProofFieldTranscriptHash),
		BetaCommitment:   wire.MustField(fields, mtaResponseProofFieldBetaCommitment),
		CipherCommitment: wire.MustField(fields, mtaResponseProofFieldCipherCommitment),
		BCommitment:      wire.MustField(fields, mtaResponseProofFieldBCommitment),
		BetaNonce:        wire.MustField(fields, mtaResponseProofFieldBetaNonce),
		BResponse:        wire.MustField(fields, mtaResponseProofFieldBResponse),
		BetaResponse:     wire.MustField(fields, mtaResponseProofFieldBetaResponse),
		Randomness:       wire.MustField(fields, mtaResponseProofFieldRandomness),
	}
	if err := validateMTAResponseProof(p); err != nil {
		return nil, err
	}
	return p, nil
}

// ProveEncScalarAndRange proves ciphertext encrypts a secp256k1 scalar.
func ProveEncScalarAndRange(reader io.Reader, domain []byte, pk *pai.PublicKey, ciphertext, scalar, randomness *big.Int) (*EncScalarProof, *EncRangeProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if err := pk.Validate(); err != nil {
		return nil, nil, err
	}
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return nil, nil, err
	}
	if scalar == nil || scalar.Sign() <= 0 || scalar.Cmp(secp.Order()) >= 0 {
		return nil, nil, errors.New("scalar out of range")
	}
	scalarCommitment, err := secp.PointBytes(secp.ScalarBaseMult(scalar))
	if err != nil {
		return nil, nil, err
	}
	alpha, err := randomScalar(reader)
	if err != nil {
		return nil, nil, err
	}
	rho, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, nil, err
	}
	cipherCommitment, err := pk.EncryptWithRandomness(alpha, rho)
	if err != nil {
		return nil, nil, err
	}
	pointCommitment, err := secp.PointBytes(secp.ScalarBaseMult(alpha))
	if err != nil {
		return nil, nil, err
	}
	transcript := encScalarTranscript(domain, pk, ciphertext, scalarCommitment, cipherCommitment, pointCommitment)
	e := challenge([]byte(encScalarChallengeLabel), transcript)
	z := new(big.Int).Mul(e, scalar)
	z.Add(z, alpha)
	u := new(big.Int).Exp(randomness, e, pk.N)
	u.Mul(u, rho)
	u.Mod(u, pk.N)
	encProof := &EncScalarProof{
		Version:          proofVersion,
		ScalarCommitment: scalarCommitment,
		CipherCommitment: intBytes(cipherCommitment),
		PointCommitment:  pointCommitment,
		Response:         intBytes(z),
		Randomness:       intBytes(u),
		TranscriptHash:   transcript,
	}
	rangeProof := &EncRangeProof{
		Version:        proofVersion,
		Bound:          secp.Order().Bytes(),
		Challenge:      intBytes(e),
		Response:       intBytes(z),
		TranscriptHash: transcript,
	}
	rangeProof.Digest = encRangeDigest(rangeProof)
	return encProof, rangeProof, nil
}

// VerifyEncScalarAndRange verifies the paired encrypted scalar and range proofs.
func VerifyEncScalarAndRange(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, encProof *EncScalarProof, rangeProof *EncRangeProof) bool {
	if !VerifyEncScalar(domain, pk, ciphertext, encProof) || validateEncRangeProof(rangeProof) != nil {
		return false
	}
	if !bytes.Equal(rangeProof.TranscriptHash, encProof.TranscriptHash) || !bytes.Equal(rangeProof.Response, encProof.Response) {
		return false
	}
	if new(big.Int).SetBytes(rangeProof.Bound).Cmp(secp.Order()) != 0 {
		return false
	}
	if !bytes.Equal(rangeProof.Digest, encRangeDigest(rangeProof)) {
		return false
	}
	e := challenge([]byte(encScalarChallengeLabel), encProof.TranscriptHash)
	if new(big.Int).SetBytes(rangeProof.Challenge).Cmp(e) != 0 {
		return false
	}
	z := new(big.Int).SetBytes(rangeProof.Response)
	maxResponse := new(big.Int).Lsh(big.NewInt(1), uint(secp.Order().BitLen()*2+2))
	return z.Sign() > 0 && z.Cmp(maxResponse) < 0
}

// VerifyEncScalar verifies the encryption and public scalar commitment relation.
func VerifyEncScalar(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, proof *EncScalarProof) bool {
	if validateEncScalarProof(proof) != nil || pk == nil || pk.ValidateCiphertext(ciphertext) != nil {
		return false
	}
	scalarCommitment, err := secp.PointFromBytes(proof.ScalarCommitment)
	if err != nil {
		return false
	}
	cipherCommitment := new(big.Int).SetBytes(proof.CipherCommitment)
	if pk.ValidateCiphertext(cipherCommitment) != nil {
		return false
	}
	pointCommitment, err := secp.PointFromBytes(proof.PointCommitment)
	if err != nil {
		return false
	}
	transcript := encScalarTranscript(domain, pk, ciphertext, proof.ScalarCommitment, cipherCommitment, proof.PointCommitment)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	z := new(big.Int).SetBytes(proof.Response)
	u := new(big.Int).SetBytes(proof.Randomness)
	if z.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	e := challenge([]byte(encScalarChallengeLabel), transcript)
	encZ, err := pk.EncryptWithRandomness(z, u)
	if err != nil {
		return false
	}
	rightCipher := new(big.Int).Exp(ciphertext, e, pk.NSquared)
	rightCipher.Mul(rightCipher, cipherCommitment)
	rightCipher.Mod(rightCipher, pk.NSquared)
	if encZ.Cmp(rightCipher) != 0 {
		return false
	}
	leftPoint := secp.ScalarBaseMult(z)
	rightPoint := secp.Add(pointCommitment, secp.ScalarMult(scalarCommitment, e))
	return secp.Equal(leftPoint, rightPoint)
}

// ProveMTAResponse proves response encrypts a*b+beta for committed b.
func ProveMTAResponse(reader io.Reader, domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment []byte, b, beta, betaRandomness *big.Int) (*MTAResponseProof, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	if err := pk.ValidateCiphertext(encA); err != nil {
		return nil, fmt.Errorf("invalid input ciphertext: %w", err)
	}
	if err := pk.ValidateCiphertext(response); err != nil {
		return nil, fmt.Errorf("invalid response ciphertext: %w", err)
	}
	if b == nil || b.Sign() <= 0 || b.Cmp(secp.Order()) >= 0 {
		return nil, errors.New("b out of range")
	}
	if beta == nil {
		return nil, errors.New("nil beta")
	}
	betaMod := mod(beta, secp.Order())
	expectedBCommit, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bCommitment, expectedBCommit) {
		return nil, errors.New("b commitment mismatch")
	}
	betaCommitment, err := secp.PointBytes(secp.ScalarBaseMult(betaMod))
	if err != nil {
		return nil, err
	}
	mu, err := randomScalar(reader)
	if err != nil {
		return nil, err
	}
	nu, err := randomScalar(reader)
	if err != nil {
		return nil, err
	}
	rho, err := randomCoprime(reader, pk.N)
	if err != nil {
		return nil, err
	}
	encNu, err := pk.EncryptWithRandomness(nu, rho)
	if err != nil {
		return nil, err
	}
	cipherCommitment := new(big.Int).Exp(encA, mu, pk.NSquared)
	cipherCommitment.Mul(cipherCommitment, encNu)
	cipherCommitment.Mod(cipherCommitment, pk.NSquared)
	bNonce, err := secp.PointBytes(secp.ScalarBaseMult(mu))
	if err != nil {
		return nil, err
	}
	betaNonce, err := secp.PointBytes(secp.ScalarBaseMult(nu))
	if err != nil {
		return nil, err
	}
	transcript := mtaTranscript(domain, pk, encA, response, expectedBCommit, betaCommitment, cipherCommitment, bNonce, betaNonce)
	e := challenge([]byte(mtaChallengeLabel), transcript)
	zB := new(big.Int).Mul(e, b)
	zB.Add(zB, mu)
	zBeta := new(big.Int).Mul(e, betaMod)
	zBeta.Add(zBeta, nu)
	u := new(big.Int).Exp(betaRandomness, e, pk.N)
	u.Mul(u, rho)
	u.Mod(u, pk.N)
	return &MTAResponseProof{
		Version:          proofVersion,
		TranscriptHash:   transcript,
		BetaCommitment:   betaCommitment,
		CipherCommitment: intBytes(cipherCommitment),
		BCommitment:      bNonce,
		BetaNonce:        betaNonce,
		BResponse:        intBytes(zB),
		BetaResponse:     intBytes(zBeta),
		Randomness:       intBytes(u),
	}, nil
}

// VerifyMTAResponse checks the MtA response proof and transcript binding.
func VerifyMTAResponse(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitmentBytes []byte, proof *MTAResponseProof) bool {
	if validateMTAResponseProof(proof) != nil || pk == nil || pk.ValidateCiphertext(encA) != nil || pk.ValidateCiphertext(response) != nil {
		return false
	}
	bCommitment, err := secp.PointFromBytes(bCommitmentBytes)
	if err != nil {
		return false
	}
	betaCommitment, err := secp.PointFromBytes(proof.BetaCommitment)
	if err != nil {
		return false
	}
	bNonce, err := secp.PointFromBytes(proof.BCommitment)
	if err != nil {
		return false
	}
	betaNonce, err := secp.PointFromBytes(proof.BetaNonce)
	if err != nil {
		return false
	}
	cipherCommitment := new(big.Int).SetBytes(proof.CipherCommitment)
	if pk.ValidateCiphertext(cipherCommitment) != nil {
		return false
	}
	zB := new(big.Int).SetBytes(proof.BResponse)
	zBeta := new(big.Int).SetBytes(proof.BetaResponse)
	u := new(big.Int).SetBytes(proof.Randomness)
	if zB.Sign() <= 0 || zBeta.Sign() <= 0 || u.Sign() <= 0 {
		return false
	}
	transcript := mtaTranscript(domain, pk, encA, response, bCommitmentBytes, proof.BetaCommitment, cipherCommitment, proof.BCommitment, proof.BetaNonce)
	if !bytes.Equal(transcript, proof.TranscriptHash) {
		return false
	}
	e := challenge([]byte(mtaChallengeLabel), transcript)

	encZBeta, err := pk.EncryptWithRandomness(zBeta, u)
	if err != nil {
		return false
	}
	leftCipher := new(big.Int).Exp(encA, zB, pk.NSquared)
	leftCipher.Mul(leftCipher, encZBeta)
	leftCipher.Mod(leftCipher, pk.NSquared)
	rightCipher := new(big.Int).Exp(response, e, pk.NSquared)
	rightCipher.Mul(rightCipher, cipherCommitment)
	rightCipher.Mod(rightCipher, pk.NSquared)
	if leftCipher.Cmp(rightCipher) != 0 {
		return false
	}
	leftB := secp.ScalarBaseMult(zB)
	rightB := secp.Add(bNonce, secp.ScalarMult(bCommitment, e))
	if !secp.Equal(leftB, rightB) {
		return false
	}
	leftBeta := secp.ScalarBaseMult(zBeta)
	rightBeta := secp.Add(betaNonce, secp.ScalarMult(betaCommitment, e))
	return secp.Equal(leftBeta, rightBeta)
}

func marshalModulusProof(p *ModulusProof) ([]byte, error) {
	if err := validateModulusProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, modulusProofWireType, []wire.Field{
		{Tag: modulusProofFieldNBits, Value: wire.Uint32(uint32(p.NBits))},
		{Tag: modulusProofFieldSmallFactorCheck, Value: wire.NonNilBytes(p.SmallFactorCheck)},
		{Tag: modulusProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: modulusProofFieldDigest, Value: wire.NonNilBytes(p.Digest)},
	})
}

func marshalEncScalarProof(p *EncScalarProof) ([]byte, error) {
	if err := validateEncScalarProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, encScalarProofWireType, []wire.Field{
		{Tag: encScalarProofFieldScalarCommitment, Value: wire.NonNilBytes(p.ScalarCommitment)},
		{Tag: encScalarProofFieldCipherCommitment, Value: wire.NonNilBytes(p.CipherCommitment)},
		{Tag: encScalarProofFieldPointCommitment, Value: wire.NonNilBytes(p.PointCommitment)},
		{Tag: encScalarProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
		{Tag: encScalarProofFieldRandomness, Value: wire.NonNilBytes(p.Randomness)},
		{Tag: encScalarProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
	})
}

func marshalEncRangeProof(p *EncRangeProof) ([]byte, error) {
	if err := validateEncRangeProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, encRangeProofWireType, []wire.Field{
		{Tag: encRangeProofFieldBound, Value: wire.NonNilBytes(p.Bound)},
		{Tag: encRangeProofFieldChallenge, Value: wire.NonNilBytes(p.Challenge)},
		{Tag: encRangeProofFieldResponse, Value: wire.NonNilBytes(p.Response)},
		{Tag: encRangeProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: encRangeProofFieldDigest, Value: wire.NonNilBytes(p.Digest)},
	})
}

func marshalMTAResponseProof(p *MTAResponseProof) ([]byte, error) {
	if err := validateMTAResponseProof(p); err != nil {
		return nil, err
	}
	return wire.Marshal(proofVersion, mtaResponseProofWireType, []wire.Field{
		{Tag: mtaResponseProofFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: mtaResponseProofFieldBetaCommitment, Value: wire.NonNilBytes(p.BetaCommitment)},
		{Tag: mtaResponseProofFieldCipherCommitment, Value: wire.NonNilBytes(p.CipherCommitment)},
		{Tag: mtaResponseProofFieldBCommitment, Value: wire.NonNilBytes(p.BCommitment)},
		{Tag: mtaResponseProofFieldBetaNonce, Value: wire.NonNilBytes(p.BetaNonce)},
		{Tag: mtaResponseProofFieldBResponse, Value: wire.NonNilBytes(p.BResponse)},
		{Tag: mtaResponseProofFieldBetaResponse, Value: wire.NonNilBytes(p.BetaResponse)},
		{Tag: mtaResponseProofFieldRandomness, Value: wire.NonNilBytes(p.Randomness)},
	})
}

func validateModulusProof(p *ModulusProof) error {
	if p == nil {
		return errors.New("nil modulus proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected modulus proof version %d", p.Version)
	}
	if p.NBits <= 0 {
		return errors.New("invalid modulus proof bit length")
	}
	if uint64(p.NBits) > uint64(^uint32(0)) {
		return errors.New("modulus proof bit length too large")
	}
	if len(p.TranscriptHash) != sha256.Size || len(p.Digest) != sha256.Size || len(p.SmallFactorCheck) != sha256.Size {
		return errors.New("invalid modulus proof")
	}
	return nil
}

func validateEncScalarProof(p *EncScalarProof) error {
	if p == nil {
		return errors.New("nil encrypted scalar proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected encrypted scalar proof version %d", p.Version)
	}
	if len(p.ScalarCommitment) == 0 || len(p.CipherCommitment) == 0 || len(p.PointCommitment) == 0 || len(p.Response) == 0 || len(p.Randomness) == 0 || len(p.TranscriptHash) != sha256.Size {
		return errors.New("incomplete encrypted scalar proof")
	}
	if err := validateCurvePointBytes("scalar commitment", p.ScalarCommitment); err != nil {
		return err
	}
	if err := validateCurvePointBytes("point commitment", p.PointCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("cipher commitment", p.CipherCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("randomness", p.Randomness); err != nil {
		return err
	}
	return nil
}

func validateEncRangeProof(p *EncRangeProof) error {
	if p == nil {
		return errors.New("nil encrypted range proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected encrypted range proof version %d", p.Version)
	}
	if len(p.Bound) == 0 || len(p.Challenge) == 0 || len(p.Response) == 0 || len(p.TranscriptHash) != sha256.Size || len(p.Digest) != sha256.Size {
		return errors.New("incomplete encrypted range proof")
	}
	if err := validatePositiveIntBytes("bound", p.Bound); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("challenge", p.Challenge); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("response", p.Response); err != nil {
		return err
	}
	return nil
}

func validateMTAResponseProof(p *MTAResponseProof) error {
	if p == nil {
		return errors.New("nil MtA response proof")
	}
	if p.Version != proofVersion {
		return fmt.Errorf("unexpected MtA response proof version %d", p.Version)
	}
	if len(p.TranscriptHash) != sha256.Size || len(p.BetaCommitment) == 0 || len(p.CipherCommitment) == 0 || len(p.BCommitment) == 0 || len(p.BetaNonce) == 0 || len(p.BResponse) == 0 || len(p.BetaResponse) == 0 || len(p.Randomness) == 0 {
		return errors.New("incomplete MtA response proof")
	}
	if err := validateCurvePointBytes("beta commitment", p.BetaCommitment); err != nil {
		return err
	}
	if err := validateCurvePointBytes("b commitment", p.BCommitment); err != nil {
		return err
	}
	if err := validateCurvePointBytes("beta nonce", p.BetaNonce); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("cipher commitment", p.CipherCommitment); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("b response", p.BResponse); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("beta response", p.BetaResponse); err != nil {
		return err
	}
	if err := validatePositiveIntBytes("randomness", p.Randomness); err != nil {
		return err
	}
	return nil
}

func validateCurvePointBytes(name string, in []byte) error {
	if _, err := secp.PointFromBytes(in); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}

func validatePositiveIntBytes(name string, in []byte) error {
	if len(in) == 0 {
		return fmt.Errorf("%s is empty", name)
	}
	if in[0] == 0 {
		return fmt.Errorf("%s is not minimally encoded", name)
	}
	return nil
}

func requireExactProofTags(fields []wire.Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("unexpected proof field count %d", len(fields))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected proof field tag %d", fields[i].Tag)
		}
	}
	return nil
}

func encScalarTranscript(domain []byte, pk *pai.PublicKey, ciphertext *big.Int, scalarCommitment []byte, cipherCommitment *big.Int, pointCommitment []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return hashParts([]byte(encScalarTranscriptLabel), domain, pkBytes, intBytes(ciphertext), scalarCommitment, intBytes(cipherCommitment), pointCommitment)
}

func mtaTranscript(domain []byte, pk *pai.PublicKey, encA, response *big.Int, bCommitment, betaCommitment []byte, cipherCommitment *big.Int, bNonce, betaNonce []byte) []byte {
	pkBytes, _ := pk.MarshalBinary()
	return hashParts([]byte(mtaTranscriptLabel), domain, pkBytes, intBytes(encA), intBytes(response), bCommitment, betaCommitment, intBytes(cipherCommitment), bNonce, betaNonce)
}

func encRangeDigest(proof *EncRangeProof) []byte {
	if proof == nil {
		return nil
	}
	return hashParts([]byte(encRangeDigestLabel), proof.Bound, proof.Challenge, proof.Response, proof.TranscriptHash)
}

func challenge(parts ...[]byte) *big.Int {
	out := new(big.Int).SetBytes(hashParts(parts...))
	out.Mod(out, secp.Order())
	if out.Sign() == 0 {
		out.SetInt64(1)
	}
	return out
}

func smallFactorDigest(n *big.Int) []byte {
	h := sha256.New()
	for _, p := range []int64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47} {
		rem := new(big.Int).Mod(n, big.NewInt(p)).Int64()
		_, _ = h.Write([]byte{byte(p), byte(rem)})
	}
	return h.Sum(nil)
}

func hashParts(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
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

func randomCoprime(reader io.Reader, n *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	for {
		x, err := rand.Int(reader, n)
		if err != nil {
			return nil, err
		}
		if x.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, x, n).Cmp(one) == 0 {
			return x, nil
		}
	}
}

func intBytes(x *big.Int) []byte {
	if x == nil {
		return nil
	}
	return x.Bytes()
}

func partyBytes(party uint32) []byte {
	return []byte{byte(party >> 24), byte(party >> 16), byte(party >> 8), byte(party)}
}

func mod(x, m *big.Int) *big.Int {
	out := new(big.Int).Mod(x, m)
	if out.Sign() < 0 {
		out.Add(out, m)
	}
	return out
}
