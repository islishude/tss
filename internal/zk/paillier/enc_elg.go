package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const (
	encElgProofType    = "zk.paillier.enc-elg-proof"
	encElgProofVersion = 1
)

// EncElgStatement is the Figure 24 Πenc-elg statement specialized to the
// Figure 8 relation used by CGGMP21. In additive notation it proves that
// Ciphertext encrypts x and that
//
//	ExponentCommitment = [a]Generator
//	CombinedCommitment = [a]ElGamalBase + [x]Generator.
//
// ElGamalBase is Figure 24's A, ExponentCommitment is its B, and
// CombinedCommitment is its X. The prover does not need the discrete logarithm
// of ElGamalBase.
type EncElgStatement struct {
	Generator          *secp.Point
	PaillierN          *pai.PublicKey
	Ciphertext         *big.Int
	ElGamalBase        *secp.Point
	ExponentCommitment *secp.Point
	CombinedCommitment *secp.Point
	VerifierAux        *RingPedersenParams
}

// EncElgWitness is the secret opening of an EncElgStatement.
type EncElgWitness struct {
	Plaintext  *secret.Scalar
	Randomness *secret.Scalar
	Exponent   *secret.Scalar
}

// EncElgProof is the Fiat-Shamir form of Figure 24 Πenc-elg.
type EncElgProof struct {
	PlaintextCommitment    *big.Int `wire:"1,bigpos,max_bytes=paillier_modulus"`
	CiphertextCommitment   *big.Int `wire:"2,bigpos,max_bytes=paillier_signed"`
	ElGamalCommitment      []byte   `wire:"3,bytes,max_bytes=point"`
	ExponentMaskCommitment []byte   `wire:"4,bytes,max_bytes=point"`
	RangeMaskCommitment    *big.Int `wire:"5,bigpos,max_bytes=paillier_modulus"`
	PlaintextResponse      *big.Int `wire:"6,bigint,max_bytes=signed_response"`
	ExponentResponse       []byte   `wire:"7,bytes,len=32"`
	RandomnessResponse     *big.Int `wire:"8,bigpos,max_bytes=paillier_signed"`
	RangeResponse          *big.Int `wire:"9,bigint,max_bytes=signed_response"`
	TranscriptHash         []byte   `wire:"10,bytes,len=32"`
}

// WireType returns the canonical Πenc-elg proof wire type.
func (EncElgProof) WireType() string { return encElgProofType }

// WireVersion returns the canonical Πenc-elg proof wire version.
func (EncElgProof) WireVersion() uint16 { return encElgProofVersion }

// Clone returns an independently owned Πenc-elg proof.
func (p *EncElgProof) Clone() *EncElgProof {
	if p == nil {
		return nil
	}
	return &EncElgProof{
		PlaintextCommitment:    tss.CloneBigInt(p.PlaintextCommitment),
		CiphertextCommitment:   tss.CloneBigInt(p.CiphertextCommitment),
		ElGamalCommitment:      bytes.Clone(p.ElGamalCommitment),
		ExponentMaskCommitment: bytes.Clone(p.ExponentMaskCommitment),
		RangeMaskCommitment:    tss.CloneBigInt(p.RangeMaskCommitment),
		PlaintextResponse:      tss.CloneBigInt(p.PlaintextResponse),
		ExponentResponse:       bytes.Clone(p.ExponentResponse),
		RandomnessResponse:     tss.CloneBigInt(p.RandomnessResponse),
		RangeResponse:          tss.CloneBigInt(p.RangeResponse),
		TranscriptHash:         bytes.Clone(p.TranscriptHash),
	}
}

// Destroy clears all proof fields.
func (p *EncElgProof) Destroy() {
	if p == nil {
		return
	}
	secret.ClearBigInt(p.PlaintextCommitment)
	secret.ClearBigInt(p.CiphertextCommitment)
	clear(p.ElGamalCommitment)
	clear(p.ExponentMaskCommitment)
	secret.ClearBigInt(p.RangeMaskCommitment)
	secret.ClearBigInt(p.PlaintextResponse)
	clear(p.ExponentResponse)
	secret.ClearBigInt(p.RandomnessResponse)
	secret.ClearBigInt(p.RangeResponse)
	clear(p.TranscriptHash)
	*p = EncElgProof{}
}

// Validate checks the structural and canonical Πenc-elg proof encoding.
func (p *EncElgProof) Validate() error {
	if p == nil {
		return errors.New("nil EncElgProof")
	}
	if p.PlaintextCommitment == nil || p.CiphertextCommitment == nil ||
		p.RangeMaskCommitment == nil || p.PlaintextResponse == nil ||
		p.RandomnessResponse == nil || p.RangeResponse == nil {
		return errors.New("incomplete EncElgProof")
	}
	if _, err := secp.PointFromBytes(p.ElGamalCommitment); err != nil {
		return fmt.Errorf("EncElgProof: invalid ElGamal commitment: %w", err)
	}
	if _, err := secp.PointFromBytes(p.ExponentMaskCommitment); err != nil {
		return fmt.Errorf("EncElgProof: invalid exponent-mask commitment: %w", err)
	}
	if _, err := secp.ScalarFromBytesAllowZero(p.ExponentResponse); err != nil {
		return fmt.Errorf("EncElgProof: invalid exponent response: %w", err)
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("EncElgProof: invalid transcript hash")
	}
	return nil
}

// MarshalBinary encodes a canonical Πenc-elg proof.
func (p *EncElgProof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes a canonical Πenc-elg proof.
func (p *EncElgProof) UnmarshalBinary(in []byte) error {
	var decoded EncElgProof
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(zkFrameLimits(tss.DefaultMaxZKProofBytes)),
		wire.WithFieldLimits(zkFieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// ProveEncElg creates a Figure 24 Πenc-elg proof bound to state.
func ProveEncElg(params SecurityParams, state []byte, stmt EncElgStatement, witness EncElgWitness, rng io.Reader) (*EncElgProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if err := validateEncElgStatement(params, stmt, witness); err != nil {
		return nil, err
	}

	n := stmt.PaillierN
	nhat := stmt.VerifierAux.N
	alpha, err := sampleSignedSecret(rng, params.EncRange())
	if err != nil {
		return nil, err
	}
	defer alpha.Destroy()
	mu, err := sampleMultRangeSecret(rng, params.Ell, nhat)
	if err != nil {
		return nil, err
	}
	defer mu.Destroy()
	r, err := sampleZNStarSecret(rng, n.N)
	if err != nil {
		return nil, err
	}
	defer r.Destroy()
	beta, err := secp.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	defer beta.Set(secp.ScalarZero())
	gamma, err := sampleMultRangeSecret(rng, params.EncRange(), nhat)
	if err != nil {
		return nil, err
	}
	defer gamma.Destroy()

	secretCommitLen := max(signedPowerOfTwoBytes(params.Ell), multRangeBytes(nhat, params.Ell))
	xSigned, err := signedSecretFromScalar(witness.Plaintext, secretCommitLen)
	if err != nil {
		return nil, err
	}
	defer xSigned.Destroy()
	muPadded, err := resizeSignedSecret(mu, secretCommitLen)
	if err != nil {
		return nil, err
	}
	defer muPadded.Destroy()
	plaintextCommitment, err := RPCommitCT(stmt.VerifierAux, xSigned, muPadded, secretCommitLen)
	if err != nil {
		return nil, err
	}
	ciphertextCommitment, err := encRandomSecrets(n, alpha, r)
	if err != nil {
		return nil, err
	}
	alphaScalar, err := signedSecretSecpScalar(alpha)
	if err != nil {
		return nil, err
	}
	defer alphaScalar.Set(secp.ScalarZero())
	elgamalCommitmentPoint := secp.Add(
		secp.ScalarMult(stmt.ElGamalBase, beta),
		secp.ScalarMult(stmt.Generator, alphaScalar),
	)
	elgamalCommitment, err := secp.PointBytes(elgamalCommitmentPoint)
	if err != nil {
		return nil, err
	}
	exponentMaskCommitment, err := secp.PointBytes(secp.ScalarMult(stmt.Generator, beta))
	if err != nil {
		return nil, err
	}
	maskCommitLen := max(signedPowerOfTwoBytes(params.EncRange()), multRangeBytes(nhat, params.EncRange()))
	alphaPadded, err := resizeSignedSecret(alpha, maskCommitLen)
	if err != nil {
		return nil, err
	}
	defer alphaPadded.Destroy()
	gammaPadded, err := resizeSignedSecret(gamma, maskCommitLen)
	if err != nil {
		return nil, err
	}
	defer gammaPadded.Destroy()
	rangeMaskCommitment, err := RPCommitCT(stmt.VerifierAux, alphaPadded, gammaPadded, maskCommitLen)
	if err != nil {
		return nil, err
	}

	transcript, err := buildEncElgTranscript(
		params,
		state,
		stmt,
		plaintextCommitment,
		ciphertextCommitment,
		elgamalCommitment,
		exponentMaskCommitment,
		rangeMaskCommitment,
	)
	if err != nil {
		return nil, err
	}
	eScalar, e, err := transcript.ChallengeScalar(params.ChallengeBits)
	if err != nil {
		return nil, err
	}

	x, err := secretScalarBig(witness.Plaintext)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(x)
	alphaBig, err := signedSecretBig(alpha)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(alphaBig)
	plaintextResponse := new(big.Int).Mul(e, x)
	plaintextResponse.Add(plaintextResponse, alphaBig)

	exponent, err := secpScalarFromSecretAllowZero(witness.Exponent, "exponent")
	if err != nil {
		return nil, err
	}
	defer exponent.Set(secp.ScalarZero())
	exponentResponse := secp.ScalarAdd(beta, secp.ScalarMul(eScalar, exponent))

	rBig, err := secretScalarBig(r)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rBig)
	rho, err := secretScalarBig(witness.Randomness)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rho)
	// e is the public Fiat-Shamir challenge. Keep the exponentiation routed
	// through the audited public-exponent boundary even though rho is secret.
	rhoPower, err := ExpSignedMod(rho, e, n.N)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(rhoPower)
	randomnessResponse := new(big.Int).Mul(rBig, rhoPower)
	randomnessResponse.Mod(randomnessResponse, n.N)

	muBig, err := signedSecretBig(mu)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(muBig)
	gammaBig, err := signedSecretBig(gamma)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(gammaBig)
	rangeResponse := new(big.Int).Mul(e, muBig)
	rangeResponse.Add(rangeResponse, gammaBig)

	return &EncElgProof{
		PlaintextCommitment:    plaintextCommitment,
		CiphertextCommitment:   ciphertextCommitment,
		ElGamalCommitment:      elgamalCommitment,
		ExponentMaskCommitment: exponentMaskCommitment,
		RangeMaskCommitment:    rangeMaskCommitment,
		PlaintextResponse:      plaintextResponse,
		ExponentResponse:       exponentResponse.Bytes(),
		RandomnessResponse:     randomnessResponse,
		RangeResponse:          rangeResponse,
		TranscriptHash:         transcript.Sum(),
	}, nil
}

// VerifyEncElg verifies a Figure 24 Πenc-elg proof bound to state.
func VerifyEncElg(params SecurityParams, state []byte, stmt EncElgStatement, proof *EncElgProof) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if err := validateEncElgPublic(params, stmt); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	n := stmt.PaillierN
	nhat := stmt.VerifierAux.N
	if _, err := RequireZNStar(proof.PlaintextCommitment, nhat); err != nil {
		return fmt.Errorf("EncElgProof: plaintext commitment: %w", err)
	}
	if _, err := RequireZN2Star(proof.CiphertextCommitment, n.N); err != nil {
		return fmt.Errorf("EncElgProof: ciphertext commitment: %w", err)
	}
	if _, err := RequireZNStar(proof.RangeMaskCommitment, nhat); err != nil {
		return fmt.Errorf("EncElgProof: range-mask commitment: %w", err)
	}
	if _, err := RequireZNStar(proof.RandomnessResponse, n.N); err != nil {
		return fmt.Errorf("EncElgProof: randomness response: %w", err)
	}
	if !InSignedPowerOfTwo(proof.PlaintextResponse, params.EncRange()+1) {
		return fmt.Errorf("EncElgProof: plaintext response out of range ±2^%d", params.EncRange()+1)
	}
	if !inMultRange(proof.RangeResponse, nhat, params.EncRange()+1) {
		return errors.New("EncElgProof: range response out of range")
	}

	transcript, err := buildEncElgTranscript(
		params,
		state,
		stmt,
		proof.PlaintextCommitment,
		proof.CiphertextCommitment,
		proof.ElGamalCommitment,
		proof.ExponentMaskCommitment,
		proof.RangeMaskCommitment,
	)
	if err != nil {
		return err
	}
	if !bytes.Equal(transcript.Sum(), proof.TranscriptHash) {
		return errors.New("EncElgProof: transcript hash mismatch")
	}
	eScalar, e, err := transcript.ChallengeScalar(params.ChallengeBits)
	if err != nil {
		return err
	}
	w, _ := secp.ScalarFromBytesAllowZero(proof.ExponentResponse)
	yCommitment, _ := secp.PointFromBytes(proof.ElGamalCommitment)
	zCommitment, _ := secp.PointFromBytes(proof.ExponentMaskCommitment)
	z1Scalar := secp.ScalarFromBigInt(proof.PlaintextResponse)

	encResponse, err := EncRandom(n, proof.PlaintextResponse, proof.RandomnessResponse)
	if err != nil {
		return fmt.Errorf("EncElgProof: encrypt response: %w", err)
	}
	ciphertextPower, err := OMulPublic(n, e, stmt.Ciphertext)
	if err != nil {
		return fmt.Errorf("EncElgProof: challenge ciphertext: %w", err)
	}
	wantEnc, err := OAdd(n, proof.CiphertextCommitment, ciphertextPower)
	if err != nil {
		return fmt.Errorf("EncElgProof: Paillier equation: %w", err)
	}
	if encResponse.Cmp(wantEnc) != 0 {
		return errors.New("EncElgProof: Paillier equation failed")
	}

	leftElGamal := secp.Add(
		secp.ScalarMult(stmt.ElGamalBase, w),
		secp.ScalarMult(stmt.Generator, z1Scalar),
	)
	rightElGamal := secp.Add(yCommitment, secp.ScalarMult(stmt.CombinedCommitment, eScalar))
	if !secp.Equal(leftElGamal, rightElGamal) {
		return errors.New("EncElgProof: ElGamal equation failed")
	}
	if !secp.Equal(
		secp.ScalarMult(stmt.Generator, w),
		secp.Add(zCommitment, secp.ScalarMult(stmt.ExponentCommitment, eScalar)),
	) {
		return errors.New("EncElgProof: exponent equation failed")
	}

	leftRange, err := RPCommit(stmt.VerifierAux, proof.PlaintextResponse, proof.RangeResponse)
	if err != nil {
		return fmt.Errorf("EncElgProof: range response commitment: %w", err)
	}
	plaintextCommitmentPower, err := ExpSignedMod(proof.PlaintextCommitment, e, nhat)
	if err != nil {
		return fmt.Errorf("EncElgProof: challenge range commitment: %w", err)
	}
	rightRange := new(big.Int).Mul(proof.RangeMaskCommitment, plaintextCommitmentPower)
	rightRange.Mod(rightRange, nhat)
	if leftRange.Cmp(rightRange) != 0 {
		return errors.New("EncElgProof: Ring-Pedersen equation failed")
	}
	return nil
}

func validateEncElgPublic(params SecurityParams, stmt EncElgStatement) error {
	if stmt.PaillierN == nil {
		return errors.New("EncElgProof: nil Paillier key")
	}
	if err := stmt.PaillierN.Validate(); err != nil {
		return fmt.Errorf("EncElgProof: invalid Paillier key: %w", err)
	}
	if err := params.CheckPaillierModulus(stmt.PaillierN); err != nil {
		return fmt.Errorf("EncElgProof: %w", err)
	}
	if err := stmt.PaillierN.ValidateCiphertext(stmt.Ciphertext); err != nil {
		return fmt.Errorf("EncElgProof: invalid ciphertext: %w", err)
	}
	if err := validateRPParamsForProof(params, stmt.VerifierAux); err != nil {
		return fmt.Errorf("EncElgProof: invalid verifier aux: %w", err)
	}
	if err := validateAuxModulusDistinct(stmt.VerifierAux, stmt.PaillierN); err != nil {
		return fmt.Errorf("EncElgProof: invalid verifier aux: %w", err)
	}
	for _, field := range []struct {
		name  string
		point *secp.Point
	}{
		{"Generator", stmt.Generator},
		{"ElGamalBase", stmt.ElGamalBase},
		{"ExponentCommitment", stmt.ExponentCommitment},
		{"CombinedCommitment", stmt.CombinedCommitment},
	} {
		if _, err := secp.PointBytes(field.point); err != nil {
			return fmt.Errorf("EncElgProof: invalid statement %s: %w", field.name, err)
		}
	}
	return nil
}

func validateEncElgStatement(params SecurityParams, stmt EncElgStatement, witness EncElgWitness) error {
	if err := validateEncElgPublic(params, stmt); err != nil {
		return err
	}
	if witness.Plaintext == nil || witness.Randomness == nil || witness.Exponent == nil {
		return errors.New("EncElgProof: nil witness")
	}
	x, err := secpScalarFromSecretAllowZero(witness.Plaintext, "plaintext")
	if err != nil {
		return err
	}
	defer x.Set(secp.ScalarZero())
	xBig, err := secretScalarBig(witness.Plaintext)
	if err != nil {
		return errors.New("EncElgProof: invalid plaintext witness")
	}
	defer secret.ClearBigInt(xBig)
	if !InUnsignedPowerOfTwo(xBig, params.Ell) {
		return errors.New("EncElgProof: plaintext witness out of range")
	}
	if witness.Randomness.FixedLen() != modulusBytes(stmt.PaillierN.N) {
		return errors.New("EncElgProof: randomness witness has invalid width")
	}
	rho, err := secretScalarBig(witness.Randomness)
	if err != nil || !IsZNStar(rho, stmt.PaillierN.N) {
		secret.ClearBigInt(rho)
		return errors.New("EncElgProof: invalid randomness witness")
	}
	secret.ClearBigInt(rho)
	a, err := secpScalarFromSecretAllowZero(witness.Exponent, "exponent")
	if err != nil {
		return err
	}
	defer a.Set(secp.ScalarZero())

	expectedCiphertext, err := stmt.PaillierN.EncryptWithSecretRandomness(witness.Plaintext, witness.Randomness)
	if err != nil {
		return fmt.Errorf("EncElgProof: verify ciphertext opening: %w", err)
	}
	if expectedCiphertext.Cmp(stmt.Ciphertext) != 0 {
		return errors.New("EncElgProof: plaintext witness does not open ciphertext")
	}
	if !secp.Equal(secp.ScalarMult(stmt.Generator, a), stmt.ExponentCommitment) {
		return errors.New("EncElgProof: exponent witness does not open exponent commitment")
	}
	expectedCombined := secp.Add(secp.ScalarMult(stmt.ElGamalBase, a), secp.ScalarMult(stmt.Generator, x))
	if !secp.Equal(expectedCombined, stmt.CombinedCommitment) {
		return errors.New("EncElgProof: witness does not open combined commitment")
	}
	return nil
}

func buildEncElgTranscript(
	params SecurityParams,
	state []byte,
	stmt EncElgStatement,
	plaintextCommitment *big.Int,
	ciphertextCommitment *big.Int,
	elgamalCommitment []byte,
	exponentMaskCommitment []byte,
	rangeMaskCommitment *big.Int,
) (*Transcript, error) {
	if err := validateEncElgPublic(params, stmt); err != nil {
		return nil, err
	}
	t := NewTranscript("cggmp21-paillier-enc-elg-proof-v1")
	appendSecurityParams(t, params)
	t.AppendBytes("state", state)
	if err := t.AppendBigInt("paillier_N", stmt.PaillierN.N); err != nil {
		return nil, err
	}
	if err := t.AppendBigInt("ciphertext", stmt.Ciphertext); err != nil {
		return nil, err
	}
	nhatLen := modulusBytes(stmt.VerifierAux.N)
	for _, field := range []struct {
		name  string
		value *big.Int
	}{
		{"verifier_N", stmt.VerifierAux.N},
		{"verifier_S", stmt.VerifierAux.S},
		{"verifier_T", stmt.VerifierAux.T},
	} {
		encoded, err := fixedModNBytes(field.value, nhatLen)
		if err != nil {
			return nil, fmt.Errorf("EncElgProof transcript %s: %w", field.name, err)
		}
		t.AppendBytes(field.name, encoded)
	}
	for _, field := range []struct {
		name  string
		point *secp.Point
	}{
		{"generator", stmt.Generator},
		{"elgamal_base", stmt.ElGamalBase},
		{"exponent_commitment", stmt.ExponentCommitment},
		{"combined_commitment", stmt.CombinedCommitment},
	} {
		if err := t.AppendPoint(field.name, field.point); err != nil {
			return nil, err
		}
	}
	for _, field := range []struct {
		name  string
		value *big.Int
	}{
		{"plaintext_commitment", plaintextCommitment},
		{"ciphertext_commitment", ciphertextCommitment},
		{"range_mask_commitment", rangeMaskCommitment},
	} {
		if err := t.AppendBigInt(field.name, field.value); err != nil {
			return nil, err
		}
	}
	if err := t.AppendPointBytes("elgamal_commitment", elgamalCommitment); err != nil {
		return nil, err
	}
	if err := t.AppendPointBytes("exponent_mask_commitment", exponentMaskCommitment); err != nil {
		return nil, err
	}
	return t, nil
}
