package paillier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkchallenge "github.com/islishude/tss/internal/zk/challenge"
)

const (
	elogProofType    = "zk.paillier.elog-proof"
	elogProofVersion = 1
)

// ElogStatement is the public input for Figure 23 Πelog. Group operations use
// additive notation: LambdaCommitment=[lambda]Generator,
// ElGamalCommitment=[y]Generator+[lambda]ElGamalBase, and
// ResultCommitment=[y]ResultBase.
type ElogStatement struct {
	Generator         *secp.Point
	LambdaCommitment  *secp.Point
	ElGamalCommitment *secp.Point
	ElGamalBase       *secp.Point
	ResultCommitment  *secp.Point
	ResultBase        *secp.Point
}

// ElogWitness is the secret input for Figure 23 Πelog.
type ElogWitness struct {
	Y      *secret.Scalar
	Lambda *secret.Scalar
}

// ElogProof is the Fiat-Shamir form of Figure 23 Πelog.
type ElogProof struct {
	A              []byte `wire:"1,bytes,max_bytes=point"`
	N              []byte `wire:"2,bytes,max_bytes=point"`
	B              []byte `wire:"3,bytes,max_bytes=point"`
	Z              []byte `wire:"4,bytes,len=32"`
	U              []byte `wire:"5,bytes,len=32"`
	TranscriptHash []byte `wire:"6,bytes,len=32"`
}

// WireType returns the canonical Πelog proof wire type.
func (ElogProof) WireType() string { return elogProofType }

// WireVersion returns the canonical Πelog proof wire version.
func (ElogProof) WireVersion() uint16 { return elogProofVersion }

// Clone returns an independently owned Πelog proof.
func (p *ElogProof) Clone() *ElogProof {
	if p == nil {
		return nil
	}
	return &ElogProof{
		A:              bytes.Clone(p.A),
		N:              bytes.Clone(p.N),
		B:              bytes.Clone(p.B),
		Z:              bytes.Clone(p.Z),
		U:              bytes.Clone(p.U),
		TranscriptHash: bytes.Clone(p.TranscriptHash),
	}
}

// Destroy clears all proof fields.
func (p *ElogProof) Destroy() {
	if p == nil {
		return
	}
	clear(p.A)
	clear(p.N)
	clear(p.B)
	clear(p.Z)
	clear(p.U)
	clear(p.TranscriptHash)
	*p = ElogProof{}
}

// Validate checks the structural and canonical Πelog proof encoding.
func (p *ElogProof) Validate() error {
	if p == nil {
		return errors.New("nil ElogProof")
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{{"A", p.A}, {"N", p.N}, {"B", p.B}} {
		if _, err := secp.PointFromBytes(field.value); err != nil {
			return fmt.Errorf("ElogProof: invalid %s: %w", field.name, err)
		}
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{{"z", p.Z}, {"u", p.U}} {
		if _, err := secp.ScalarFromBytesAllowZero(field.value); err != nil {
			return fmt.Errorf("ElogProof: invalid %s: %w", field.name, err)
		}
	}
	if len(p.TranscriptHash) != sha256.Size {
		return errors.New("ElogProof: invalid transcript hash")
	}
	return nil
}

// MarshalBinary encodes a canonical Πelog proof.
func (p *ElogProof) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(zkFieldLimits()))
}

// UnmarshalBinary decodes a canonical Πelog proof.
func (p *ElogProof) UnmarshalBinary(in []byte) error {
	var decoded ElogProof
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

// ProveElog creates a Figure 23 Πelog proof bound to state.
func ProveElog(state []byte, stmt ElogStatement, witness ElogWitness, rng io.Reader) (*ElogProof, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if err := validateElogStatement(stmt, witness); err != nil {
		return nil, err
	}
	y, err := secpScalarFromSecretAllowZero(witness.Y, "y")
	if err != nil {
		return nil, err
	}
	defer y.Set(secp.ScalarZero())
	lambda, err := secpScalarFromSecretAllowZero(witness.Lambda, "lambda")
	if err != nil {
		return nil, err
	}
	defer lambda.Set(secp.ScalarZero())

	alpha, err := secp.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	defer alpha.Set(secp.ScalarZero())
	m, err := secp.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	defer m.Set(secp.ScalarZero())

	aBytes, err := secp.PointBytes(secp.ScalarMult(stmt.Generator, alpha))
	if err != nil {
		return nil, err
	}
	nPoint := secp.Add(secp.ScalarMult(stmt.Generator, m), secp.ScalarMult(stmt.ElGamalBase, alpha))
	nBytes, err := secp.PointBytes(nPoint)
	if err != nil {
		return nil, err
	}
	bBytes, err := secp.PointBytes(secp.ScalarMult(stmt.ResultBase, m))
	if err != nil {
		return nil, err
	}

	root, err := elogTranscript(state, stmt, aBytes, nBytes, bBytes)
	if err != nil {
		return nil, err
	}
	challenge, err := zkchallenge.DeriveCanonicalNonZeroSecp256k1(
		paillierChallengeDerivationLabel,
		root,
		challengeCounterLimit,
	)
	if err != nil {
		return nil, err
	}
	z := secp.ScalarAdd(alpha, secp.ScalarMul(challenge, lambda))
	u := secp.ScalarAdd(m, secp.ScalarMul(challenge, y))
	return &ElogProof{
		A:              aBytes,
		N:              nBytes,
		B:              bBytes,
		Z:              z.Bytes(),
		U:              u.Bytes(),
		TranscriptHash: root,
	}, nil
}

// VerifyElog verifies a Figure 23 Πelog proof bound to state.
func VerifyElog(state []byte, stmt ElogStatement, proof *ElogProof) error {
	if err := validateElogPublic(stmt); err != nil {
		return err
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	a, _ := secp.PointFromBytes(proof.A)
	n, _ := secp.PointFromBytes(proof.N)
	b, _ := secp.PointFromBytes(proof.B)
	z, _ := secp.ScalarFromBytesAllowZero(proof.Z)
	u, _ := secp.ScalarFromBytesAllowZero(proof.U)
	root, err := elogTranscript(state, stmt, proof.A, proof.N, proof.B)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, proof.TranscriptHash) {
		return errors.New("ElogProof: transcript hash mismatch")
	}
	challenge, err := zkchallenge.DeriveCanonicalNonZeroSecp256k1(
		paillierChallengeDerivationLabel,
		root,
		challengeCounterLimit,
	)
	if err != nil {
		return err
	}

	if !secp.Equal(secp.ScalarMult(stmt.Generator, z), secp.Add(a, secp.ScalarMult(stmt.LambdaCommitment, challenge))) {
		return errors.New("ElogProof: first equation failed")
	}
	leftSecond := secp.Add(secp.ScalarMult(stmt.Generator, u), secp.ScalarMult(stmt.ElGamalBase, z))
	rightSecond := secp.Add(n, secp.ScalarMult(stmt.ElGamalCommitment, challenge))
	if !secp.Equal(leftSecond, rightSecond) {
		return errors.New("ElogProof: second equation failed")
	}
	if !secp.Equal(secp.ScalarMult(stmt.ResultBase, u), secp.Add(b, secp.ScalarMult(stmt.ResultCommitment, challenge))) {
		return errors.New("ElogProof: third equation failed")
	}
	return nil
}

func validateElogPublic(stmt ElogStatement) error {
	for _, field := range []struct {
		name  string
		point *secp.Point
	}{
		{"Generator", stmt.Generator},
		{"LambdaCommitment", stmt.LambdaCommitment},
		{"ElGamalCommitment", stmt.ElGamalCommitment},
		{"ElGamalBase", stmt.ElGamalBase},
		{"ResultCommitment", stmt.ResultCommitment},
		{"ResultBase", stmt.ResultBase},
	} {
		if _, err := secp.PointBytes(field.point); err != nil {
			return fmt.Errorf("ElogProof: invalid statement %s: %w", field.name, err)
		}
	}
	return nil
}

func validateElogStatement(stmt ElogStatement, witness ElogWitness) error {
	if err := validateElogPublic(stmt); err != nil {
		return err
	}
	y, err := secpScalarFromSecretAllowZero(witness.Y, "y")
	if err != nil {
		return err
	}
	defer y.Set(secp.ScalarZero())
	lambda, err := secpScalarFromSecretAllowZero(witness.Lambda, "lambda")
	if err != nil {
		return err
	}
	defer lambda.Set(secp.ScalarZero())
	if !secp.Equal(secp.ScalarMult(stmt.Generator, lambda), stmt.LambdaCommitment) {
		return errors.New("ElogProof: lambda witness mismatch")
	}
	if !secp.Equal(secp.ScalarMult(stmt.ResultBase, y), stmt.ResultCommitment) {
		return errors.New("ElogProof: y witness mismatch")
	}
	wantM := secp.Add(secp.ScalarMult(stmt.Generator, y), secp.ScalarMult(stmt.ElGamalBase, lambda))
	if !secp.Equal(wantM, stmt.ElGamalCommitment) {
		return errors.New("ElogProof: ElGamal witness mismatch")
	}
	return nil
}

func elogTranscript(state []byte, stmt ElogStatement, a, n, b []byte) ([]byte, error) {
	t := NewTranscript("cggmp21-paillier-elog-proof-v1")
	t.AppendBytes("state", state)
	for _, field := range []struct {
		name  string
		point *secp.Point
	}{
		{"generator", stmt.Generator},
		{"lambda_commitment", stmt.LambdaCommitment},
		{"elgamal_commitment", stmt.ElGamalCommitment},
		{"elgamal_base", stmt.ElGamalBase},
		{"result_commitment", stmt.ResultCommitment},
		{"result_base", stmt.ResultBase},
	} {
		if err := t.AppendPoint(field.name, field.point); err != nil {
			return nil, err
		}
	}
	t.AppendBytes("A", a)
	t.AppendBytes("N", n)
	t.AppendBytes("B", b)
	return t.Sum(), nil
}

func secpScalarFromSecretAllowZero(value *secret.Scalar, name string) (secp.Scalar, error) {
	if value == nil || value.FixedLen() != secp.ScalarSize {
		return secp.Scalar{}, fmt.Errorf("invalid %s witness width", name)
	}
	encoded := value.FixedBytes()
	defer clear(encoded)
	scalar, err := secp.ScalarFromBytesAllowZero(encoded)
	if err != nil {
		return secp.Scalar{}, fmt.Errorf("invalid %s witness: %w", name, err)
	}
	return scalar, nil
}
