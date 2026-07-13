package schnorr

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testvectors"
)

func TestGoldenProof(t *testing.T) {
	t.Parallel()

	// Construct a valid proof deterministically using known scalars.
	domain := []byte("golden-test-domain")

	sec := secp.ScalarOne()
	n := secp.ScalarFromUint64(2)
	public, err := secp.PointBytes(secp.ScalarBaseMult(sec))
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := secp.PointBytes(secp.ScalarBaseMult(n))
	if err != nil {
		t.Fatal(err)
	}
	challengeScalar, err := challenge(domain, public, commitment)
	if err != nil {
		t.Fatal(err)
	}
	response := secp.ScalarAdd(secp.ScalarMul(challengeScalar, sec), n)

	p := &Proof{Commitment: commitment, Response: response.Bytes()}

	// Round-trip: MarshalBinary → UnmarshalProof → MarshalBinary.
	raw, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/zk/SchnorrProof.golden", raw)

	decoded, err := tss.DecodeBinary[Proof](raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}

	// Reject trailing byte.
	if _, err := tss.DecodeBinary[Proof](append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenSchnorrMarshalBinaryRejectsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := (&Proof{}).MarshalBinary(); err == nil {
		t.Error("accepted nil fields")
	}

	validCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarOne()))
	if err != nil {
		t.Fatal(err)
	}
	// Valid commitment + malformed response (1 byte instead of 32).
	p := &Proof{Commitment: validCommitment, Response: []byte{0x00}}
	if _, err := p.MarshalBinary(); err == nil {
		t.Error("accepted malformed response")
	}

	// Malformed commitment.
	p2 := &Proof{Commitment: []byte{0x00}, Response: make([]byte, 32)}
	if _, err := p2.MarshalBinary(); err == nil {
		t.Error("accepted malformed commitment")
	}
}
