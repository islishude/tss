package schnorr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

func TestGoldenProof(t *testing.T) {
	// Construct a valid proof deterministically using known scalars.
	secret := big.NewInt(1)
	nonce := big.NewInt(2)
	domain := []byte("golden-test-domain")

	sec := secp.ScalarFromBigInt(secret)
	n := secp.ScalarFromBigInt(nonce)
	public, err := secp.PointBytes(secp.ScalarBaseMult(sec))
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := secp.PointBytes(secp.ScalarBaseMult(n))
	if err != nil {
		t.Fatal(err)
	}
	// Compute challenge: SHA256(challengeLabel || domain || public || commitment) mod order.
	h := sha256.New()
	wire.WriteHashPart(h, []byte(schnorrChallengeLabel))
	wire.WriteHashPart(h, domain)
	wire.WriteHashPart(h, public)
	wire.WriteHashPart(h, commitment)
	challenge := new(big.Int).SetBytes(h.Sum(nil))
	challenge.Mod(challenge, secp.Order())
	challengeScalar := secp.ScalarFromBigInt(challenge)
	response := secp.ScalarAdd(secp.ScalarMul(challengeScalar, sec), n)

	p := &Proof{Commitment: commitment, Response: response.Bytes()}

	// Round-trip: MarshalBinary → UnmarshalProof → MarshalBinary.
	raw, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "Proof.golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}

	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		t.Fatalf("reading golden file %s: %v (run with UPDATE_GOLDEN=1 to generate)", golden, err)
	}
	gotHex := hex.EncodeToString(raw)
	if gotHex != string(bytes.TrimSpace(wantHex)) {
		t.Errorf("golden mismatch:\n  got:  %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex)))
	}

	decoded, err := UnmarshalProof(raw)
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
	if _, err := UnmarshalProof(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenSchnorrMarshalBinaryRejectsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := (&Proof{}).MarshalBinary(); err == nil {
		t.Error("accepted nil fields")
	}

	validCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
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
