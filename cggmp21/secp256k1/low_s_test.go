package secp256k1

import (
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestFast_VerifyDigestRejectsHighS(t *testing.T) {
	t.Parallel()

	secret := secp.ScalarFromUint64(7)
	public := secp.ScalarBaseMult(secret)
	publicBytes, err := secp.PointBytes(public)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("canonical low-S verification"))
	r, lowS, err := secp.SignECDSA(testutil.DeterministicReader(0x51), digest[:], secret)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(publicBytes, digest[:], &Signature{R: r.Bytes(), S: lowS.Bytes()}) {
		t.Fatal("low-S signature did not verify")
	}

	highS := secp.ScalarNeg(lowS)
	if secp.IsLowS(highS) {
		t.Fatal("malleated signature did not produce high-S")
	}
	if !secp.VerifyECDSA(public, digest[:], r, highS) {
		t.Fatal("high-S twin must remain mathematically valid ECDSA")
	}
	if VerifyDigest(publicBytes, digest[:], &Signature{R: r.Bytes(), S: highS.Bytes()}) {
		t.Fatal("VerifyDigest accepted high-S signature")
	}
}

func TestFast_VerifySignatureRejectsHighS(t *testing.T) {
	t.Parallel()

	secret := secp.ScalarFromUint64(11)
	publicBytes, err := secp.PointBytes(secp.ScalarBaseMult(secret))
	if err != nil {
		t.Fatal(err)
	}
	request := tss.SignRequest{
		Context: testPresignContext(),
		Message: []byte("canonical context-bound verification"),
	}
	contextHash := presignContextHash(request.Context)
	digest := signMessageDigest(contextHash, request.Context.MessageDomain, request.Message)
	r, lowS, err := secp.SignECDSA(testutil.DeterministicReader(0x52), digest, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(publicBytes, request, &Signature{R: r.Bytes(), S: lowS.Bytes()}) {
		t.Fatal("VerifySignature rejected low-S signature")
	}
	highS := secp.ScalarNeg(lowS)
	if VerifySignature(publicBytes, request, &Signature{R: r.Bytes(), S: highS.Bytes()}) {
		t.Fatal("VerifySignature accepted high-S signature")
	}
}

func TestFast_LowSNormalizationFlipsRecoveryParity(t *testing.T) {
	t.Parallel()

	pointBytes, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(9)))
	if err != nil {
		t.Fatal(err)
	}
	original, err := recoveryIDFromPresignR(pointBytes, false)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := recoveryIDFromPresignR(pointBytes, true)
	if err != nil {
		t.Fatal(err)
	}
	if original^normalized != 1 {
		t.Fatalf("normalization changed recovery ID by %d, want parity bit only", original^normalized)
	}
}
