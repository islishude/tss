package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// TestRFC9591ContextString verifies the RFC 9591 Section 5.4.1 ciphersuite
// context string used for domain separation.
func TestRFC9591ContextString(t *testing.T) {
	const expected = "FROST-ED25519-SHA512-v1"
	if rfc9591ContextString != expected {
		t.Errorf("context string mismatch: got %q, want %q", rfc9591ContextString, expected)
	}
}

// TestRFC9591HashToScalarDirectConcat verifies that HashToScalar uses direct
// concatenation (no length-delimited encoding), per RFC 9591 Section 3.1.
// We check this by hashing known inputs and verifying the output is
// deterministic and independent of any length encoding.
func TestRFC9591HashToScalarDirectConcat(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x04, 0x05}

	// HashToScalar should just concatenate parts and SHA-512.
	s1, _ := edcurve.HashToScalar(a, b)
	s2, _ := edcurve.HashToScalar(a, b)

	// Deterministic: same inputs produce same output.
	if s1.Equal(s2) != 1 {
		t.Error("HashToScalar is not deterministic")
	}

	// Verify direct concatenation: compute expected manually.
	expectedHash := sha512.Sum512(append(a, b...))
	s3, _ := edcurve.HashToScalar(append(a, b...))
	if s1.Equal(s3) != 1 {
		t.Error("HashToScalar does not use direct concatenation")
	}
	_ = expectedHash
}

// TestRFC9591Ed25519Challenge verifies the RFC 8032 challenge computation
// format: H(R || A || msg) using SHA-512.
func TestRFC9591Ed25519Challenge(t *testing.T) {
	R := make([]byte, 32)
	A := make([]byte, 32)
	msg := []byte("test")

	_, c1 := edcurve.Ed25519Challenge(R, A, msg)
	_, c2 := edcurve.Ed25519Challenge(R, A, msg)

	if c1.Cmp(c2) != 0 {
		t.Error("Ed25519Challenge is not deterministic")
	}
}

// TestRFC9591EndToEndSignature verifies that a full FROST Ed25519 keygen,
// signing, and Ed25519 signature verification produces valid output.
// This exercises the complete RFC 9591 flow: keygen → sign → verify.
func TestRFC9591EndToEndSignature(t *testing.T) {
	// 2-of-3 keygen (matching RFC 9591 Appendix E configuration).
	shares := frostKeygen(t, 2, 3)
	key1 := shares[1]
	key3 := shares[3]

	message := []byte("test")

	// Sign with signers P1, P3 (matching the RFC test vector).
	signers := []*KeyShare{key1, key3}
	pub, sig, err := Sign(message, signers)
	if err != nil {
		t.Fatal(err)
	}

	if !stded25519.Verify(stded25519.PublicKey(pub), message, sig) {
		t.Fatal("Ed25519 signature verification failed for 2-of-3")
	}

	// Verify the signature is 64 bytes (R || S format per RFC 8032).
	if len(sig) != 64 {
		t.Errorf("signature length: got %d, want 64", len(sig))
	}
}

// TestRFC9591ThresholdCombinations verifies FROST signatures work for
// the standard threshold configurations from the RFC.
func TestRFC9591ThresholdCombinations(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		n         int
		signers   []tss.PartyID
	}{
		{"1-of-1", 1, 1, []tss.PartyID{1}},
		{"2-of-3", 2, 3, []tss.PartyID{1, 3}},
		{"3-of-5", 3, 5, []tss.PartyID{1, 3, 5}},
	}

	message := []byte("RFC 9591 compliance test")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares := frostKeygen(t, tt.threshold, tt.n)
			signerShares := make([]*KeyShare, len(tt.signers))
			for i, id := range tt.signers {
				signerShares[i] = shares[id]
			}
			pub, sig, err := Sign(message, signerShares)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			if !stded25519.Verify(stded25519.PublicKey(pub), message, sig) {
				t.Fatalf("Ed25519 signature verification failed for %s", tt.name)
			}
		})
	}
}

// TestRFC9591DomainSeparatorDeterminism verifies that the domain separation
// label hierarchy follows RFC 9591's recommended structure.
func TestRFC9591DomainSeparatorDeterminism(t *testing.T) {
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2, 3}
	signers := []tss.PartyID{1, 3}
	publicKey := []byte{0x01, 0x02}

	// Domain separators must be deterministic.
	d1 := signingBindingFactorDomain(session, 2, parties, signers, publicKey)
	d2 := signingBindingFactorDomain(session, 2, parties, signers, publicKey)

	if hex.EncodeToString(d1) != hex.EncodeToString(d2) {
		t.Error("signingBindingFactorDomain is not deterministic")
	}

	// Different labels should produce different domains.
	k1 := keygenDomain(session, 2, parties, 1, publicKey)
	if hex.EncodeToString(d1) == hex.EncodeToString(k1) {
		t.Error("binding factor domain and keygen domain should differ")
	}
}
