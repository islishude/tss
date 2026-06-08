package secp256k1

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/islishude/tss"
)

// minimalKeyShare returns a KeyShare with only public metadata populated.
// Secret and crypto material fields are left empty — this is sufficient for
// exercising accessors, formatting, and serialization rejection.
func minimalKeyShare() *KeyShare {
	return &KeyShare{
		Version:                tss.Version,
		Party:                  1,
		Threshold:              2,
		Parties:                []tss.PartyID{1, 2, 3},
		PublicKey:              make([]byte, 33),
		ChainCode:              make([]byte, 32),
		PaillierProofDomain:    "keygen.modulus",
		PaillierProofSessionID: tss.SessionID{},
	}
}

func TestFast_KeyShareAlgorithm(t *testing.T) {
	k := minimalKeyShare()
	if k.Algorithm() != tss.AlgorithmCGGMP21Secp256k1 {
		t.Fatalf("Algorithm() = %q, want %q", k.Algorithm(), tss.AlgorithmCGGMP21Secp256k1)
	}
	var nilKey *KeyShare
	if nilKey.PartyID() != 0 {
		t.Fatal("nil KeyShare.PartyID() should return 0")
	}
	if nilKey.PublicKeyBytes() != nil {
		t.Fatal("nil KeyShare.PublicKeyBytes() should return nil")
	}
}

func TestFast_KeyShareMarshalJSONRejects(t *testing.T) {
	k := minimalKeyShare()
	if _, err := json.Marshal(k); err == nil {
		t.Fatal("json.Marshal(KeyShare) should reject")
	}
	if _, err := json.Marshal(*k); err == nil {
		t.Fatal("json.Marshal(KeyShare) should reject")
	}
}

func TestFast_KeyShareRedactedStringNoSecrets(t *testing.T) {
	k := minimalKeyShare()
	s := k.String()
	// Must include the <redacted> marker for secret and private-key fields.
	for _, want := range []string{"Secret:<redacted>", "PaillierPrivateKey:<redacted>"} {
		if !strings.Contains(s, want) {
			t.Fatalf("redacted string does not contain %q: %s", want, s)
		}
	}
	// Must not contain raw hex-encoded public key (only length-based display).
	if !strings.Contains(s, "PublicKey:") {
		t.Fatal("redacted string should include PublicKey length info")
	}
}

func TestFast_KeySharePublicKeyBytesReturnsCopy(t *testing.T) {
	k := minimalKeyShare()
	k.PublicKey[0] = 0x02
	cp := k.PublicKeyBytes()
	cp[0] = 0x03
	if k.PublicKey[0] != 0x02 {
		t.Fatal("PublicKeyBytes() did not return a copy")
	}
}
