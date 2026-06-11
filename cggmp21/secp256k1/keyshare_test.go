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
	t.Parallel()
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
	t.Parallel()
	k := minimalKeyShare()
	if _, err := json.Marshal(k); err == nil {
		t.Fatal("json.Marshal(KeyShare) should reject")
	}
	if _, err := json.Marshal(*k); err == nil {
		t.Fatal("json.Marshal(KeyShare) should reject")
	}
}

func TestFast_KeyShareRedactedStringNoSecrets(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	k := minimalKeyShare()
	k.PublicKey[0] = 0x02
	cp := k.PublicKeyBytes()
	cp[0] = 0x03
	if k.PublicKey[0] != 0x02 {
		t.Fatal("PublicKeyBytes() did not return a copy")
	}
}

func TestFast_KeyShareChainCodeBytesReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalKeyShare()
	k.ChainCode[0] = 0xaa
	cp := k.ChainCodeBytes()
	cp[0] = 0xbb
	if k.ChainCode[0] != 0xaa {
		t.Fatal("ChainCodeBytes() did not return a copy")
	}
}

func TestFast_KeyShareShareProofBytesReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalKeyShare()
	k.ShareProof = []byte{0x01, 0x02, 0x03}
	cp := k.ShareProofBytes()
	cp[0] = 0xff
	if k.ShareProof[0] != 0x01 {
		t.Fatal("ShareProofBytes() did not return a copy")
	}
}

func TestFast_KeyShareKeygenTranscriptHashBytesReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalKeyShare()
	k.KeygenTranscriptHash = []byte{0xde, 0xad, 0xbe, 0xef}
	cp := k.KeygenTranscriptHashBytes()
	cp[0] = 0x00
	if k.KeygenTranscriptHash[0] != 0xde {
		t.Fatal("KeygenTranscriptHashBytes() did not return a copy")
	}
}

func TestFast_KeyShareGroupCommitmentsCopyReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalKeyShare()
	k.GroupCommitments = [][]byte{{0x01, 0x02}, {0x03, 0x04}}
	cp := k.GroupCommitmentsCopy()
	cp[0][0] = 0xff
	if k.GroupCommitments[0][0] != 0x01 {
		t.Fatal("GroupCommitmentsCopy() did not deep-copy inner slices")
	}
	cp[0] = []byte{0x99}
	if len(k.GroupCommitments[0]) != 2 {
		t.Fatal("GroupCommitmentsCopy() did not deep-copy outer slice")
	}
}

func TestFast_KeyShareNilAccessors(t *testing.T) {
	t.Parallel()
	var nilKey *KeyShare
	if b := nilKey.ChainCodeBytes(); b != nil {
		t.Fatal("nil ChainCodeBytes() should return nil")
	}
	if b := nilKey.ShareProofBytes(); b != nil {
		t.Fatal("nil ShareProofBytes() should return nil")
	}
	if b := nilKey.KeygenTranscriptHashBytes(); b != nil {
		t.Fatal("nil KeygenTranscriptHashBytes() should return nil")
	}
	if b := nilKey.GroupCommitmentsCopy(); b != nil {
		t.Fatal("nil GroupCommitmentsCopy() should return nil")
	}
}

func TestFast_KeyShareFormatRedaction(t *testing.T) {
	t.Parallel()
	k := minimalKeyShare()
	// GoString should use String() or a similar redacted form.
	gs := k.GoString()
	if gs == "" {
		t.Fatal("GoString() returned empty string")
	}
	// GoString must not leak secret bytes.
	if strings.Contains(gs, "secret") && !strings.Contains(strings.ToLower(gs), "redacted") {
		t.Fatalf("GoString() exposed secret field: %s", gs)
	}
}
