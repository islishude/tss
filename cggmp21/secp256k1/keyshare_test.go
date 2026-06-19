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
	return &KeyShare{state: &keyShareState{
		party:                  1,
		threshold:              2,
		parties:                tss.NewPartySet(1, 2, 3),
		publicKey:              make([]byte, 33),
		chainCode:              make([]byte, 32),
		paillierProofDomain:    "keygen.modulus",
		paillierProofSessionID: tss.SessionID{},
	}}
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
	if _, ok := nilKey.PublicMetadata(); ok {
		t.Fatal("nil KeyShare.PublicMetadata() should report false")
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

func TestFast_KeySharePublicMetadataReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalKeyShare()
	k.state.publicKey[0] = 0x02
	k.state.chainCode[0] = 0xaa
	k.state.shareProof = []byte{0x01, 0x02, 0x03}
	k.state.keygenTranscriptHash = []byte{0xde, 0xad, 0xbe, 0xef}
	k.state.groupCommitments = [][]byte{{0x01, 0x02}, {0x03, 0x04}}

	meta := mustKeyShareMetadata(t, k)
	meta.PublicKey[0] = 0x03
	meta.ChainCode[0] = 0xbb
	meta.ShareProof[0] = 0xff
	meta.KeygenTranscriptHash[0] = 0x00
	meta.GroupCommitments[0][0] = 0xff
	meta.GroupCommitments[0] = []byte{0x99}

	if k.state.publicKey[0] != 0x02 {
		t.Fatal("PublicMetadata() did not deep-copy public key")
	}
	if k.state.chainCode[0] != 0xaa {
		t.Fatal("PublicMetadata() did not deep-copy chain code")
	}
	if k.state.shareProof[0] != 0x01 {
		t.Fatal("PublicMetadata() did not deep-copy share proof")
	}
	if k.state.keygenTranscriptHash[0] != 0xde {
		t.Fatal("PublicMetadata() did not deep-copy keygen transcript hash")
	}
	if k.state.groupCommitments[0][0] != 0x01 {
		t.Fatal("PublicMetadata() did not deep-copy group commitment bytes")
	}
	if len(k.state.groupCommitments[0]) != 2 {
		t.Fatal("PublicMetadata() did not deep-copy group commitment slice")
	}
}

func TestFast_KeyShareNilMetadata(t *testing.T) {
	t.Parallel()
	var nilKey *KeyShare
	if _, ok := nilKey.PublicMetadata(); ok {
		t.Fatal("nil PublicMetadata() should report false")
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
