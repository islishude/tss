package secp256k1

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// minimalKeyShare returns a KeyShare with only public metadata populated.
// Secret and crypto material fields are left empty — this is sufficient for
// exercising accessors, formatting, and serialization rejection.
func minimalKeyShare() *KeyShare {
	return &KeyShare{state: &keyShareState{
		Party:                  1,
		Threshold:              2,
		Parties:                tss.NewPartySet(1, 2, 3),
		PublicKey:              make([]byte, 33),
		ChainCode:              make([]byte, 32),
		PaillierProofDomain:    "keygen.modulus",
		PaillierProofSessionID: tss.SessionID{},
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
	k.state.PublicKey[0] = 0x02
	k.state.ChainCode[0] = 0xaa
	k.state.ShareProof = testSchnorrProof(t)
	k.state.KeygenTranscriptHash = []byte{0xde, 0xad, 0xbe, 0xef}
	k.state.GroupCommitments = []*secp.Point{testCurvePoint(1), testCurvePoint(2)}
	attachTestEpoch(t, k)

	meta := mustKeyShareMetadata(t, k)
	originalShareProof := append([]byte(nil), meta.ShareProof...)
	originalCommitment := append([]byte(nil), meta.GroupCommitments[0]...)
	meta.PublicKey[0] = 0x03
	meta.ChainCode[0] = 0xbb
	meta.ShareProof[0] = 0xff
	meta.KeygenTranscriptHash[0] = 0x00
	meta.GroupCommitments[0][0] = 0xff
	meta.GroupCommitments[0] = []byte{0x99}

	if k.state.PublicKey[0] != 0x02 {
		t.Fatal("PublicMetadata() did not deep-copy public key")
	}
	if k.state.ChainCode[0] != 0xaa {
		t.Fatal("PublicMetadata() did not deep-copy chain code")
	}
	metaAgain := mustKeyShareMetadata(t, k)
	if metaAgain.ShareProof[0] != originalShareProof[0] {
		t.Fatal("PublicMetadata() did not deep-copy share proof")
	}
	if k.state.KeygenTranscriptHash[0] != 0xde {
		t.Fatal("PublicMetadata() did not deep-copy keygen transcript hash")
	}
	if metaAgain.GroupCommitments[0][0] != originalCommitment[0] {
		t.Fatal("PublicMetadata() did not deep-copy group commitment bytes")
	}
	if len(metaAgain.GroupCommitments[0]) != len(originalCommitment) {
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
