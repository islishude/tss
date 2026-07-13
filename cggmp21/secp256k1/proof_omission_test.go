//go:build integration

package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
)

func decodedKeyShareForProofMutation(t *testing.T) *KeyShare {
	t.Helper()
	shares := CachedKeygenShares(t, 2, 2)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := tss.DecodeBinary[KeyShare](raw)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestKeyShareValidateRejectsMissingSchnorrProof ensures a persisted epoch
// cannot omit the proof that its local secret opens the advertised public
// share.
func TestKeyShareValidateRejectsMissingSchnorrProof(t *testing.T) {
	t.Parallel()
	decoded := decodedKeyShareForProofMutation(t)
	decoded.state.ShareProof = nil
	if _, err := decoded.MarshalBinary(); err == nil {
		t.Fatal("KeyShare with missing ShareProof marshaled successfully")
	}
}

// TestKeyShareValidateRejectsMissingPaillierProof ensures every persisted
// Figure 7 auxiliary key retains its public Pi-mod proof.
func TestKeyShareValidateRejectsMissingPaillierProof(t *testing.T) {
	t.Parallel()
	decoded := decodedKeyShareForProofMutation(t)
	data := decoded.state.PartyData[decoded.state.Party]
	data.PaillierProof = nil
	decoded.state.PartyData[decoded.state.Party] = data
	if _, err := decoded.MarshalBinary(); err == nil {
		t.Fatal("KeyShare with missing PaillierProof marshaled successfully")
	}
}

// TestKeyShareValidateRejectsMissingRingPedersenProof ensures every persisted
// Figure 7 verifier setup retains its public Pi-prm proof.
func TestKeyShareValidateRejectsMissingRingPedersenProof(t *testing.T) {
	t.Parallel()
	decoded := decodedKeyShareForProofMutation(t)
	data := decoded.state.PartyData[decoded.state.Party]
	data.RingPedersenProof = nil
	decoded.state.PartyData[decoded.state.Party] = data
	if _, err := decoded.MarshalBinary(); err == nil {
		t.Fatal("KeyShare with missing RingPedersenProof marshaled successfully")
	}
}
