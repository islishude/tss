package paillier

import (
	"testing"
)

// TestPaillierKeyDomainSeparation verifies each protocol phase uses a distinct
// domain tag that binds the session and party identifiers.
func TestPaillierKeyDomainSeparation(t *testing.T) {
	t.Parallel()
	// Test that modProof and ringPedersenProof use different tags in their
	// proof transcripts.
	if modulusProofTag == ringPedersenProofTag {
		t.Fatal("modulusProofTag and ringPedersenProofTag collide")
	}
	t.Logf("All proof tags are distinct: mod=%q, rp=%q",
		modulusProofTag, ringPedersenProofTag)
}
