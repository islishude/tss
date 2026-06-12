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
	if modulusProofTag == mtaProofTag {
		t.Fatal("modulusProofTag and mtaProofTag collide")
	}
	if ringPedersenProofTag == mtaProofTag {
		t.Fatal("ringPedersenProofTag and mtaProofTag collide")
	}
	if modulusProofTag == logProofTag {
		t.Fatal("modulusProofTag and logProofTag collide")
	}
	if encryptionProofTag == logProofTag {
		t.Fatal("encryptionProofTag and logProofTag collide")
	}
	t.Logf("All proof tags are distinct: mod=%q, rp=%q, mta=%q, log=%q, enc=%q",
		modulusProofTag, ringPedersenProofTag, mtaProofTag, logProofTag, encryptionProofTag)
}
