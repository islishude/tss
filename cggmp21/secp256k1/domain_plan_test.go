package secp256k1

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func testDomainPaillierKey() *pai.PublicKey {
	n := big.NewInt(65)
	return &pai.PublicKey{
		N:        n,
		G:        new(big.Int).Add(n, big.NewInt(1)),
		NSquared: new(big.Int).Mul(n, n),
	}
}

func testDomainRingPedersenParams() *zkpai.RingPedersenParams {
	return &zkpai.RingPedersenParams{
		N: big.NewInt(65),
		S: big.NewInt(2),
		T: big.NewInt(4),
	}
}

func TestCGGMP21ReshareProofDomainsBindLifecyclePlanHash(t *testing.T) {
	t.Parallel()

	var sessionID tss.SessionID
	sessionID[0] = 1
	config := tss.ThresholdConfig{
		Threshold: 2,
		Parties:   tss.NewPartySet(1, 2),
		SessionID: sessionID,
	}
	planHash := bytes.Repeat([]byte{0x42}, 32)

	tests := []struct {
		name   string
		domain func([]byte) ([]byte, error)
	}{
		{name: "paillier", domain: func(hash []byte) ([]byte, error) {
			return resharePaillierDomain(config, 1, testDomainPaillierKey(), hash, testLimits())
		}},
		{name: "ring pedersen", domain: func(hash []byte) ([]byte, error) {
			return reshareRingPedersenDomain(config, 1, testDomainRingPedersenParams(), hash, testLimits())
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.domain(planHash)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 {
				t.Fatal("empty proof domain")
			}
			for _, invalid := range [][]byte{nil, bytes.Repeat([]byte{0x42}, 31), bytes.Repeat([]byte{0x42}, 33)} {
				if _, err := tc.domain(invalid); err == nil {
					t.Fatalf("accepted lifecycle plan hash length %d", len(invalid))
				}
			}
		})
	}
}

func TestCGGMP21MTAResponseProofDomainsBindLabelAndLifecyclePlan(t *testing.T) {
	t.Parallel()

	key := &KeyShare{state: &keyShareState{
		Threshold:            2,
		Parties:              tss.NewPartySet(1, 2),
		PublicKey:            []byte("public-key"),
		KeygenTranscriptHash: bytes.Repeat([]byte{0x24}, 32),
		PlanHash:             bytes.Repeat([]byte{0x25}, 32),
	}}
	var sessionID tss.SessionID
	sessionID[0] = 1
	args := struct {
		signers                    tss.PartySet
		initiator, responder       tss.PartyID
		initiatorPaillierPublicKey *pai.PublicKey
		presignContextHash         []byte
		planHash                   []byte
	}{
		signers:                    tss.NewPartySet(1, 2),
		initiator:                  1,
		responder:                  2,
		initiatorPaillierPublicKey: testDomainPaillierKey(),
		presignContextHash:         bytes.Repeat([]byte{0x41}, 32),
		planHash:                   bytes.Repeat([]byte{0x42}, 32),
	}

	delta, err := mtaDeltaResponseDomain(key, sessionID, args.signers, args.initiator, args.responder, args.initiatorPaillierPublicKey, args.presignContextHash, args.planHash, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	sigma, err := mtaSigmaResponseDomain(key, sessionID, args.signers, args.initiator, args.responder, args.initiatorPaillierPublicKey, args.presignContextHash, args.planHash, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(delta, sigma) {
		t.Fatal("MtA delta and sigma response domains must differ")
	}
	wrongPlanHash := bytes.Clone(args.planHash)
	wrongPlanHash[0] ^= 1
	wrongPlan, err := mtaDeltaResponseDomain(key, sessionID, args.signers, args.initiator, args.responder, args.initiatorPaillierPublicKey, args.presignContextHash, wrongPlanHash, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(delta, wrongPlan) {
		t.Fatal("MtA response domain must bind the lifecycle plan hash")
	}
	for _, tc := range []struct {
		name        string
		contextHash []byte
		planHash    []byte
	}{
		{name: "missing context", contextHash: nil, planHash: args.planHash},
		{name: "short context", contextHash: bytes.Repeat([]byte{1}, 31), planHash: args.planHash},
		{name: "missing plan", contextHash: args.presignContextHash, planHash: nil},
		{name: "short plan", contextHash: args.presignContextHash, planHash: bytes.Repeat([]byte{1}, 31)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mtaDeltaResponseDomain(key, sessionID, args.signers, args.initiator, args.responder, args.initiatorPaillierPublicKey, tc.contextHash, tc.planHash, testLimits()); err == nil {
				t.Fatal("accepted invalid MtA proof-domain binding")
			}
		})
	}
}
