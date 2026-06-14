package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestCGGMP21ReshareProofDomainsBindLifecyclePlanHash(t *testing.T) {
	t.Parallel()

	var sessionID tss.SessionID
	sessionID[0] = 1
	config := tss.ThresholdConfig{
		Threshold: 2,
		Parties:   []tss.PartyID{1, 2},
		SessionID: sessionID,
	}
	planHash := bytes.Repeat([]byte{0x42}, 32)

	tests := []struct {
		name string
		got  []byte
		ctx  proofDomainContext
	}{
		{
			name: "paillier",
			got:  resharePaillierDomain(config, 1, []byte("paillier"), planHash),
			ctx: proofDomainContext{
				label:             domainLabelResharePaillier,
				sessionID:         sessionID,
				threshold:         2,
				parties:           []tss.PartyID{1, 2},
				sender:            1,
				paillierPublicKey: []byte("paillier"),
				lifecyclePlanHash: planHash,
			},
		},
		{
			name: "ring pedersen",
			got:  reshareRingPedersenDomain(config, 1, []byte("ring-pedersen"), planHash),
			ctx: proofDomainContext{
				label:              domainLabelReshareRingPedersen,
				sessionID:          sessionID,
				threshold:          2,
				parties:            []tss.PartyID{1, 2},
				sender:             1,
				ringPedersenParams: []byte("ring-pedersen"),
				lifecyclePlanHash:  planHash,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if want := proofDomain(tc.ctx); !bytes.Equal(tc.got, want) {
				t.Fatal("reshare proof domain omitted lifecycle plan hash")
			}
			tc.ctx.lifecyclePlanHash = nil
			if legacy := proofDomain(tc.ctx); bytes.Equal(tc.got, legacy) {
				t.Fatal("reshare proof domain matches legacy domain without lifecycle plan hash")
			}
		})
	}
}

func TestCGGMP21MTAResponseProofDomainsBindLabelAndLifecyclePlan(t *testing.T) {
	t.Parallel()

	key := &KeyShare{state: &keyShareState{
		threshold:            2,
		parties:              []tss.PartyID{1, 2},
		publicKey:            []byte("public-key"),
		keygenTranscriptHash: []byte("key-transcript"),
	}}
	var sessionID tss.SessionID
	sessionID[0] = 1
	args := struct {
		signers                    []tss.PartyID
		initiator, responder       tss.PartyID
		initiatorPaillierPublicKey []byte
		presignContextHash         []byte
		planHash                   []byte
	}{
		signers:                    []tss.PartyID{1, 2},
		initiator:                  1,
		responder:                  2,
		initiatorPaillierPublicKey: []byte("paillier"),
		presignContextHash:         []byte("presign-context"),
		planHash:                   bytes.Repeat([]byte{0x42}, 32),
	}

	delta := mtaDeltaResponseDomain(key, sessionID, args.signers, args.initiator, args.responder, args.initiatorPaillierPublicKey, args.presignContextHash, args.planHash)
	sigma := mtaSigmaResponseDomain(key, sessionID, args.signers, args.initiator, args.responder, args.initiatorPaillierPublicKey, args.presignContextHash, args.planHash)
	if bytes.Equal(delta, sigma) {
		t.Fatal("MtA delta and sigma response domains must differ")
	}
	wrongPlanHash := bytes.Clone(args.planHash)
	wrongPlanHash[0] ^= 1
	wrongPlan := mtaDeltaResponseDomain(key, sessionID, args.signers, args.initiator, args.responder, args.initiatorPaillierPublicKey, args.presignContextHash, wrongPlanHash)
	if bytes.Equal(delta, wrongPlan) {
		t.Fatal("MtA response domain must bind the lifecycle plan hash")
	}
}
