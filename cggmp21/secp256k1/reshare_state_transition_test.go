package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
)

func TestCGGMP21ReshareDealerMessagesFailureDoesNotCommitLocalDealerData(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	plan, err := NewResharePlan(ResharePlanOption{
		OldKey:        shares[1],
		SessionID:     sessionID,
		DealerParties: parties,
		NewParties:    parties,
		NewThreshold:  2,
		Limits:        testLimitsPtr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	session1, _, err := startCGGMP21ReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startCGGMP21ReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	var receiverMaterial tss.Envelope
	for _, env := range out2 {
		if env.PayloadType == payloadReshareReceiverMaterial {
			receiverMaterial = env
			break
		}
	}
	if receiverMaterial.Payload == nil {
		t.Fatal("missing receiver material from party 2")
	}
	payload, err := tss.DecodeBinaryValueWithLimits[reshareReceiverMaterialPayload](receiverMaterial.Payload, session1.limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := session1.verifyAndStoreReceiverMaterial(receiverMaterial, payload); err != nil {
		t.Fatal(err)
	}
	if !session1.allReshareReceiverMaterialReceived() {
		t.Fatal("test setup did not collect all receiver material")
	}

	session1.cfg.SessionID = tss.SessionID{}
	if _, err := session1.dealerMessages(); err == nil {
		t.Fatal("dealerMessages succeeded with invalid local session id")
	}
	dd := session1.dealerData[session1.selfID]
	if dd == nil {
		t.Fatal("missing local dealer slot")
	}
	if dd.commitments != nil {
		t.Fatal("failed dealerMessages committed local commitments")
	}
	if dd.share != nil {
		t.Fatal("failed dealerMessages committed local share")
	}
}
