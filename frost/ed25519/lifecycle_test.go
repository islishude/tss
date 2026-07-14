package ed25519

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func assertFROSTDerivationPathCleared(t *testing.T, name string, path tss.DerivationPath) {
	t.Helper()
	for i, v := range path {
		if v != 0 {
			t.Fatalf("%s element %d not cleared: %d", name, i, v)
		}
	}
}

func TestFROSTKeyShareJSONAndDestroy(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 1, 1)
	share := shares[1]
	if _, err := json.Marshal(share); err == nil {
		t.Fatal("pointer key share JSON encoded")
	}
	if _, err := json.Marshal(*share); err == nil {
		t.Fatal("value key share JSON encoded")
	}
	publicKey := share.state.PublicKey.Bytes()
	share.Destroy()
	if !testutil.IsZeroBytes(share.state.Secret.FixedBytes()) {
		t.Fatal("key share secret was not cleared")
	}
	if !bytes.Equal(share.state.PublicKey.Bytes(), publicKey) {
		t.Fatal("public key metadata changed")
	}
}

func TestFROSTKeyShareRedactsFormattingAndReturnsCopy(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygen, _, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   tss.NewPartySet(1),
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	share, ok := keygen.KeyShare()
	if !ok {
		t.Fatal("keygen did not complete")
	}
	formatted := fmt.Sprintf("%#v", share)
	formattedValue := fmt.Sprintf("%#v", *share)
	if !strings.Contains(formatted, "Secret:<redacted>") {
		t.Fatalf("formatted key share did not mark secret field redacted: %s", formatted)
	}
	if !strings.Contains(formattedValue, "Secret:<redacted>") {
		t.Fatalf("formatted key share value did not mark secret field redacted: %s", formattedValue)
	}
	if strings.Contains(formatted, string(share.state.Secret.FixedBytes())) {
		t.Fatal("formatted key share exposed secret scalar bytes")
	}
	if strings.Contains(formattedValue, string(share.state.Secret.FixedBytes())) {
		t.Fatal("formatted key share value exposed secret scalar bytes")
	}
	if keygen.keyShare == nil {
		t.Fatal("missing session-retained key share")
	}
	internalPublic := keygen.keyShare.state.PublicKey.Bytes()
	internalSecret := keygen.keyShare.state.Secret.FixedBytes()
	share.state.PublicKey.p.Set(fed.NewIdentityPoint())
	share.state.Secret.Destroy()
	if !bytes.Equal(keygen.keyShare.state.PublicKey.Bytes(), internalPublic) {
		t.Fatal("mutating returned key share changed session public key")
	}
	if !bytes.Equal(keygen.keyShare.state.Secret.FixedBytes(), internalSecret) {
		t.Fatal("mutating returned key share changed session secret scalar")
	}
}

func TestFROSTSessionCompletedStatusDoesNotCloneOutputs(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	share := shares[1]
	defer share.Destroy()

	keygen := &KeygenSession{completed: true, keyShare: share}
	reshare := &ReshareSession{completed: true, newShare: share}
	sign := &SignSession{completed: true, signature: bytes.Repeat([]byte{0x42}, 64)}

	tests := []struct {
		name      string
		completed func() bool
	}{
		{name: "keygen", completed: keygen.Completed},
		{name: "reshare holder", completed: reshare.Completed},
		{name: "sign", completed: sign.Completed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var completed bool
			allocations := testing.AllocsPerRun(100, func() {
				completed = tc.completed()
			})
			if !completed {
				t.Fatal("completed session reported incomplete")
			}
			if allocations != 0 {
				t.Fatalf("Completed allocated %.2f objects per status query", allocations)
			}
		})
	}

	dealerOnly := &ReshareSession{completed: true}
	if !dealerOnly.Completed() {
		t.Fatal("completed dealer-only reshare reported incomplete without a new share")
	}
}

func TestFROSTSessionDestroyClearsLocalSecrets(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygen, _, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   tss.NewPartySet(1),
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	share, ok := keygen.KeyShare()
	if !ok {
		t.Fatal("keygen did not complete")
	}
	publicKey := share.state.PublicKey.Bytes()
	keygen.Destroy()
	for _, slot := range keygen.round1.slots {
		if slot.share != nil {
			t.Fatal("keygen share map was not cleared")
		}
	}
	if keygen.local != nil {
		t.Fatal("keygen local material was not released")
	}
	if keygen.keyShare == nil || !testutil.IsZeroBytes(keygen.keyShare.state.Secret.FixedBytes()) {
		t.Fatal("completed key share secret was not cleared")
	}
	if !bytes.Equal(share.state.PublicKey.Bytes(), publicKey) {
		t.Fatal("keygen public metadata changed")
	}

	shares := frostKeygen(t, 2, 2)
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign, _, err := startFROSTSign(shares[1], signID, tss.NewPartySet(1, 2), []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	if sign.dNonce == nil || sign.eNonce == nil {
		t.Fatal("sign session did not retain expected local nonces before round 2")
	}
	_, out2, err := startFROSTSign(shares[2], signID, tss.NewPartySet(1, 2), []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	env := out2[0]
	if _, err := sign.Handle(testutil.DeliverEnvelope(env)); err != nil {
		t.Fatal(err)
	}
	if sign.dNonce != nil || sign.eNonce != nil {
		t.Fatal("signing nonces were not released after partial generation")
	}
	if len(sign.partials) == 0 {
		t.Fatal("sign session did not retain expected local partial material")
	}
	childPublicKey := []byte{0x01, 0x02, 0x03}
	childChainCode := []byte{0x04, 0x05, 0x06}
	requestedPath := tss.DerivationPath{1, 2}
	resolvedPath := tss.DerivationPath{1, 2}
	additiveShift := []byte{0x07, 0x08, 0x09}
	sign.derivation = &tss.DerivationResult{
		Scheme:         tss.DerivationSchemeEd25519KhovratovichLaw,
		ChildPublicKey: childPublicKey,
		ChildChainCode: childChainCode,
		RequestedPath:  requestedPath,
		ResolvedPath:   resolvedPath,
		AdditiveShift:  additiveShift,
	}
	sign.Destroy()
	if sign.dNonce != nil || sign.eNonce != nil {
		t.Fatal("signing nonces were not released")
	}
	if len(sign.partials) != 0 {
		t.Fatal("signing partials were not cleared")
	}
	if sign.message != nil {
		t.Fatal("signed message copy was not released")
	}
	if sign.derivation != nil {
		t.Fatal("derivation result was not released")
	}
	if sign.commitments != nil || sign.commitMessage.Payload != nil {
		t.Fatal("destroyed sign session retained nonce commitment state")
	}
	testutil.AssertBytesCleared(t, childPublicKey)
	testutil.AssertBytesCleared(t, childChainCode)
	testutil.AssertBytesCleared(t, additiveShift)
	assertFROSTDerivationPathCleared(t, "requested path", requestedPath)
	assertFROSTDerivationPathCleared(t, "resolved path", resolvedPath)
	if len(sign.signers) != 2 || sign.signers[0] != 1 || sign.signers[1] != 2 {
		t.Fatal("signer metadata changed")
	}
}

func TestFROSTKeygenCompletionClearsIntermediateSecrets(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygen, out, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   tss.NewPartySet(1),
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || len(out[0].Payload) == 0 {
		t.Fatal("keygen completion cleared caller-owned outbound payload")
	}
	if share, ok := keygen.KeyShare(); !ok || share == nil {
		t.Fatal("single-party keygen did not complete")
	}
	for _, slot := range keygen.round1.slots {
		if slot.share != nil {
			t.Fatal("completed keygen retained received share scalars")
		}
	}
	if keygen.local != nil {
		t.Fatal("completed keygen retained local material")
	}
	for _, chainCode := range keygen.confirmations.chainCodes {
		if chainCode != nil {
			t.Fatal("completed keygen retained chain codes")
		}
	}
}

func TestFROSTExplicitLimitsAllowOneOfOne(t *testing.T) {
	t.Parallel()
	limits := testLimits()
	if !limits.Threshold.AllowOneOfOne {
		t.Fatal("test limits must allow 1-of-1")
	}
	if limits.Threshold.MinProductionThreshold != 1 {
		t.Fatal("test limits MinProductionThreshold must be 1")
	}
	if !limits.Threshold.AllowOversizedSignerSet {
		t.Fatal("test limits must allow oversized signer sets")
	}
}

func TestFROSTThresholdLimitsIsAccessor(t *testing.T) {
	t.Parallel()
	limits := testLimits()
	tl := limits.ThresholdLimits()
	if tl.MaxParties != limits.Threshold.MaxParties {
		t.Fatal("ThresholdLimits() does not match Threshold field")
	}
	if tl.AllowOneOfOne != limits.Threshold.AllowOneOfOne {
		t.Fatal("ThresholdLimits() AllowOneOfOne mismatch")
	}
}

func TestFROSTLimitsFieldBounds(t *testing.T) {
	t.Parallel()
	limits := testLimits()
	if limits.Curve.MaxScalarBytes != 32 {
		t.Fatalf("MaxScalarBytes = %d, want 32", limits.Curve.MaxScalarBytes)
	}
	if limits.Curve.MaxPointBytes != 32 {
		t.Fatalf("MaxPointBytes = %d, want 32", limits.Curve.MaxPointBytes)
	}
	if limits.Threshold.MaxParties > 8 {
		t.Fatalf("test limits MaxParties = %d, want <= 8", limits.Threshold.MaxParties)
	}
	if limits.State.MaxSerializedKeyShareBytes <= 0 {
		t.Fatal("MaxSerializedKeyShareBytes must be positive")
	}
	if limits.Payload.MaxMessageBytes <= 0 {
		t.Fatal("MaxMessageBytes must be positive")
	}
}
