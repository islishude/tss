package ed25519

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

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
	publicKey := append([]byte(nil), share.state.publicKey...)
	share.Destroy()
	if !testutil.IsZeroBytes(share.state.secret.FixedBytes()) {
		t.Fatal("key share secret was not cleared")
	}
	if !bytes.Equal(share.state.publicKey, publicKey) {
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
		Parties:   []tss.PartyID{1},
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
	if strings.Contains(formatted, string(share.state.secret.FixedBytes())) {
		t.Fatal("formatted key share exposed secret scalar bytes")
	}
	if strings.Contains(formattedValue, string(share.state.secret.FixedBytes())) {
		t.Fatal("formatted key share value exposed secret scalar bytes")
	}
	if keygen.keyShare == nil {
		t.Fatal("missing session-retained key share")
	}
	internalPublic := append([]byte(nil), keygen.keyShare.state.publicKey...)
	internalSecret := keygen.keyShare.state.secret.FixedBytes()
	share.state.publicKey[0] ^= 1
	share.state.secret.Destroy()
	if !bytes.Equal(keygen.keyShare.state.publicKey, internalPublic) {
		t.Fatal("mutating returned key share changed session public key")
	}
	if !bytes.Equal(keygen.keyShare.state.secret.FixedBytes(), internalSecret) {
		t.Fatal("mutating returned key share changed session secret scalar")
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
		Parties:   []tss.PartyID{1},
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
	publicKey := append([]byte(nil), share.state.publicKey...)
	keygen.Destroy()
	if len(keygen.shares) != 0 {
		t.Fatal("keygen share map was not cleared")
	}
	if keygen.ownPoly != nil {
		t.Fatal("keygen polynomial was not released")
	}
	if keygen.keyShare == nil || !testutil.IsZeroBytes(keygen.keyShare.state.secret.FixedBytes()) {
		t.Fatal("completed key share secret was not cleared")
	}
	if !bytes.Equal(share.state.publicKey, publicKey) {
		t.Fatal("keygen public metadata changed")
	}

	shares := frostKeygen(t, 2, 2)
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign, _, err := startFROSTSign(shares[1], signID, []tss.PartyID{1, 2}, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sign.dNonce) == 0 || len(sign.eNonce) == 0 {
		t.Fatal("sign session did not retain expected local nonce bytes before round 2")
	}
	_, out2, err := startFROSTSign(shares[2], signID, []tss.PartyID{1, 2}, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	env := out2[0]
	env.Security.Authenticated = true
	env.Security.AuthenticatedParty = env.From
	if _, err := sign.HandleSignMessage(env); err != nil {
		t.Fatal(err)
	}
	if sign.dNonce != nil || sign.eNonce != nil {
		t.Fatal("signing nonces were not released after partial generation")
	}
	if len(sign.partials) == 0 {
		t.Fatal("sign session did not retain expected local partial material")
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
		Parties:   []tss.PartyID{1},
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
	if len(keygen.shares) != 0 {
		t.Fatal("completed keygen retained received share scalars")
	}
	if keygen.ownPoly != nil {
		t.Fatal("completed keygen retained local polynomial")
	}
	if keygen.ownMessages != nil {
		t.Fatal("completed keygen retained secret outbound messages")
	}
	if keygen.chainCodes != nil {
		t.Fatal("completed keygen retained chain codes")
	}
}

func TestFROSTTestLimitsAllowsOneOfOne(t *testing.T) {
	t.Parallel()
	limits := TestLimits()
	if !limits.Threshold.AllowOneOfOne {
		t.Fatal("TestLimits must allow 1-of-1")
	}
	if limits.Threshold.MinProductionThreshold != 1 {
		t.Fatal("TestLimits MinProductionThreshold must be 1")
	}
	if !limits.Threshold.AllowOversizedSignerSet {
		t.Fatal("TestLimits must allow oversized signer sets")
	}
}

func TestFROSTThresholdLimitsIsAccessor(t *testing.T) {
	t.Parallel()
	// Note: DefaultLimits() returns TestLimits() in tests because TestMain sets
	// testDefaultLimits. Test the accessor regardless of which limits are active.
	limits := TestLimits()
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
	limits := TestLimits()
	if limits.Curve.MaxScalarBytes != 32 {
		t.Fatalf("MaxScalarBytes = %d, want 32", limits.Curve.MaxScalarBytes)
	}
	if limits.Curve.MaxPointBytes != 32 {
		t.Fatalf("MaxPointBytes = %d, want 32", limits.Curve.MaxPointBytes)
	}
	if limits.Threshold.MaxParties > 8 {
		t.Fatalf("TestLimits MaxParties = %d, want <= 8", limits.Threshold.MaxParties)
	}
	if limits.State.MaxSerializedKeyShareBytes <= 0 {
		t.Fatal("MaxSerializedKeyShareBytes must be positive")
	}
	if limits.Payload.MaxMessageBytes <= 0 {
		t.Fatal("MaxMessageBytes must be positive")
	}
}
