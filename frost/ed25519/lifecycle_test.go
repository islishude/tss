package ed25519

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/islishude/tss"
)

func TestFROSTKeyShareJSONAndDestroy(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	share := shares[1]
	if _, err := json.Marshal(share); err == nil {
		t.Fatal("pointer key share JSON encoded")
	}
	if _, err := json.Marshal(*share); err == nil {
		t.Fatal("value key share JSON encoded")
	}
	publicKey := append([]byte(nil), share.PublicKey...)
	share.Destroy()
	if !allZeroBytes(share.secret) {
		t.Fatal("key share secret was not cleared")
	}
	if !bytes.Equal(share.PublicKey, publicKey) {
		t.Fatal("public key metadata changed")
	}
}

func TestFROSTKeyShareRedactsFormattingAndReturnsCopy(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygen, _, err := StartKeygen(tss.ThresholdConfig{
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
	if strings.Contains(formatted, string(share.secret)) {
		t.Fatal("formatted key share exposed secret scalar bytes")
	}
	if strings.Contains(formattedValue, string(share.secret)) {
		t.Fatal("formatted key share value exposed secret scalar bytes")
	}
	if keygen.keyShare == nil {
		t.Fatal("missing session-retained key share")
	}
	internalPublic := append([]byte(nil), keygen.keyShare.PublicKey...)
	internalSecret := append([]byte(nil), keygen.keyShare.secret...)
	share.PublicKey[0] ^= 1
	share.secret[0] ^= 1
	if !bytes.Equal(keygen.keyShare.PublicKey, internalPublic) {
		t.Fatal("mutating returned key share changed session public key")
	}
	if !bytes.Equal(keygen.keyShare.secret, internalSecret) {
		t.Fatal("mutating returned key share changed session secret scalar")
	}
}

func TestFROSTSessionDestroyClearsLocalSecrets(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygen, _, err := StartKeygen(tss.ThresholdConfig{
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
	publicKey := append([]byte(nil), share.PublicKey...)
	keygen.Destroy()
	if len(keygen.shares) != 0 {
		t.Fatal("keygen share map was not cleared")
	}
	if keygen.ownPoly != nil {
		t.Fatal("keygen polynomial was not released")
	}
	if keygen.keyShare == nil || !allZeroBytes(keygen.keyShare.secret) {
		t.Fatal("completed key share secret was not cleared")
	}
	if !bytes.Equal(share.PublicKey, publicKey) {
		t.Fatal("keygen public metadata changed")
	}

	shares := frostKeygen(t, 1, 1)
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign, _, err := StartSign(shares[1], signID, []tss.PartyID{1}, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	if sign.d == nil || sign.e == nil || len(sign.partials) == 0 {
		t.Fatal("sign session did not retain expected local secret material")
	}
	sign.Destroy()
	if sign.d != nil || sign.e != nil {
		t.Fatal("signing nonces were not released")
	}
	if len(sign.partials) != 0 {
		t.Fatal("signing partials were not cleared")
	}
	if sign.message != nil {
		t.Fatal("signed message copy was not released")
	}
	if len(sign.signers) != 1 || sign.signers[0] != 1 {
		t.Fatal("signer metadata changed")
	}
}

func allZeroBytes(in []byte) bool {
	for _, b := range in {
		if b != 0 {
			return false
		}
	}
	return true
}
