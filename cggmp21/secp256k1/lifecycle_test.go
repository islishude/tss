package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
)

func TestCGGMP21KeyShareJSONAndDestroy(t *testing.T) {
	_, share := secpLifecycleKeygen(t, true)
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
	if !allZeroBytes(share.paillierPrivateKey) {
		t.Fatal("Paillier private key bytes were not cleared")
	}
	if !allZeroBytes(share.ChainCode) {
		t.Fatal("chain code bytes were not cleared")
	}
	if !bytes.Equal(share.PublicKey, publicKey) {
		t.Fatal("public key metadata changed")
	}
}

func TestCGGMP21KeyShareRedactsFormattingAndReturnsCopy(t *testing.T) {
	keygen, share := secpLifecycleKeygen(t, false)
	formatted := fmt.Sprintf("%#v", share)
	formattedValue := fmt.Sprintf("%#v", *share)
	if !strings.Contains(formatted, "Secret:<redacted>") || !strings.Contains(formatted, "PaillierPrivateKey:<redacted>") {
		t.Fatalf("formatted key share did not mark secret fields redacted: %s", formatted)
	}
	if !strings.Contains(formattedValue, "Secret:<redacted>") || !strings.Contains(formattedValue, "PaillierPrivateKey:<redacted>") {
		t.Fatalf("formatted key share value did not mark secret fields redacted: %s", formattedValue)
	}
	if strings.Contains(formatted, fmt.Sprint(string(share.secret))) {
		t.Fatal("formatted key share exposed secret scalar bytes")
	}
	if strings.Contains(formattedValue, fmt.Sprint(string(share.secret))) {
		t.Fatal("formatted key share value exposed secret scalar bytes")
	}
	if strings.Contains(formatted, fmt.Sprint(string(share.paillierPrivateKey))) {
		t.Fatal("formatted key share exposed Paillier private-key bytes")
	}
	if strings.Contains(formattedValue, fmt.Sprint(string(share.paillierPrivateKey))) {
		t.Fatal("formatted key share value exposed Paillier private-key bytes")
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

func TestCGGMP21PresignJSONAndDestroy(t *testing.T) {
	_, share := secpLifecycleKeygen(t, false)
	presign := secpLifecyclePresign(t, share)
	if _, err := json.Marshal(presign); err == nil {
		t.Fatal("pointer presign JSON encoded")
	}
	if _, err := json.Marshal(*presign); err == nil {
		t.Fatal("value presign JSON encoded")
	}
	r := append([]byte(nil), presign.R...)
	littleR := append([]byte(nil), presign.LittleR...)
	transcript := append([]byte(nil), presign.TranscriptHash...)
	presign.Destroy()
	if !presign.Consumed {
		t.Fatal("presign was not marked consumed")
	}
	if !allZeroBytes(presign.KShare) || !allZeroBytes(presign.ChiShare) || !allZeroBytes(presign.Delta) {
		t.Fatal("presign secret shares were not cleared")
	}
	if !bytes.Equal(presign.R, r) || !bytes.Equal(presign.LittleR, littleR) || !bytes.Equal(presign.TranscriptHash, transcript) {
		t.Fatal("presign public diagnostic metadata changed")
	}
}

func TestCGGMP21SessionDestroyClearsLocalSecrets(t *testing.T) {
	keygen, share := secpLifecycleKeygen(t, true)
	publicKey := append([]byte(nil), share.PublicKey...)
	keygen.Destroy()
	if len(keygen.shares) != 0 {
		t.Fatal("keygen share map was not cleared")
	}
	if len(keygen.chainCodes) != 0 {
		t.Fatal("keygen chain-code map was not cleared")
	}
	if keygen.paillier != nil {
		t.Fatal("Paillier private key was not released")
	}
	if keygen.keyShare == nil || !allZeroBytes(keygen.keyShare.secret) || !allZeroBytes(keygen.keyShare.paillierPrivateKey) {
		t.Fatal("completed key share secret material was not cleared")
	}
	if !bytes.Equal(share.PublicKey, publicKey) {
		t.Fatal("keygen public metadata changed")
	}

	_, share = secpLifecycleKeygen(t, false)
	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	presignSession, _, err := StartPresign(share, presignID, []tss.PartyID{1})
	if err != nil {
		t.Fatal(err)
	}
	presign, ok := presignSession.Presign()
	if !ok {
		t.Fatal("presign did not complete")
	}
	r := append([]byte(nil), presign.R...)
	presignSession.Destroy()
	if presignSession.kShare != nil || presignSession.gamma != nil || presignSession.xBar != nil {
		t.Fatal("presign local scalars were not released")
	}
	if presignSession.paillier != nil {
		t.Fatal("presign Paillier private key was not released")
	}
	if len(presignSession.alphaDelta) != 0 || len(presignSession.betaDelta) != 0 || len(presignSession.alphaSigma) != 0 || len(presignSession.betaSigma) != 0 {
		t.Fatal("presign MtA share maps were not cleared")
	}
	if !presign.Consumed || !allZeroBytes(presign.KShare) || !allZeroBytes(presign.ChiShare) || !allZeroBytes(presign.Delta) {
		t.Fatal("completed presign was not destroyed")
	}
	if !bytes.Equal(presign.R, r) {
		t.Fatal("presign public metadata changed")
	}

	_, share = secpLifecycleKeygen(t, false)
	signPresign := secpLifecyclePresign(t, share)
	digest := sha256.Sum256([]byte("message"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signSession, _, err := StartSignDigest(share, signPresign, signID, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(signSession.partials) == 0 || len(signSession.digest) == 0 {
		t.Fatal("sign session did not retain expected local material")
	}
	signSession.Destroy()
	if len(signSession.partials) != 0 {
		t.Fatal("online signing partials were not cleared")
	}
	if signSession.digest != nil {
		t.Fatal("online signing digest was not released")
	}
	if signSession.sessionID != signID {
		t.Fatal("signing session metadata changed")
	}
}

func secpLifecycleKeygen(t testing.TB, enableHD bool) (*KeygenSession, *KeyShare) {
	t.Helper()
	restore := pai.SetMinimumModulusBitsForTesting(minKeygenPaillierBits)
	t.Cleanup(restore)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygen, _, err := StartKeygenWithOptions(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   []tss.PartyID{1},
		Self:      1,
		SessionID: sessionID,
	}, KeygenOptions{PaillierBits: minKeygenPaillierBits, EnableHD: enableHD})
	if err != nil {
		t.Fatal(err)
	}
	share, ok := keygen.KeyShare()
	if !ok {
		t.Fatal("keygen did not complete")
	}
	return keygen, share
}

func secpLifecyclePresign(t testing.TB, share *KeyShare) *Presign {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := StartPresign(share, sessionID, []tss.PartyID{1})
	if err != nil {
		t.Fatal(err)
	}
	presign, ok := session.Presign()
	if !ok {
		t.Fatal("presign did not complete")
	}
	return presign
}

func allZeroBytes(in []byte) bool {
	for _, b := range in {
		if b != 0 {
			return false
		}
	}
	return true
}
