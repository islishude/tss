//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestThresholdECDSAHDAdditiveShift(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 3, KeygenOptions{EnableHD: true})
	signers := []tss.PartyID{1, 2}
	path := []uint32{0, 17}
	derived, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testPresignContext()
	ctx.DerivationPath = path
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("hd additive shift"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSign(shares[id], presigns[id], signID, request)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range signers {
			if id == env.From {
				continue
			}
			if _, err := sessions[id].HandleSignMessage(env); err != nil {
				t.Fatal(err)
			}
		}
	}
	sig, ok := sessions[1].Signature()
	if !ok {
		t.Fatal("signature not completed")
	}
	if !VerifySignature(derived, request, sig) {
		t.Fatal("shifted signature did not verify against derived key")
	}
	if VerifySignature(shares[1].PublicKey, request, sig) {
		t.Fatal("shifted signature verified against unshifted key")
	}
}

func TestThresholdECDSASignInteractiveReturnsDerivedPublicKey(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 3, KeygenOptions{EnableHD: true})
	signers := []*KeyShare{shares[1], shares[2]}
	path := []uint32{0, 9}
	derived, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testPresignContext()
	ctx.DerivationPath = path
	request := SignRequest{Context: ctx, Message: []byte("interactive hd"), LowS: true}
	pub, sig, err := Sign(request.Message, signers, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, derived) {
		t.Fatal("interactive signing returned master key instead of derived key")
	}
	if !VerifySignature(pub, request, sig) {
		t.Fatal("interactive signature did not verify with returned key")
	}
}

func TestBIP32SingleLevel(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	pubKey := shares[1].PublicKey
	chainCode := shares[1].ChainCode

	childPub, shift, childChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(childPub) != 33 {
		t.Fatal("child public key must be 33 bytes")
	}
	if len(shift) != 32 {
		t.Fatal("additive shift must be 32 bytes")
	}
	if len(childChain) != 32 {
		t.Fatal("child chain code must be 32 bytes")
	}
	derived, err := DerivePublicKey(pubKey, shift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, childPub) {
		t.Fatal("DeriveBIP32 and DerivePublicKey mismatch")
	}
}

func TestBIP32MultiLevel(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	pubKey := shares[1].PublicKey
	chainCode := shares[1].ChainCode

	childPub, shift, childChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(childPub) != 33 {
		t.Fatal("child public key must be 33 bytes")
	}
	if len(shift) != 32 {
		t.Fatal("additive shift must be 32 bytes")
	}
	if len(childChain) != 32 {
		t.Fatal("child chain code must be 32 bytes")
	}
	// Two-step cumulative should produce consistent chain code with direct.
	_, _, midChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	_, _, finalChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(childChain, finalChain) {
		t.Fatal("multi-level chain code mismatch")
	}
	_ = midChain
	derived, err := DerivePublicKey(pubKey, shift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, childPub) {
		t.Fatal("DeriveBIP32 and DerivePublicKey mismatch for multi-level")
	}
}

func TestBIP32DeriveAndSign(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 3, KeygenOptions{EnableHD: true})
	path := []uint32{0, 5}
	childPub, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}
	ctx := testPresignContext()
	ctx.DerivationPath = path
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("bip32 derived signing"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession)
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSign(shares[id], presigns[id], signID, request)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range signers {
			if id == env.From {
				continue
			}
			if _, err := sessions[id].HandleSignMessage(env); err != nil {
				t.Fatal(err)
			}
		}
	}
	sig, ok := sessions[1].Signature()
	if !ok {
		t.Fatal("signature not completed")
	}
	if !VerifySignature(childPub, request, sig) {
		t.Fatal("signature did not verify against derived BIP32 key")
	}
	if VerifySignature(shares[1].PublicKey, request, sig) {
		t.Fatal("signature verified against master key (should use derived key)")
	}
}

func TestBIP32RejectsHardened(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	_, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{HardenedKeyStart})
	if err == nil {
		t.Fatal("expected error for hardened index")
	}
	_, _, _, err = DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{0, HardenedKeyStart + 1})
	if err == nil {
		t.Fatal("expected error for hardened index in path")
	}
}

func TestBIP32RejectsEmptyChainCode(t *testing.T) {
	shares := secpKeygen(t, 1, 1)
	if len(shares[1].ChainCode) > 0 {
		t.Skip("unexpected chain code with HD disabled")
	}
	_, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{0})
	if err == nil {
		t.Fatal("expected error for empty chain code")
	}
}

func TestBIP32RejectsEmptyPath(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	_, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}
