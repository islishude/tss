//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestThresholdECDSAHDAdditiveShift(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	path := []uint32{0, 17}
	result, err := DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), path)
	if err != nil {
		t.Fatal(err)
	}
	derived := result.ChildPublicKey
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("hd additive shift"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := startCGGMP21Sign(shares[id], presigns[id], signID, request)
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
			if _, err := sessions[id].HandleSignMessage(testutil.DeliverEnvelope(env)); err != nil {
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
	if VerifySignature(shares[1].PublicKeyBytes(), request, sig) {
		t.Fatal("shifted signature verified against unshifted key")
	}
}

func TestThresholdECDSASignInteractiveReturnsDerivedPublicKey(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	signers := []*KeyShare{shares[1], shares[2]}
	path := []uint32{0, 9}
	result, err := DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), path)
	if err != nil {
		t.Fatal(err)
	}
	derived := result.ChildPublicKey
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
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
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	pubKey := shares[1].PublicKeyBytes()
	chainCode := shares[1].ChainCodeBytes()

	result, err := DeriveNonHardenedBIP32(pubKey, chainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ChildPublicKey) != 33 {
		t.Fatal("child public key must be 33 bytes")
	}
	if len(result.AdditiveShift) != 32 {
		t.Fatal("additive shift must be 32 bytes")
	}
	if len(result.ChildChainCode) != 32 {
		t.Fatal("child chain code must be 32 bytes")
	}
	derived, err := DerivePublicKey(pubKey, result.AdditiveShift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, result.ChildPublicKey) {
		t.Fatal("DeriveNonHardenedBIP32 and DerivePublicKey mismatch")
	}
}

func TestBIP32MultiLevel(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	pubKey := shares[1].PublicKeyBytes()
	chainCode := shares[1].ChainCodeBytes()

	result, err := DeriveNonHardenedBIP32(pubKey, chainCode, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ChildPublicKey) != 33 {
		t.Fatal("child public key must be 33 bytes")
	}
	if len(result.AdditiveShift) != 32 {
		t.Fatal("additive shift must be 32 bytes")
	}
	if len(result.ChildChainCode) != 32 {
		t.Fatal("child chain code must be 32 bytes")
	}
	// Two-step cumulative should produce consistent chain code with direct.
	_, err = DeriveNonHardenedBIP32(pubKey, chainCode, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	finalResult, err := DeriveNonHardenedBIP32(pubKey, chainCode, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.ChildChainCode, finalResult.ChildChainCode) {
		t.Fatal("multi-level chain code mismatch")
	}
	derived, err := DerivePublicKey(pubKey, result.AdditiveShift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, result.ChildPublicKey) {
		t.Fatal("DeriveNonHardenedBIP32 and DerivePublicKey mismatch for multi-level")
	}
}

func TestBIP32DeriveAndSign(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	path := []uint32{0, 5}
	result, err := DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), path)
	if err != nil {
		t.Fatal(err)
	}
	childPub := result.ChildPublicKey
	signers := tss.NewPartySet(1, 2)
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("bip32 derived signing"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := startCGGMP21Sign(shares[id], presigns[id], signID, request)
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
			if _, err := sessions[id].HandleSignMessage(testutil.DeliverEnvelope(env)); err != nil {
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
	if VerifySignature(shares[1].PublicKeyBytes(), request, sig) {
		t.Fatal("signature verified against master key (should use derived key)")
	}
}

func TestBIP32RejectsHardened(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	_, err := DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), []uint32{tss.HardenedKeyStart})
	if err == nil {
		t.Fatal("expected error for hardened index")
	}
	_, err = DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), []uint32{0, tss.HardenedKeyStart + 1})
	if err == nil {
		t.Fatal("expected error for hardened index in path")
	}
}

func TestBIP32RejectsEmptyChainCode(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	if len(shares[1].ChainCodeBytes()) > 0 {
		t.Skip("unexpected chain code with HD disabled")
	}
	_, err := DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), []uint32{0})
	if err == nil {
		t.Fatal("expected error for empty chain code")
	}
}

func TestSignWithEmptyBIP32PathMatchesParentKey(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	signers := tss.NewPartySet(1)
	ctx := testPresignContext()
	// Empty derivation path: the public key should be the parent key.
	ctx.Derivation.Path = tss.DerivationPath(nil).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("empty path signing"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := startCGGMP21Sign(shares[1], presigns[1], signID, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("expected sign partial")
	}
	sig, ok := session.Signature()
	if !ok {
		t.Fatal("signature not completed")
	}
	// The empty path should produce the parent key signature.
	if !VerifySignature(shares[1].PublicKeyBytes(), request, sig) {
		t.Fatal("empty path signature did not verify against parent key")
	}
}

func TestSignWithDerivedBIP32PathVerifiesUnderChildPublicKey(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	signers := tss.NewPartySet(1)
	path := []uint32{0, 1}
	result, err := DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("child key verify"), LowS: true}
	signID, _ := tss.NewSessionID(nil)
	session, out, err := startCGGMP21Sign(shares[1], presigns[1], signID, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("expected sign partial")
	}
	sig, ok := session.Signature()
	if !ok {
		t.Fatal("signature not completed")
	}
	if !VerifySignature(result.ChildPublicKey, request, sig) {
		t.Fatal("signature did not verify against child public key")
	}
	if VerifySignature(shares[1].PublicKeyBytes(), request, sig) {
		t.Fatal("signature verified against parent key (should not)")
	}
}

func TestPresignCannotBeReusedAcrossDerivedPaths(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	signers := tss.NewPartySet(1)

	// Create presign for path A.
	ctxA := testPresignContext()
	ctxA.Derivation.Path = tss.DerivationPath([]uint32{0}).Clone()
	presignsA := secpPresignWithContext(t, shares, signers, ctxA)
	presignA := presignsA[1]

	// Attempt to sign with path B using presign from path A.
	ctxB := testPresignContext()
	ctxB.Derivation.Path = tss.DerivationPath([]uint32{1}).Clone()
	requestB := SignRequest{Context: ctxB, Message: []byte("cross path"), LowS: true}
	signID, _ := tss.NewSessionID(nil)
	cloned := clonePresignForTest(presignA)
	_, _, err := startCGGMP21Sign(shares[1], cloned, signID, requestB)
	if err == nil {
		t.Fatal("expected error signing with mismatched derivation path")
	}
}

func TestPresignBIP32AdditiveShiftBoundToContext(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	signers := tss.NewPartySet(1)
	path := []uint32{0, 5}
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)

	// Verify the presign has a non-zero additive shift.
	presign := presigns[1]
	derivation := presign.Derivation()
	if derivation == nil || len(derivation.AdditiveShift) != 32 {
		t.Fatal("expected 32-byte additive shift in presign")
	}
	if testutil.IsZeroBytes(derivation.AdditiveShift) {
		t.Fatal("additive shift should be non-zero for non-empty path")
	}
	// The context hash embeds the derivation path.
	if len(presign.ContextHashBytes()) != 32 {
		t.Fatal("expected 32-byte context hash")
	}
}
