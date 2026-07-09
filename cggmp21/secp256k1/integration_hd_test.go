//go:build integration

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
	result, err := DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), path)
	if err != nil {
		t.Fatal(err)
	}
	derived := result.ChildPublicKey
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("hd additive shift")}
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
			if _, err := sessions[id].Handle(testutil.DeliverEnvelope(env)); err != nil {
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
	if VerifySignature(mustKeySharePublicKey(t, shares[1]), request, sig) {
		t.Fatal("shifted signature verified against unshifted key")
	}
}

func TestThresholdECDSADeriveMatchesPublicMetadata(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	share := shares[1]
	metadata, ok := share.PublicMetadata()
	if !ok {
		t.Fatal("missing public metadata")
	}
	path := tss.DerivationPath{0, 11}

	fromShare, err := share.Derive(path)
	if err != nil {
		t.Fatal(err)
	}
	fromMetadata, err := DeriveNonHardenedBIP32(metadata.PublicKey, metadata.ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fromShare.ChildPublicKey, fromMetadata.ChildPublicKey) {
		t.Fatal("KeyShare.Derive child public key differs from public metadata derivation")
	}
	if fromShare.Scheme != tss.DerivationSchemeBIP32Secp256k1 {
		t.Fatalf("scheme = %q, want %q", fromShare.Scheme, tss.DerivationSchemeBIP32Secp256k1)
	}
}

func TestThresholdECDSASignInteractiveReturnsDerivedPublicKey(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	signers := []*KeyShare{shares[1], shares[2]}
	path := []uint32{0, 9}
	result, err := DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), path)
	if err != nil {
		t.Fatal(err)
	}
	derived := result.ChildPublicKey
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	request := SignRequest{Context: ctx, Message: []byte("interactive hd")}
	pub, sig, err := signCGGMP21Simulation(request.Message, signers, ctx, false, testLimits())
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

func TestBIP32DeriveAndSign(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	path := []uint32{0, 5}
	result, err := DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), path)
	if err != nil {
		t.Fatal(err)
	}
	childPub := result.ChildPublicKey
	signers := tss.NewPartySet(1, 2)
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("bip32 derived signing")}
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
			if _, err := sessions[id].Handle(testutil.DeliverEnvelope(env)); err != nil {
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
	if VerifySignature(mustKeySharePublicKey(t, shares[1]), request, sig) {
		t.Fatal("signature verified against master key (should use derived key)")
	}
}

func TestBIP32RejectsHardened(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	_, err := DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), []uint32{tss.HardenedKeyStart})
	if err == nil {
		t.Fatal("expected error for hardened index")
	}
	_, err = DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), []uint32{0, tss.HardenedKeyStart + 1})
	if err == nil {
		t.Fatal("expected error for hardened index in path")
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
	request := SignRequest{Context: ctx, Message: []byte("empty path signing")}
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
	if !VerifySignature(mustKeySharePublicKey(t, shares[1]), request, sig) {
		t.Fatal("empty path signature did not verify against parent key")
	}
}

func TestSignWithDerivedBIP32PathVerifiesUnderChildPublicKey(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	signers := tss.NewPartySet(1)
	path := []uint32{0, 1}
	result, err := DeriveNonHardenedBIP32(mustKeySharePublicKey(t, shares[1]), mustKeyShareChainCode(t, shares[1]), path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testPresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("child key verify")}
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
	if VerifySignature(mustKeySharePublicKey(t, shares[1]), request, sig) {
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
	requestB := SignRequest{Context: ctxB, Message: []byte("cross path")}
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
	derivation := mustPresignMetadata(t, presign).Derivation
	if derivation == nil || len(derivation.AdditiveShift) != 32 {
		t.Fatal("expected 32-byte additive shift in presign")
	}
	if testutil.IsZeroBytes(derivation.AdditiveShift) {
		t.Fatal("additive shift should be non-zero for non-empty path")
	}
	// The context hash embeds the derivation path.
	if len(mustPresignContextHash(t, presign)) != 32 {
		t.Fatal("expected 32-byte context hash")
	}
}
