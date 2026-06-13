//go:build slowcrypto

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// slowCryptoKeygen runs a full keygen with production 3072-bit Paillier and
// returns the confirmed key shares.
func slowCryptoKeygen(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()

	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*KeygenSession)
	var pending []tss.Envelope
	for _, party := range parties {
		kg, out, err := startCGGMP21Keygen(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      party,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = kg
		pending = append(pending, out...)
	}

	deliverKeygenMessages(t, sessions, parties, pending)

	shares := make(map[tss.PartyID]*KeyShare, n)
	for _, party := range parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			t.Fatalf("party %d keygen did not complete", party)
		}
		shares[party] = share
	}

	return shares
}

// slowCryptoPresign runs a full presign with production params and returns
// the presign records keyed by party.
func slowCryptoPresign(t *testing.T, shares map[tss.PartyID]*KeyShare, signers []tss.PartyID) map[tss.PartyID]*Presign {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*PresignSession)
	var pending []tss.Envelope
	for _, party := range signers {
		ps, out, err := StartPresign(shares[party], sessionID, signers)
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = ps
		pending = append(pending, out...)
	}

	for len(pending) > 0 {
		env := pending[0]
		pending = pending[1:]
		for _, party := range signers {
			if party == env.From || (env.To != 0 && env.To != party) {
				continue
			}
			out, err := sessions[party].HandlePresignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			pending = append(pending, out...)
		}
	}

	presigns := make(map[tss.PartyID]*Presign, len(signers))
	for _, party := range signers {
		p, ok := sessions[party].Presign()
		if !ok {
			t.Fatalf("party %d presign did not complete", party)
		}
		presigns[party] = p
	}
	return presigns
}

// TestSlowCrypto_Keygen3of5Production verifies 3-of-5 keygen with production
// 3072-bit Paillier keys. This is a correctness and performance regression test.
func TestSlowCrypto_Keygen3of5Production(t *testing.T) {
	t.Parallel()
	shares := slowCryptoKeygen(t, 3, 5)
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}
	// Verify all shares share the same public key.
	pk := shares[1].PublicKey
	for i := 2; i <= 5; i++ {
		if !bytes.Equal(pk, shares[tss.PartyID(i)].PublicKey) {
			t.Fatalf("party %d public key mismatch", i)
		}
	}
}

// TestSlowCrypto_Presign3of5Production verifies full 3-of-5 presign with
// production 3072-bit Paillier keys.
func TestSlowCrypto_Presign3of5Production(t *testing.T) {
	t.Parallel()
	shares := slowCryptoKeygen(t, 3, 5)
	signers := []tss.PartyID{1, 3, 5}
	presigns := slowCryptoPresign(t, shares, signers)
	if len(presigns) != 3 {
		t.Fatalf("expected 3 presigns, got %d", len(presigns))
	}
}

// TestSlowCrypto_Sign3of5Production verifies full 3-of-5 sign cycle with
// production 3072-bit Paillier keys.
func TestSlowCrypto_Sign3of5Production(t *testing.T) {
	t.Parallel()
	shares := slowCryptoKeygen(t, 3, 5)
	signers := []tss.PartyID{1, 3, 5}

	selected := make([]*KeyShare, 0, len(signers))
	for _, id := range signers {
		selected = append(selected, shares[id])
	}
	digest := sha256.Sum256([]byte("slowcrypto 3-of-5 production"))
	pub, sig, err := SignDigest(digest[:], selected)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature did not verify")
	}
}

// TestSlowCrypto_Refresh2of3Production verifies a 2-of-3 refresh cycle with
// production 3072-bit Paillier key rotation.
func TestSlowCrypto_Refresh2of3Production(t *testing.T) {
	t.Parallel()
	shares := slowCryptoKeygen(t, 2, 3)

	// Run refresh to rotate Paillier keys.
	parties := []tss.PartyID{1, 2, 3}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*RefreshSession)
	var pending []tss.Envelope
	for _, party := range parties {
		rs, out, err := startCGGMP21Refresh(shares[party], tss.ThresholdConfig{
			Threshold: 2,
			Parties:   parties,
			Self:      party,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = rs
		pending = append(pending, out...)
	}

	for len(pending) > 0 {
		env := pending[0]
		pending = pending[1:]
		for _, party := range parties {
			if party == env.From || (env.To != 0 && env.To != party) {
				continue
			}
			out, err := sessions[party].HandleRefreshMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			pending = append(pending, out...)
		}
	}

	refreshed := make(map[tss.PartyID]*KeyShare, 3)
	for _, party := range parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			t.Fatalf("party %d refresh did not complete", party)
		}
		refreshed[party] = share
	}

	// Verify group public key preserved.
	for _, party := range parties {
		if !bytes.Equal(shares[party].PublicKey, refreshed[party].PublicKey) {
			t.Fatalf("party %d public key changed after refresh", party)
		}
	}

	// Sign with refreshed shares.
	signers := []tss.PartyID{1, 2}
	selected := make([]*KeyShare, 0, len(signers))
	for _, id := range signers {
		selected = append(selected, refreshed[id])
	}
	digest := sha256.Sum256([]byte("slowcrypto refresh production"))
	pub, sig, err := SignDigest(digest[:], selected)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature did not verify after refresh")
	}
}

// TestSlowCrypto_BIP32DeriveAndSignProduction verifies BIP32 HD derivation
// and signing with production 3072-bit Paillier parameters.
func TestSlowCrypto_BIP32DeriveAndSignProduction(t *testing.T) {
	t.Parallel()
	shares := slowCryptoKeygenWithOptions(t, 2, 3, KeygenOptions{EnableHD: true})
	signers := []tss.PartyID{1, 2}
	path := []uint32{0, 17}

	// Verify derivation produces valid child key.
	result, err := DeriveNonHardenedBIP32(shares[1].PublicKey, shares[1].ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	derivedPub := result.ChildPublicKey

	ctx := testPresignContext()
	ctx.DerivationPath = path
	presigns := slowCryptoPresignWithContext(t, shares, signers, ctx)

	request := SignRequest{Context: ctx, Message: []byte("slowcrypto bip32 production"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*SignSession)
	var pending []tss.Envelope
	for _, party := range signers {
		ss, out, err := startCGGMP21Sign(shares[party], presigns[party], signID, request)
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = ss
		pending = append(pending, out...)
	}

	var sig *Signature
	for len(pending) > 0 {
		env := pending[0]
		pending = pending[1:]
		for _, party := range signers {
			if party == env.From || (env.To != 0 && env.To != party) {
				continue
			}
			out, err := sessions[party].HandleSignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			pending = append(pending, out...)
			if s, ok := sessions[party].Signature(); ok {
				sig = s
			}
		}
	}
	if sig == nil {
		t.Fatal("signing did not complete")
	}
	if !VerifySignature(derivedPub, request, sig) {
		t.Fatal("BIP32-derived signature did not verify")
	}
}

// slowCryptoKeygenWithOptions runs keygen with explicit options and production params.
func slowCryptoKeygenWithOptions(t *testing.T, threshold, n int, opts KeygenOptions) map[tss.PartyID]*KeyShare {
	t.Helper()

	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*KeygenSession)
	var pending []tss.Envelope
	for _, party := range parties {
		kg, out, err := startCGGMP21KeygenWithOptions(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      party,
			SessionID: sessionID,
		}, opts)
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = kg
		pending = append(pending, out...)
	}

	deliverKeygenMessages(t, sessions, parties, pending)

	shares := make(map[tss.PartyID]*KeyShare, n)
	for _, party := range parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			t.Fatalf("party %d keygen did not complete", party)
		}
		shares[party] = share
	}

	return shares
}

// slowCryptoPresignWithContext runs presign with explicit context and production params.
func slowCryptoPresignWithContext(t *testing.T, shares map[tss.PartyID]*KeyShare, signers []tss.PartyID, ctx PresignContext) map[tss.PartyID]*Presign {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*PresignSession)
	var pending []tss.Envelope
	for _, party := range signers {
		ps, out, err := startCGGMP21PresignWithContext(shares[party], sessionID, signers, ctx)
		if err != nil {
			t.Fatal(err)
		}
		sessions[party] = ps
		pending = append(pending, out...)
	}

	for len(pending) > 0 {
		env := pending[0]
		pending = pending[1:]
		for _, party := range signers {
			if party == env.From || (env.To != 0 && env.To != party) {
				continue
			}
			out, err := sessions[party].HandlePresignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			pending = append(pending, out...)
		}
	}

	presigns := make(map[tss.PartyID]*Presign, len(signers))
	for _, party := range signers {
		p, ok := sessions[party].Presign()
		if !ok {
			t.Fatalf("party %d presign did not complete", party)
		}
		presigns[party] = p
	}
	return presigns
}
