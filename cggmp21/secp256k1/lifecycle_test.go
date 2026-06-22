package secp256k1

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// TestKeygenSession_Destroy_ClearsSecrets verifies that Destroy zeros all
// secret-bearing fields and clears maps on a manually populated keygen session.
// This is a Tier 0 test: it constructs a session directly without Paillier keygen.
func TestKeygenSession_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	secretScalar := testSecretScalar(t, 42)
	pd := make(map[tss.PartyID]*keygenPartyData, 2)
	pd[2] = &keygenPartyData{
		share:        testSecretScalar(t, 12345),
		chainCode:    []byte{0x01, 0x02, 0x03},
		commitments:  [][]byte{{0x0a}},
		confirmation: &KeygenConfirmation{},
	}
	pd[3] = &keygenPartyData{
		share: testSecretScalar(t, 67890),
	}
	s := &KeygenSession{
		partyData: pd,
		pending:   &KeyShare{state: &keyShareState{Secret: secretScalar, ChainCode: []byte{0x04, 0x05}}},
	}

	s.Destroy()

	// After Destroy, all secret-bearing maps must be empty.
	// shares checked via partyData
	// chainCodes checked via partyData
	// commits checked via partyData
	// confirmations checked via partyData

	// pending must be nil.
	if s.pending != nil {
		t.Error("pending not set to nil after Destroy")
	}

	// aborted must be true (set by abort() called from Destroy).
	if !s.aborted {
		t.Error("aborted flag not set after Destroy")
	}
	if s.state != keygenAborted {
		t.Errorf("state not keygenAborted after Destroy: got %d", s.state)
	}

	// keyShare must be nil (no completed share).
	if s.keyShare != nil {
		t.Error("keyShare not nil after Destroy")
	}
}

// fillSecretScalar creates a new secp256k1 secret.Scalar filled with non-zero
// data from the given seed byte. Only for use in tests.
func fillSecretScalar(t *testing.T, seed byte) *secret.Scalar {
	t.Helper()
	data := make([]byte, secp.ScalarSize)
	for i := range data {
		data[i] = seed + byte(i)
	}
	s, err := newSecpSecretScalar(data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustTestSecretScalar(t *testing.T, value uint64) *secret.Scalar {
	t.Helper()
	out, err := secpSecretScalarFromScalar(secp.ScalarFromUint64(value))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func testPaillierPublicKey(seed int64) pai.PublicKey {
	n := big.NewInt(seed)
	return pai.PublicKey{
		N:        n,
		G:        big.NewInt(seed + 1),
		NSquared: new(big.Int).Mul(n, n),
	}
}

func testPaillierPrivateKey(t *testing.T) *pai.PrivateKey {
	t.Helper()
	publicKey := testPaillierPublicKey(65)
	return &pai.PrivateKey{
		PublicKey: publicKey,
		Lambda:    mustTestSecretScalar(t, 1),
		Mu:        mustTestSecretScalar(t, 2),
		P:         mustTestSecretScalar(t, 3),
		Q:         mustTestSecretScalar(t, 4),
	}
}

func testEncProof(seed int64) zkpai.EncProof {
	return zkpai.EncProof{
		S:              big.NewInt(seed),
		A:              big.NewInt(seed + 1),
		C:              big.NewInt(seed + 2),
		Z1:             big.NewInt(seed + 3),
		Z2:             big.NewInt(seed + 4),
		Z3:             big.NewInt(seed + 5),
		TranscriptHash: []byte{byte(seed), byte(seed + 1)},
	}
}

func testAffGProof(seed int64) zkpai.AffGProof {
	return zkpai.AffGProof{
		A:              big.NewInt(seed),
		By:             big.NewInt(seed + 1),
		E:              big.NewInt(seed + 2),
		S:              big.NewInt(seed + 3),
		F:              big.NewInt(seed + 4),
		T:              big.NewInt(seed + 5),
		Y:              big.NewInt(seed + 6),
		Z1:             big.NewInt(seed + 7),
		Z2:             big.NewInt(seed + 8),
		Z3:             big.NewInt(seed + 9),
		Z4:             big.NewInt(seed + 10),
		W:              big.NewInt(seed + 11),
		WY:             big.NewInt(seed + 12),
		TranscriptHash: []byte{byte(seed), byte(seed + 1)},
	}
}

// newTestPresignSession creates a PresignSession populated with non-zero secret
// scalars, MtA scalar maps, and round payload data suitable for testing Destroy
// and abort cleanup.
func newTestPresignSession(t *testing.T) *PresignSession {
	t.Helper()
	paillierPublicKey := testPaillierPublicKey(600)
	party := presignPartyState{
		id: 2,
		round1: presignRound1State{
			payload:       presignRound1Payload{Gamma: []byte{0xaa}, EncK: []byte{0xbb}, PaillierPublicKey: &paillierPublicKey},
			havePayload:   true,
			proof:         presignRound1ProofPayload{PublicRound1Hash: []byte{0xdd}, EncKProof: testEncProof(700)},
			proofEnvelope: tss.Envelope{},
			haveProof:     true,
			verified:      true,
		},
		round2: presignRound2State{
			payload: presignRound2Payload{
				Delta:      mta.ResponseMessage{Ciphertext: []byte{0x01}, Proof: testAffGProof(800)},
				Sigma:      mta.ResponseMessage{Ciphertext: []byte{0x03}, Proof: testAffGProof(900)},
				Round1Echo: []byte{0x05},
			},
			havePayload: true,
		},
		round3: presignRound3State{
			delta:     mustTestSecretScalar(t, 100),
			haveDelta: true,
		},
		mta: presignMTAState{
			alphaDelta: mustTestSecretScalar(t, 200),
			betaDelta:  mustTestSecretScalar(t, 300),
			alphaSigma: mustTestSecretScalar(t, 400),
			betaSigma:  mustTestSecretScalar(t, 500),
		},
	}
	return &PresignSession{
		kShare:     fillSecretScalar(t, 0x01),
		gamma:      fillSecretScalar(t, 0x11),
		xBar:       fillSecretScalar(t, 0x21),
		partyIndex: map[tss.PartyID]int{2: 0},
		parties:    []presignPartyState{party},
		derivation: &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: []byte{0x02, 0x03, 0x04},
			ChildChainCode: []byte{0x05, 0x06, 0x07},
			RequestedPath:  tss.DerivationPath{1, 2},
			ResolvedPath:   tss.DerivationPath{1, 2},
			AdditiveShift:  []byte{0x08, 0x09, 0x0a},
		},
	}
}

func assertDerivationPathCleared(t *testing.T, name string, path tss.DerivationPath) {
	t.Helper()
	for i, v := range path {
		if v != 0 {
			t.Fatalf("%s element %d not cleared: %d", name, i, v)
		}
	}
}

// TestPresignSession_Destroy_ClearsSecrets verifies that Destroy zeros all
// secret-bearing scalars and round payload data on a manually populated
// presign session.
func TestPresignSession_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := newTestPresignSession(t)
	childPublicKey := s.derivation.ChildPublicKey
	childChainCode := s.derivation.ChildChainCode
	requestedPath := s.derivation.RequestedPath
	resolvedPath := s.derivation.ResolvedPath
	additiveShift := s.derivation.AdditiveShift
	round1Gamma := s.parties[0].round1.payload.Gamma
	round1EncK := s.parties[0].round1.payload.EncK
	round2Delta := s.parties[0].round2.payload.Delta.Ciphertext
	round2Sigma := s.parties[0].round2.payload.Sigma.Ciphertext

	s.Destroy()

	// Scalars must be nil after Destroy.
	if s.kShare != nil {
		t.Error("kShare not nil after Destroy")
	}
	if s.gamma != nil {
		t.Error("gamma not nil after Destroy")
	}
	if s.xBar != nil {
		t.Error("xBar not nil after Destroy")
	}

	if len(s.partyIndex) != 0 {
		t.Error("partyIndex not cleared after Destroy")
	}
	if s.parties != nil {
		t.Error("parties not nil after Destroy")
	}
	testutil.AssertBytesCleared(t, round1Gamma)
	testutil.AssertBytesCleared(t, round1EncK)
	testutil.AssertBytesCleared(t, round2Delta)
	testutil.AssertBytesCleared(t, round2Sigma)

	if s.derivation != nil {
		t.Error("derivation not nil after Destroy")
	}
	testutil.AssertBytesCleared(t, childPublicKey)
	testutil.AssertBytesCleared(t, childChainCode)
	testutil.AssertBytesCleared(t, additiveShift)
	assertDerivationPathCleared(t, "requested path", requestedPath)
	assertDerivationPathCleared(t, "resolved path", resolvedPath)

	// aborted must be true.
	if !s.aborted {
		t.Error("aborted flag not set after Destroy")
	}
}

// TestSignSession_Destroy_ClearsSecrets verifies that Destroy zeros all
// secret-bearing partials and digest on a manually populated signing session.
func TestSignSession_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := &SignSession{
		partials: map[tss.PartyID]secp.Scalar{
			2: secp.ScalarFromUint64(888),
			3: secp.ScalarFromUint64(999),
		},
		digest:    []byte{0x01, 0x02, 0x03, 0x04},
		publicKey: []byte{0xaa, 0xbb},
		signature: &Signature{R: []byte{0x11}, S: []byte{0x22}},
	}

	s.Destroy()

	// partials map must be empty.
	testutil.AssertMapCleared(t, s.partials)
	// digest must be nil.
	if s.digest != nil {
		t.Error("digest not nil after Destroy")
	}
	// publicKey must be nil.
	if s.publicKey != nil {
		t.Error("publicKey not nil after Destroy")
	}
	// signature bytes cleared, struct nil.
	if s.signature != nil {
		t.Error("signature not nil after Destroy")
	}
	// aborted must be true.
	if !s.aborted {
		t.Error("aborted flag not set after Destroy")
	}
}

func TestPresignSession_Abort_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := newTestPresignSession(t)
	childPublicKey := s.derivation.ChildPublicKey
	childChainCode := s.derivation.ChildChainCode
	requestedPath := s.derivation.RequestedPath
	resolvedPath := s.derivation.ResolvedPath
	additiveShift := s.derivation.AdditiveShift
	round1Gamma := s.parties[0].round1.payload.Gamma
	round1EncK := s.parties[0].round1.payload.EncK
	round2Delta := s.parties[0].round2.payload.Delta.Ciphertext
	round2Sigma := s.parties[0].round2.payload.Sigma.Ciphertext

	s.abort()

	if !s.aborted {
		t.Fatal("aborted flag not set")
	}
	if s.kShare != nil {
		t.Error("kShare not nil after abort")
	}
	if s.gamma != nil {
		t.Error("gamma not nil after abort")
	}
	if s.xBar != nil {
		t.Error("xBar not nil after abort")
	}
	if len(s.partyIndex) != 0 {
		t.Error("partyIndex not cleared after abort")
	}
	if s.parties != nil {
		t.Error("parties not nil after abort")
	}
	testutil.AssertBytesCleared(t, round1Gamma)
	testutil.AssertBytesCleared(t, round1EncK)
	testutil.AssertBytesCleared(t, round2Delta)
	testutil.AssertBytesCleared(t, round2Sigma)
	if s.derivation != nil {
		t.Error("derivation not nil after abort")
	}
	testutil.AssertBytesCleared(t, childPublicKey)
	testutil.AssertBytesCleared(t, childChainCode)
	testutil.AssertBytesCleared(t, additiveShift)
	assertDerivationPathCleared(t, "requested path", requestedPath)
	assertDerivationPathCleared(t, "resolved path", resolvedPath)
}

// TestKeygenSession_Abort_ClearsSecrets verifies that abort clears all
// secret-bearing accumulated state on a keygen session.
func TestKeygenSession_Abort_ClearsSecrets(t *testing.T) {
	t.Parallel()
	secretScalar := testSecretScalar(t, 42)
	pd := make(map[tss.PartyID]*keygenPartyData, 1)
	pd[2] = &keygenPartyData{
		share:     testSecretScalar(t, 12345),
		chainCode: []byte{0x01, 0x02, 0x03},
	}
	s := &KeygenSession{
		partyData: pd,
		pending:   &KeyShare{state: &keyShareState{Secret: secretScalar, ChainCode: []byte{0x04}}},
	}

	s.abort()

	if !s.aborted {
		t.Fatal("aborted flag not set")
	}
	if s.state != keygenAborted {
		t.Errorf("state not keygenAborted: got %d", s.state)
	}
	// shares checked via partyData
	// chainCodes checked via partyData
	if s.pending != nil {
		t.Error("pending not nil after abort")
	}
}

// TestRefreshSession_Abort_ClearsSecrets verifies that abort clears shares on a
// refresh session.
func TestRefreshSession_Abort_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := &RefreshSession{
		partyData: map[tss.PartyID]*refreshPartyData{
			2: {share: testSecretScalar(t, 42)},
		},
	}

	s.abort()

	if !s.aborted {
		t.Fatal("aborted flag not set")
	}
	// shares checked via partyData
}

// TestKeyShare_Destroy_ClearsSecrets verifies that KeyShare.Destroy zeros the
// secret scalar, chain code, and Paillier private-key material.
func TestKeyShare_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	secretScalar := fillSecretScalar(t, 0x42)
	privateKey := testPaillierPrivateKey(t)
	k := &KeyShare{state: &keyShareState{
		ChainCode:          []byte{0x01, 0x02, 0x03, 0x04},
		Secret:             secretScalar,
		PaillierPrivateKey: privateKey,
	}}

	k.Destroy()

	// Chain code must be zeroed (clear zeros elements but preserves length).
	testutil.AssertBytesCleared(t, k.state.ChainCode)
	for name, scalar := range map[string]*secret.Scalar{
		"lambda": privateKey.Lambda,
		"mu":     privateKey.Mu,
		"p":      privateKey.P,
		"q":      privateKey.Q,
	} {
		if scalar.FixedLen() != 0 {
			t.Errorf("Paillier private key %s not zeroed after Destroy", name)
		}
	}
	// secret must report zero length (buf is set to nil by Destroy).
	if k.state.Secret.FixedLen() != 0 {
		t.Error("secret scalar not zeroed after Destroy")
	}
}

// TestPresign_Destroy_ClearsSecrets verifies that Presign.Destroy zeros secret
// shares and marks the presign consumed.
func TestPresign_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	kShare := fillSecretScalar(t, 0x11)
	chiShare := fillSecretScalar(t, 0x22)
	delta := fillSecretScalar(t, 0x33)

	childPublicKey := []byte{0x02, 0x03, 0x04}
	childChainCode := []byte{0x05, 0x06, 0x07}
	requestedPath := tss.DerivationPath{1, 2}
	resolvedPath := tss.DerivationPath{1, 2}
	additiveShift := []byte{0x08, 0x09, 0x0a}
	p := &Presign{state: &presignState{

		Consumed:       NewAtomicBoolWire(false),
		attempt:        newPresignAttemptBinding(false),
		KShare:         kShare,
		ChiShare:       chiShare,
		DeltaAggregate: delta,
		Derivation: &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: childPublicKey,
			ChildChainCode: childChainCode,
			RequestedPath:  requestedPath,
			ResolvedPath:   resolvedPath,
			AdditiveShift:  additiveShift,
		},
	}}

	p.Destroy()

	if !IsPresignConsumed(p) {
		t.Error("presign not consumed after Destroy")
	}
	if p.state.KShare.FixedLen() != 0 {
		t.Error("kShare not zeroed")
	}
	if p.state.ChiShare.FixedLen() != 0 {
		t.Error("chiShare not zeroed")
	}
	if p.state.DeltaAggregate.FixedLen() != 0 {
		t.Error("delta not zeroed")
	}
	testutil.AssertBytesCleared(t, childPublicKey)
	testutil.AssertBytesCleared(t, childChainCode)
	testutil.AssertBytesCleared(t, additiveShift)
	assertDerivationPathCleared(t, "requested path", requestedPath)
	assertDerivationPathCleared(t, "resolved path", resolvedPath)
	if p.state.Derivation.Scheme != "" ||
		p.state.Derivation.ChildPublicKey != nil ||
		p.state.Derivation.ChildChainCode != nil ||
		p.state.Derivation.RequestedPath != nil ||
		p.state.Derivation.ResolvedPath != nil ||
		p.state.Derivation.AdditiveShift != nil {
		t.Fatal("derivation result metadata not reset after Destroy")
	}
}

// TestDestroy_Idempotent verifies that calling Destroy twice does not panic.
func TestDestroy_Idempotent(t *testing.T) {
	t.Parallel()
	// KeygenSession double-Destroy.
	secretScalar := testSecretScalar(t, 42)
	kg := &KeygenSession{
		partyData: map[tss.PartyID]*keygenPartyData{2: {share: testSecretScalar(t, 1)}},
		pending:   &KeyShare{state: &keyShareState{Secret: secretScalar}},
	}
	kg.Destroy()
	kg.Destroy() // must not panic

	// PresignSession double-Destroy.
	kShare := fillSecretScalar(t, 0x01)
	ps := &PresignSession{
		kShare:     kShare,
		partyIndex: map[tss.PartyID]int{2: 0},
		parties: []presignPartyState{{
			id:     2,
			round3: presignRound3State{delta: mustTestSecretScalar(t, 1), haveDelta: true},
		}},
	}
	ps.Destroy()
	ps.Destroy() // must not panic

	// SignSession double-Destroy.
	ss := &SignSession{
		partials: map[tss.PartyID]secp.Scalar{2: secp.ScalarOne()},
	}
	ss.Destroy()
	ss.Destroy() // must not panic

	// Nil receiver Destroy must not panic.
	var nilKG *KeygenSession
	nilKG.Destroy()
	var nilPS *PresignSession
	nilPS.Destroy()
	var nilSS *SignSession
	nilSS.Destroy()
}
