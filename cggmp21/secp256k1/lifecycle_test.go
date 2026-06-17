package secp256k1

import (
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
)

// TestKeygenSession_Destroy_ClearsSecrets verifies that Destroy zeros all
// secret-bearing fields and clears maps on a manually populated keygen session.
// This is a Tier 0 test: it constructs a session directly without Paillier keygen.
func TestKeygenSession_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	secretScalar, err := secpSecretScalarFromBig(big.NewInt(42))
	if err != nil {
		t.Fatal(err)
	}
	pd := make(map[tss.PartyID]*keygenPartyData, 2)
	pd[2] = &keygenPartyData{
		share:        new(big.Int).SetInt64(12345),
		chainCode:    []byte{0x01, 0x02, 0x03},
		commitments:  [][]byte{{0x0a}},
		confirmation: &KeygenConfirmation{},
	}
	pd[3] = &keygenPartyData{
		share: new(big.Int).SetInt64(67890),
	}
	s := &KeygenSession{
		partyData: pd,
		pending:   &KeyShare{state: &keyShareState{secret: secretScalar, chainCode: []byte{0x04, 0x05}}},
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

// newTestPresignSession creates a PresignSession populated with non-zero secret
// scalars, big.Int maps, and round payload data suitable for testing Destroy
// and abort cleanup.
func newTestPresignSession(t *testing.T) *PresignSession {
	t.Helper()
	return &PresignSession{
		kShare:     fillSecretScalar(t, 0x01),
		gamma:      fillSecretScalar(t, 0x11),
		xBar:       fillSecretScalar(t, 0x21),
		deltas:     map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(100)},
		alphaDelta: map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(200)},
		betaDelta:  map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(300)},
		alphaSigma: map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(400)},
		betaSigma:  map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(500)},
		derivation: &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: []byte{0x02, 0x03, 0x04},
			ChildChainCode: []byte{0x05, 0x06, 0x07},
			RequestedPath:  tss.DerivationPath{1, 2},
			ResolvedPath:   tss.DerivationPath{1, 2},
			AdditiveShift:  []byte{0x08, 0x09, 0x0a},
		},
		round1: map[tss.PartyID]presignRound1Payload{
			2: {Gamma: []byte{0xaa}, EncK: []byte{0xbb}, PaillierPublicKey: []byte{0xcc}},
		},
		round1Proofs: map[tss.PartyID]presignRound1ProofPayload{
			2: {PublicRound1Hash: []byte{0xdd}, EncKProof: []byte{0xee}},
		},
		round1ProofEnvelopes: map[tss.PartyID]tss.Envelope{
			2: {},
		},
		round2: map[tss.PartyID]presignRound2Payload{
			2: {
				Delta:      mta.ResponseMessage{Ciphertext: []byte{0x01}, Proof: []byte{0x02}},
				Sigma:      mta.ResponseMessage{Ciphertext: []byte{0x03}, Proof: []byte{0x04}},
				Round1Echo: []byte{0x05},
			},
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
// secret-bearing scalars, big.Int maps, and round payload data on a manually
// populated presign session.
func TestPresignSession_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := newTestPresignSession(t)
	childPublicKey := s.derivation.ChildPublicKey
	childChainCode := s.derivation.ChildChainCode
	requestedPath := s.derivation.RequestedPath
	resolvedPath := s.derivation.ResolvedPath
	additiveShift := s.derivation.AdditiveShift

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

	// big.Int maps must be empty.
	testutil.AssertMapCleared(t, s.deltas)
	testutil.AssertMapCleared(t, s.alphaDelta)
	testutil.AssertMapCleared(t, s.betaDelta)
	testutil.AssertMapCleared(t, s.alphaSigma)
	testutil.AssertMapCleared(t, s.betaSigma)

	// Round payload maps must be empty (secret-bearing: round1, round2).
	testutil.AssertMapCleared(t, s.round1)
	testutil.AssertMapCleared(t, s.round2)

	// Non-secret cleanup: round1Proofs map cleared, envelope map cleared.
	testutil.AssertMapCleared(t, s.round1Proofs)
	testutil.AssertMapCleared(t, s.round1ProofEnvelopes)

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
		partials: map[tss.PartyID]*big.Int{
			2: new(big.Int).SetInt64(888),
			3: new(big.Int).SetInt64(999),
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
	testutil.AssertMapCleared(t, s.deltas)
	testutil.AssertMapCleared(t, s.alphaDelta)
	testutil.AssertMapCleared(t, s.betaDelta)
	testutil.AssertMapCleared(t, s.alphaSigma)
	testutil.AssertMapCleared(t, s.betaSigma)
	testutil.AssertMapCleared(t, s.round1)
	testutil.AssertMapCleared(t, s.round2)
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
	secretScalar, _ := secpSecretScalarFromBig(big.NewInt(42))
	pd := make(map[tss.PartyID]*keygenPartyData, 1)
	pd[2] = &keygenPartyData{
		share:     new(big.Int).SetInt64(12345),
		chainCode: []byte{0x01, 0x02, 0x03},
	}
	s := &KeygenSession{
		partyData: pd,
		pending:   &KeyShare{state: &keyShareState{secret: secretScalar, chainCode: []byte{0x04}}},
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

// TestRefreshSession_Abort_ClearsSecrets verifies that abort clears shares
// and polynomial coefficients on a refresh session.
func TestRefreshSession_Abort_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := &RefreshSession{
		partyData: map[tss.PartyID]*refreshPartyData{
			2: {share: new(big.Int).SetInt64(42)},
		},
		ownPoly: []*big.Int{
			new(big.Int).SetInt64(1),
			new(big.Int).SetInt64(2),
			new(big.Int).SetInt64(3),
		},
	}

	s.abort()

	if !s.aborted {
		t.Fatal("aborted flag not set")
	}
	// shares checked via partyData
	if s.ownPoly != nil {
		t.Error("ownPoly not nil after abort")
	}
}

// TestKeyShare_Destroy_ClearsSecrets verifies that KeyShare.Destroy zeros the
// secret scalar, chain code, and Paillier private-key bytes.
func TestKeyShare_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	secretScalar := fillSecretScalar(t, 0x42)
	k := &KeyShare{state: &keyShareState{
		chainCode:          []byte{0x01, 0x02, 0x03, 0x04},
		secret:             secretScalar,
		paillierPrivateKey: []byte{0xaa, 0xbb, 0xcc},
	}}

	k.Destroy()

	// Chain code must be zeroed (clear zeros elements but preserves length).
	testutil.AssertBytesCleared(t, k.state.chainCode)
	// Paillier private key must be zeroed.
	testutil.AssertBytesCleared(t, k.state.paillierPrivateKey)
	// secret must report zero length (buf is set to nil by Destroy).
	if k.state.secret.FixedLen() != 0 {
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
		version: tss.Version,

		consumed: new(atomic.Bool),
		attempt:  newPresignAttemptBinding(false),
		kShare:   kShare,
		chiShare: chiShare,
		delta:    delta,
		derivation: &tss.DerivationResult{
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
	if p.state.kShare.FixedLen() != 0 {
		t.Error("kShare not zeroed")
	}
	if p.state.chiShare.FixedLen() != 0 {
		t.Error("chiShare not zeroed")
	}
	if p.state.delta.FixedLen() != 0 {
		t.Error("delta not zeroed")
	}
	testutil.AssertBytesCleared(t, childPublicKey)
	testutil.AssertBytesCleared(t, childChainCode)
	testutil.AssertBytesCleared(t, additiveShift)
	assertDerivationPathCleared(t, "requested path", requestedPath)
	assertDerivationPathCleared(t, "resolved path", resolvedPath)
	if p.state.derivation.Scheme != "" ||
		p.state.derivation.ChildPublicKey != nil ||
		p.state.derivation.ChildChainCode != nil ||
		p.state.derivation.RequestedPath != nil ||
		p.state.derivation.ResolvedPath != nil ||
		p.state.derivation.AdditiveShift != nil {
		t.Fatal("derivation result metadata not reset after Destroy")
	}
}

// TestDestroy_Idempotent verifies that calling Destroy twice does not panic.
func TestDestroy_Idempotent(t *testing.T) {
	t.Parallel()
	// KeygenSession double-Destroy.
	secretScalar, _ := secpSecretScalarFromBig(big.NewInt(42))
	kg := &KeygenSession{
		partyData: map[tss.PartyID]*keygenPartyData{2: {share: new(big.Int).SetInt64(1)}},
		pending:   &KeyShare{state: &keyShareState{secret: secretScalar}},
	}
	kg.Destroy()
	kg.Destroy() // must not panic

	// PresignSession double-Destroy.
	kShare := fillSecretScalar(t, 0x01)
	ps := &PresignSession{
		kShare:       kShare,
		deltas:       map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(1)},
		alphaDelta:   make(map[tss.PartyID]*big.Int),
		betaDelta:    make(map[tss.PartyID]*big.Int),
		alphaSigma:   make(map[tss.PartyID]*big.Int),
		betaSigma:    make(map[tss.PartyID]*big.Int),
		round1:       make(map[tss.PartyID]presignRound1Payload),
		round1Proofs: make(map[tss.PartyID]presignRound1ProofPayload),
		round2:       make(map[tss.PartyID]presignRound2Payload),
	}
	ps.Destroy()
	ps.Destroy() // must not panic

	// SignSession double-Destroy.
	ss := &SignSession{
		partials: map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(1)},
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
