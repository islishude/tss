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
	s := &KeygenSession{
		shares: map[tss.PartyID]*big.Int{
			2: new(big.Int).SetInt64(12345),
			3: new(big.Int).SetInt64(67890),
		},
		chainCodes: map[tss.PartyID][]byte{
			2: {0x01, 0x02, 0x03},
		},
		pending: &pendingKeyShare{
			share: &KeyShare{secret: secretScalar, ChainCode: []byte{0x04, 0x05}},
		},
		commits: map[tss.PartyID][][]byte{
			2: {{0x0a}},
		},
		confirmations: map[tss.PartyID][]byte{
			2: {0x0b},
		},
	}

	s.Destroy()

	// After Destroy, all secret-bearing maps must be empty.
	testutil.AssertMapCleared(t, s.shares)
	testutil.AssertMapCleared(t, s.chainCodes)
	testutil.AssertMapCleared(t, s.commits)
	testutil.AssertMapCleared(t, s.confirmations)

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

// TestPresignSession_Destroy_ClearsSecrets verifies that Destroy zeros all
// secret-bearing scalars, big.Int maps, and round payload data on a manually
// populated presign session.
func TestPresignSession_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := newTestPresignSession(t)

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
}

// TestKeygenSession_Abort_ClearsSecrets verifies that abort clears all
// secret-bearing accumulated state on a keygen session.
func TestKeygenSession_Abort_ClearsSecrets(t *testing.T) {
	t.Parallel()
	secretScalar, _ := secpSecretScalarFromBig(big.NewInt(42))
	s := &KeygenSession{
		shares: map[tss.PartyID]*big.Int{
			2: new(big.Int).SetInt64(12345),
		},
		chainCodes: map[tss.PartyID][]byte{
			2: {0x01, 0x02, 0x03},
		},
		pending: &pendingKeyShare{
			share: &KeyShare{secret: secretScalar, ChainCode: []byte{0x04}},
		},
	}

	s.abort()

	if !s.aborted {
		t.Fatal("aborted flag not set")
	}
	if s.state != keygenAborted {
		t.Errorf("state not keygenAborted: got %d", s.state)
	}
	testutil.AssertMapCleared(t, s.shares)
	testutil.AssertMapCleared(t, s.chainCodes)
	if s.pending != nil {
		t.Error("pending not nil after abort")
	}
}

// TestRefreshSession_Abort_ClearsSecrets verifies that abort clears shares
// and polynomial coefficients on a refresh session.
func TestRefreshSession_Abort_ClearsSecrets(t *testing.T) {
	t.Parallel()
	s := &RefreshSession{
		shares: map[tss.PartyID]*big.Int{
			2: new(big.Int).SetInt64(42),
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
	testutil.AssertMapCleared(t, s.shares)
	if s.ownPoly != nil {
		t.Error("ownPoly not nil after abort")
	}
}

// TestKeyShare_Destroy_ClearsSecrets verifies that KeyShare.Destroy zeros the
// secret scalar, chain code, and Paillier private-key bytes.
func TestKeyShare_Destroy_ClearsSecrets(t *testing.T) {
	t.Parallel()
	secretScalar := fillSecretScalar(t, 0x42)
	k := &KeyShare{
		ChainCode:          []byte{0x01, 0x02, 0x03, 0x04},
		secret:             secretScalar,
		paillierPrivateKey: []byte{0xaa, 0xbb, 0xcc},
	}

	k.Destroy()

	// Chain code must be zeroed (clear zeros elements but preserves length).
	testutil.AssertBytesCleared(t, k.ChainCode)
	// Paillier private key must be zeroed.
	testutil.AssertBytesCleared(t, k.paillierPrivateKey)
	// secret must report zero length (buf is set to nil by Destroy).
	if k.secret.FixedLen() != 0 {
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

	p := &Presign{
		consumed:      new(atomic.Bool),
		kShare:        kShare,
		chiShare:      chiShare,
		delta:         delta,
		AdditiveShift: []byte{0x01, 0x02, 0x03},
	}

	p.Destroy()

	if !IsPresignConsumed(p) {
		t.Error("presign not consumed after Destroy")
	}
	if p.kShare.FixedLen() != 0 {
		t.Error("kShare not zeroed")
	}
	if p.chiShare.FixedLen() != 0 {
		t.Error("chiShare not zeroed")
	}
	if p.delta.FixedLen() != 0 {
		t.Error("delta not zeroed")
	}
	testutil.AssertBytesCleared(t, p.AdditiveShift)
}

// TestDestroy_Idempotent verifies that calling Destroy twice does not panic.
func TestDestroy_Idempotent(t *testing.T) {
	t.Parallel()
	// KeygenSession double-Destroy.
	secretScalar, _ := secpSecretScalarFromBig(big.NewInt(42))
	kg := &KeygenSession{
		shares: map[tss.PartyID]*big.Int{2: new(big.Int).SetInt64(1)},
		pending: &pendingKeyShare{
			share: &KeyShare{secret: secretScalar},
		},
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
