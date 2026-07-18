package secp256k1

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
)

func fillSecretScalar(t *testing.T, seed byte) *secret.Scalar {
	t.Helper()
	data := make([]byte, secp.ScalarSize)
	for i := range data {
		data[i] = seed + byte(i)
	}
	out, err := newSecpSecretScalar(data)
	clear(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustTestSecretScalar(t *testing.T, value uint64) *secret.Scalar {
	t.Helper()
	out, err := secpSecretScalarFromScalar(secp.ScalarFromUint64(value))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func testPaillierPublicKey(seed int64) *pai.PublicKey {
	n := big.NewInt(seed)
	return &pai.PublicKey{N: n, G: big.NewInt(seed + 1), NSquared: new(big.Int).Mul(n, n)}
}

func testPaillierPrivateKey(t *testing.T) *pai.PrivateKey {
	t.Helper()
	return &pai.PrivateKey{
		PublicKey: testPaillierPublicKey(65),
		Lambda:    mustTestSecretScalar(t, 1),
		Mu:        mustTestSecretScalar(t, 2),
		P:         mustTestSecretScalar(t, 3),
		Q:         mustTestSecretScalar(t, 4),
	}
}

func assertScalarDestroyed(t *testing.T, name string, scalar *secret.Scalar) {
	t.Helper()
	if scalar == nil || scalar.FixedLen() != 0 {
		t.Fatalf("%s was not destroyed", name)
	}
}

func TestKeygenSessionDestroyClearsFigure6AndAuxInfoSecrets(t *testing.T) {
	t.Parallel()
	figureContribution := mustTestSecretScalar(t, 11)
	auxContribution := mustTestSecretScalar(t, 12)
	pendingSecret := mustTestSecretScalar(t, 13)
	figureChain := []byte{1, 2, 3}
	pendingChain := []byte{4, 5, 6}
	auxPrivate := testPaillierPrivateKey(t)
	s := &KeygenSession{
		state: keygenCollectingRound1,
		figure6: &figure6State{local: &figure6LocalState{
			contribution: figureContribution,
			chainCode:    figureChain,
		}},
		auxInfo: &auxInfoState{local: &auxInfoLocalState{
			contribution: auxContribution,
			paillier:     auxPrivate,
		}},
		pending: &KeyShare{state: &keyShareState{Secret: pendingSecret, ChainCode: pendingChain}},
	}

	s.Destroy()

	if !s.aborted || s.state != keygenAborted || s.figure6 != nil || s.auxInfo != nil || s.pending != nil {
		t.Fatal("keygen session retained terminal secret state")
	}
	assertScalarDestroyed(t, "Figure 6 contribution", figureContribution)
	assertScalarDestroyed(t, "AuxInfo contribution", auxContribution)
	assertScalarDestroyed(t, "pending key share", pendingSecret)
	testutil.AssertBytesCleared(t, figureChain)
	testutil.AssertBytesCleared(t, pendingChain)
	assertScalarDestroyed(t, "AuxInfo Paillier lambda", auxPrivate.Lambda)
}

func testDerivationResult() (*tss.DerivationResult, [][]byte, []tss.DerivationPath) {
	childPublic := []byte{1, 2, 3}
	childChain := []byte{4, 5, 6}
	shift := []byte{7, 8, 9}
	requested := tss.DerivationPath{1, 2}
	resolved := tss.DerivationPath{1, 2}
	return &tss.DerivationResult{
		Scheme:         tss.DerivationSchemeBIP32Secp256k1,
		ChildPublicKey: childPublic,
		ChildChainCode: childChain,
		RequestedPath:  requested,
		ResolvedPath:   resolved,
		AdditiveShift:  shift,
	}, [][]byte{childPublic, childChain, shift}, []tss.DerivationPath{requested, resolved}
}

func assertDerivationDestroyed(t *testing.T, byteFields [][]byte, paths []tss.DerivationPath) {
	t.Helper()
	for _, field := range byteFields {
		testutil.AssertBytesCleared(t, field)
	}
	for _, path := range paths {
		for i, value := range path {
			if value != 0 {
				t.Fatalf("derivation path element %d was not cleared", i)
			}
		}
	}
}

func TestPresignSessionDestroyClearsFigure8Secrets(t *testing.T) {
	t.Parallel()
	kShare := mustTestSecretScalar(t, 21)
	gamma := mustTestSecretScalar(t, 22)
	a := mustTestSecretScalar(t, 23)
	b := mustTestSecretScalar(t, 24)
	xBar := mustTestSecretScalar(t, 25)
	delta := mustTestSecretScalar(t, 26)
	chi := mustTestSecretScalar(t, 27)
	alpha := mustTestSecretScalar(t, 28)
	derivation, derivationBytes, derivationPaths := testDerivationResult()
	encK := []byte{0xaa, 0xbb}
	deltaPoint := []byte{0xcc}
	privateKey := testPaillierPrivateKey(t)
	s := &PresignSession{
		kShare:     kShare,
		gamma:      gamma,
		a:          a,
		b:          b,
		xBar:       xBar,
		paillier:   privateKey,
		derivation: derivation,
		partyIndex: map[tss.PartyID]int{2: 0},
		parties: []presignPartyState{{
			id: 2,
			round1: presignRound1State{payload: presignRound1Payload{
				EncK: encK, PaillierPublicKey: testPaillierPublicKey(91),
			}},
			round3: presignRound3State{delta: delta, chi: chi, deltaPoint: deltaPoint},
			mta:    presignMTAState{alphaDelta: alpha},
		}},
	}

	s.Destroy()

	if !s.aborted || s.kShare != nil || s.gamma != nil || s.a != nil || s.b != nil || s.xBar != nil || s.paillier != nil || s.derivation != nil || s.parties != nil || len(s.partyIndex) != 0 {
		t.Fatal("presign session retained terminal secret state")
	}
	for name, scalar := range map[string]*secret.Scalar{
		"k": kShare, "gamma": gamma, "a": a, "b": b, "x": xBar,
		"delta": delta, "chi": chi, "alpha": alpha,
	} {
		assertScalarDestroyed(t, name, scalar)
	}
	assertScalarDestroyed(t, "Paillier lambda", privateKey.Lambda)
	testutil.AssertBytesCleared(t, encK)
	testutil.AssertBytesCleared(t, deltaPoint)
	assertDerivationDestroyed(t, derivationBytes, derivationPaths)
}

func TestSignSessionDestroyClearsAttemptAndPartials(t *testing.T) {
	t.Parallel()
	digest := []byte{1, 2, 3}
	publicKey := []byte{4, 5, 6}
	exactOutbox := []byte{7, 8, 9}
	signatureR := []byte{10}
	signatureS := []byte{11}
	s := &SignSession{
		digest:    digest,
		publicKey: publicKey,
		partials:  map[tss.PartyID]secp.Scalar{2: secp.ScalarOne()},
		signature: &Signature{R: signatureR, S: signatureS},
	}
	s.attempt.ExactOutbox = exactOutbox

	s.Destroy()

	if !s.aborted || s.digest != nil || s.publicKey != nil || s.signature != nil || len(s.partials) != 0 || s.attempt.ExactOutbox != nil {
		t.Fatal("sign session retained terminal attempt state")
	}
	for _, field := range [][]byte{digest, publicKey, exactOutbox, signatureR, signatureS} {
		testutil.AssertBytesCleared(t, field)
	}
}

func TestRefreshSessionDestroyClearsPreparedEpoch(t *testing.T) {
	t.Parallel()
	contribution := mustTestSecretScalar(t, 31)
	newSecret := mustTestSecretScalar(t, 32)
	chainCode := []byte{1, 3, 5}
	privateKey := testPaillierPrivateKey(t)
	s := &RefreshSession{
		partyData: map[tss.PartyID]*refreshPartyData{1: {}},
		accepted:  make(map[paperKeygenMessageKey]struct{}),
		auxInfo: &auxInfoState{local: &auxInfoLocalState{
			contribution: contribution,
			paillier:     privateKey,
		}},
		newShare: &KeyShare{state: &keyShareState{Secret: newSecret, ChainCode: chainCode}},
	}

	s.Destroy()

	if !s.aborted || s.auxInfo != nil || s.newShare != nil || len(s.partyData) != 0 || s.accepted != nil {
		t.Fatal("refresh session retained prepared epoch state")
	}
	assertScalarDestroyed(t, "refresh contribution", contribution)
	assertScalarDestroyed(t, "refreshed share", newSecret)
	assertScalarDestroyed(t, "refresh Paillier lambda", privateKey.Lambda)
	testutil.AssertBytesCleared(t, chainCode)
}

func TestKeyShareDestroyClearsSecrets(t *testing.T) {
	t.Parallel()
	share := mustTestSecretScalar(t, 41)
	chainCode := []byte{2, 4, 6}
	privateKey := testPaillierPrivateKey(t)
	key := &KeyShare{state: &keyShareState{Secret: share, ChainCode: chainCode, PaillierPrivateKey: privateKey}}

	key.Destroy()

	assertScalarDestroyed(t, "key share", share)
	assertScalarDestroyed(t, "key Paillier lambda", privateKey.Lambda)
	testutil.AssertBytesCleared(t, chainCode)
}

func TestPresignDestroyClearsNormalizedTuple(t *testing.T) {
	t.Parallel()
	kShare := mustTestSecretScalar(t, 51)
	chiShare := mustTestSecretScalar(t, 52)
	derivation, derivationBytes, derivationPaths := testDerivationResult()
	presignID := []byte{1, 2, 3}
	epochID := []byte{4, 5, 6}
	deltaPoint := []byte{7, 8}
	sPoint := []byte{9, 10}
	p := &Presign{state: &presignState{
		Consumed:   newAtomicBool(),
		attempt:    newPresignAttemptBinding(false),
		KShare:     kShare,
		ChiShare:   chiShare,
		PresignID:  presignID,
		EpochID:    epochID,
		Derivation: derivation,
		Commitments: []normalizedPresignCommitment{{
			Party: 1, DeltaTilde: deltaPoint, STilde: sPoint,
		}},
	}}

	p.Destroy()

	if !IsPresignConsumed(p) || p.state.Derivation != nil || p.state.Commitments != nil {
		t.Fatal("destroyed presign remained available")
	}
	assertScalarDestroyed(t, "normalized k", kShare)
	assertScalarDestroyed(t, "normalized chi", chiShare)
	for _, field := range [][]byte{presignID, epochID, deltaPoint, sPoint} {
		testutil.AssertBytesCleared(t, field)
	}
	assertDerivationDestroyed(t, derivationBytes, derivationPaths)
}

func TestProtocolDestroyIsIdempotent(t *testing.T) {
	t.Parallel()
	keygen := &KeygenSession{figure6: &figure6State{local: &figure6LocalState{contribution: mustTestSecretScalar(t, 61)}}}
	presign := &PresignSession{kShare: mustTestSecretScalar(t, 62)}
	sign := &SignSession{partials: map[tss.PartyID]secp.Scalar{1: secp.ScalarOne()}}
	refresh := &RefreshSession{partyData: make(map[tss.PartyID]*refreshPartyData)}

	for range 2 {
		keygen.Destroy()
		presign.Destroy()
		sign.Destroy()
		refresh.Destroy()
	}
	var nilKeygen *KeygenSession
	var nilPresign *PresignSession
	var nilSign *SignSession
	var nilRefresh *RefreshSession
	nilKeygen.Destroy()
	nilPresign.Destroy()
	nilSign.Destroy()
	nilRefresh.Destroy()
}
