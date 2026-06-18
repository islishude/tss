package secp256k1

import (
	"bytes"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"
)

func TestFast_LongLivedStateTypesHaveNoExportedFields(t *testing.T) {
	t.Parallel()
	for _, value := range []any{KeyShare{}, Presign{}, ResharePlan{}} {
		typ := reflect.TypeOf(value)
		for field := range typ.Fields() {
			if field.IsExported() {
				t.Errorf("%s has exported field %s", typ.Name(), field.Name)
			}
		}
	}
}

func TestFast_CryptographicStateUsesTypedMaterial(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		typ    reflect.Type
		fields []string
	}{
		{
			typ: reflect.TypeFor[keyShareState](),
			fields: []string{
				"paillierPublicKey",
				"paillierPrivateKey",
				"paillierProof",
				"paillierPublicKeys",
				"ringPedersenParams",
				"ringPedersenProof",
				"ringPedersenPublic",
			},
		},
		{
			typ:    reflect.TypeFor[keygenPartyData](),
			fields: []string{"paillierPub", "ringPedersen"},
		},
		{
			typ:    reflect.TypeFor[refreshPartyData](),
			fields: []string{"paillierPub", "ringPedersen"},
		},
		{
			typ:    reflect.TypeFor[reshareNewPartyData](),
			fields: []string{"paillierPub", "ringPedersen"},
		},
	} {
		for _, name := range tc.fields {
			field, ok := tc.typ.FieldByName(name)
			if !ok {
				t.Fatalf("%s missing field %s", tc.typ.Name(), name)
			}
			if field.Type == reflect.TypeFor[[]byte]() ||
				field.Type == reflect.TypeFor[PaillierPublicShare]() ||
				field.Type == reflect.TypeFor[RingPedersenPublicShare]() ||
				field.Type == reflect.TypeFor[[]PaillierPublicShare]() ||
				field.Type == reflect.TypeFor[[]RingPedersenPublicShare]() {
				t.Errorf("%s.%s still uses a wire snapshot type", tc.typ.Name(), name)
			}
		}
	}
}

func TestFast_KeyShareGettersReturnOwnedSnapshots(t *testing.T) {
	t.Parallel()
	k := minimalKeyShare()
	k.state.parties = tss.NewPartySet(1, 2)
	k.state.groupCommitments = [][]byte{{1}, {2}}
	k.state.verificationShares = []VerificationShare{{Party: 1, PublicKey: []byte{3}}}
	paillierMaterial, err := paillierPublicMaterialFromSnapshot(testPaillierPublicShare(t), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	ringPedersenMaterial, err := ringPedersenPublicMaterialFromSnapshot(testRingPedersenPublicShare(t), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	k.state.paillierPublicKeys = []paillierPublicMaterial{paillierMaterial}
	k.state.ringPedersenPublic = []ringPedersenPublicMaterial{ringPedersenMaterial}
	k.state.keygenConfirmations = []*KeygenConfirmation{{Sender: 8}}
	paillierBefore, err := k.state.paillierPublicKeys[0].snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	ringPedersenBefore, err := k.state.ringPedersenPublic[0].snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	parties := k.Parties()
	parties[0] = 99
	commitments := k.GroupCommitments()
	commitments[0][0] = 99
	verificationShares := k.VerificationShares()
	verificationShares[0].PublicKey[0] = 99
	paillierShares := k.PaillierPublicKeys()
	paillierShares[0].PublicKey[0] = 99
	paillierShares[0].Proof[0] = 99
	ringPedersenShares := k.RingPedersenPublic()
	ringPedersenShares[0].Params[0] = 99
	ringPedersenShares[0].Proof[0] = 99
	confirmations := k.KeygenConfirmations()
	confirmations[0].Sender = 99

	paillierAfter, err := k.state.paillierPublicKeys[0].snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	ringPedersenAfter, err := k.state.ringPedersenPublic[0].snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if k.state.parties[0] != 1 ||
		k.state.groupCommitments[0][0] != 1 ||
		k.state.verificationShares[0].PublicKey[0] != 3 ||
		!reflect.DeepEqual(paillierBefore, paillierAfter) ||
		!reflect.DeepEqual(ringPedersenBefore, ringPedersenAfter) ||
		k.state.keygenConfirmations[0].Sender != 8 {
		t.Fatal("KeyShare getter snapshot aliases internal state")
	}
}

func TestFast_PresignGettersReturnOwnedSnapshots(t *testing.T) {
	t.Parallel()
	p := minimalCGGMP21Presign(t)
	p.state.context.Derivation.Path = tss.DerivationPath([]uint32{1, 2}).Clone()
	p.state.derivation.RequestedPath = tss.DerivationPath{1, 2}
	p.state.derivation.ResolvedPath = tss.DerivationPath{1, 2}
	p.state.derivation.AdditiveShift = bytes.Repeat([]byte{9}, 32)

	signers := p.Signers()
	signers[0] = 99
	context := p.Context()
	context.Derivation.Path[0] = 99
	verifyShares := p.VerifyShares()
	verifyShares[0].KPoint[0] ^= 1
	verifyShares[0].ChiPoint[0] ^= 1
	verifyShares[0].Proof[0] ^= 1
	derivation := p.Derivation()
	derivation.AdditiveShift[0] = 99
	verificationKey := p.VerificationKeyBytes()
	verificationKey[0] ^= 1

	if p.state.signers[0] != 1 ||
		p.state.context.Derivation.Path[0] != 1 ||
		p.state.verifyShares[0].KPoint[0] == verifyShares[0].KPoint[0] ||
		p.state.verifyShares[0].ChiPoint[0] == verifyShares[0].ChiPoint[0] ||
		p.state.verifyShares[0].Proof[0] == verifyShares[0].Proof[0] ||
		p.state.derivation.AdditiveShift[0] != 9 ||
		p.state.derivation.ChildPublicKey[0] == verificationKey[0] {
		t.Fatal("Presign getter snapshot aliases internal state")
	}
}

func TestFast_ShallowCopiesShareLifecycleState(t *testing.T) {
	t.Parallel()
	privateKey := testPaillierPrivateKey(t)
	key := &KeyShare{state: &keyShareState{
		chainCode:          []byte{1, 2},
		secret:             fillSecretScalar(t, 1),
		paillierPrivateKey: privateKey,
	}}
	keyHandle := *key
	keyHandle.Destroy()
	if key.state.secret.FixedLen() != 0 || key.state.chainCode[0] != 0 || privateKey.Lambda.FixedLen() != 0 {
		t.Fatal("shallow KeyShare copy did not share Destroy lifecycle")
	}

	presign := &Presign{state: &presignState{version: tss.Version, consumed: new(atomic.Bool), attempt: newPresignAttemptBinding(false)}}
	presignHandle := *presign
	if err := MarkPresignConsumed(&presignHandle); err != nil {
		t.Fatal(err)
	}
	if !IsPresignConsumed(presign) {
		t.Fatal("shallow Presign copy did not share consumed state")
	}
}

func TestFast_KeygenAccessorReturnsIndependentKeyShareState(t *testing.T) {
	t.Parallel()
	privateKey := testPaillierPrivateKey(t)
	internal := &KeyShare{state: &keyShareState{
		secret:             fillSecretScalar(t, 7),
		chainCode:          []byte{1, 2},
		paillierPrivateKey: privateKey,
	}}
	session := &KeygenSession{
		state:     keygenConfirmed,
		completed: true,
		keyShare:  internal,
	}
	share, ok := session.KeyShare()
	if !ok {
		t.Fatal("KeyShare accessor did not return completed share")
	}
	share.Destroy()
	if internal.state.secret.FixedLen() == 0 ||
		internal.state.chainCode[0] == 0 ||
		privateKey.Lambda.FixedLen() == 0 {
		t.Fatal("destroying accessor result changed session-owned key share")
	}
}
