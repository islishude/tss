package secp256k1

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
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

func TestFast_PublicGettersDoNotReturnMutableContainers(t *testing.T) {
	t.Parallel()
	for _, typ := range []reflect.Type{
		reflect.TypeFor[*KeyShare](),
		reflect.TypeFor[*Presign](),
		reflect.TypeFor[*KeygenPlan](),
		reflect.TypeFor[*RefreshPlan](),
		reflect.TypeFor[*PresignPlan](),
		reflect.TypeFor[*SignPlan](),
		reflect.TypeFor[*ResharePlan](),
	} {
		for method := range typ.Methods() {
			if method.Name == "Derive" ||
				method.Name == "Digest" ||
				strings.HasPrefix(method.Name, "Marshal") ||
				strings.HasPrefix(method.Name, "Unmarshal") {
				continue
			}
			fn := method.Type
			for returnType := range fn.Outs() {
				if returnType.Kind() == reflect.Slice || returnType.Kind() == reflect.Map {
					t.Fatalf("%s.%s returns mutable container type %s", typ, method.Name, returnType)
				}
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
				"PartyData",
				"PaillierPrivateKey",
			},
		},
		{
			typ:    reflect.TypeFor[keygenRound1Slot](),
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
	k.state.Parties = tss.NewPartySet(1)
	k.state.GroupCommitments = []*secp.Point{testCurvePoint(1), testCurvePoint(2)}
	paillierMaterial, err := paillierPublicMaterialFromSnapshot(testPaillierPublicShare(t), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	ringPedersenMaterial, err := ringPedersenPublicMaterialFromSnapshot(testRingPedersenPublicShare(t), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	k.state.PartyData = map[tss.PartyID]keySharePartyData{
		1: {
			VerificationShare:  []byte{3},
			PaillierPublicKey:  paillierMaterial.PublicKey,
			PaillierProof:      paillierMaterial.Proof,
			RingPedersenParams: ringPedersenMaterial.Params,
			RingPedersenProof:  ringPedersenMaterial.Proof,
			KeygenConfirmation: &KeygenConfirmation{Sender: 1},
		},
	}
	dataBefore := k.state.PartyData[1]
	paillierBefore, err := (paillierPublicMaterial{Party: 1, PublicKey: dataBefore.PaillierPublicKey, Proof: dataBefore.PaillierProof}).snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	ringPedersenBefore, err := (ringPedersenPublicMaterial{Party: 1, Params: dataBefore.RingPedersenParams, Proof: dataBefore.RingPedersenProof}).snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	meta := mustKeyShareMetadata(t, k)
	originalCommitment := append([]byte(nil), meta.GroupCommitments[0]...)
	meta.Parties[0] = 99
	meta.GroupCommitments[0][0] = 99
	verificationShare, ok := k.VerificationShare(1)
	if !ok {
		t.Fatal("missing verification share")
	}
	verificationShare.PublicKey[0] = 99
	paillierShare, ok := k.PaillierPublicShare(1)
	if !ok {
		t.Fatal("missing Paillier public share")
	}
	paillierShare.PublicKey[0] = 99
	paillierShare.Proof[0] = 99
	ringPedersenShare, ok := k.RingPedersenPublicShare(1)
	if !ok {
		t.Fatal("missing Ring-Pedersen public share")
	}
	ringPedersenShare.Params[0] = 99
	ringPedersenShare.Proof[0] = 99
	confirmation, ok := k.KeygenConfirmation(1)
	if !ok {
		t.Fatal("missing keygen confirmation")
	}
	confirmation.Sender = 99

	dataAfter := k.state.PartyData[1]
	metaAfter := mustKeyShareMetadata(t, k)
	paillierAfter, err := (paillierPublicMaterial{Party: 1, PublicKey: dataAfter.PaillierPublicKey, Proof: dataAfter.PaillierProof}).snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	ringPedersenAfter, err := (ringPedersenPublicMaterial{Party: 1, Params: dataAfter.RingPedersenParams, Proof: dataAfter.RingPedersenProof}).snapshot(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if k.state.Parties[0] != 1 ||
		metaAfter.GroupCommitments[0][0] != originalCommitment[0] ||
		dataAfter.VerificationShare[0] != 3 ||
		!reflect.DeepEqual(paillierBefore, paillierAfter) ||
		!reflect.DeepEqual(ringPedersenBefore, ringPedersenAfter) ||
		dataAfter.KeygenConfirmation.Sender != 1 {
		t.Fatal("KeyShare getter snapshot aliases internal state")
	}
}

func TestFast_PresignGettersReturnOwnedSnapshots(t *testing.T) {
	t.Parallel()
	p := minimalCGGMP21Presign(t)
	p.state.Context.Derivation.Path = tss.DerivationPath([]uint32{1, 2}).Clone()
	p.state.Derivation.RequestedPath = tss.DerivationPath{1, 2}
	p.state.Derivation.ResolvedPath = tss.DerivationPath{1, 2}
	p.state.Derivation.AdditiveShift = bytes.Repeat([]byte{9}, 32)

	meta := mustPresignMetadata(t, p)
	meta.Signers[0] = 99
	meta.Context.Derivation.Path[0] = 99
	meta.R[0] ^= 1
	meta.LittleR[0] ^= 1
	meta.PublicKey[0] ^= 1
	meta.Derivation.AdditiveShift[0] = 99
	meta.VerificationKey[0] ^= 1

	rBytes, err := secp.PointBytes(p.state.R)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBytes, err := secp.PointBytes(p.state.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if p.state.Signers[0] != 1 ||
		p.state.Context.Derivation.Path[0] != 1 ||
		rBytes[0] == meta.R[0] ||
		p.state.LittleR.Bytes()[0] == meta.LittleR[0] ||
		publicKeyBytes[0] == meta.PublicKey[0] ||
		p.state.Derivation.AdditiveShift[0] != 9 ||
		p.state.Derivation.ChildPublicKey[0] == meta.VerificationKey[0] {
		t.Fatal("Presign getter snapshot aliases internal state")
	}
}

func TestFast_ShallowCopiesShareLifecycleState(t *testing.T) {
	t.Parallel()
	privateKey := testPaillierPrivateKey(t)
	key := &KeyShare{state: &keyShareState{
		ChainCode:          []byte{1, 2},
		Secret:             fillSecretScalar(t, 1),
		PaillierPrivateKey: privateKey,
	}}
	keyHandle := *key
	keyHandle.Destroy()
	if key.state.Secret.FixedLen() != 0 || key.state.ChainCode[0] != 0 || privateKey.Lambda.FixedLen() != 0 {
		t.Fatal("shallow KeyShare copy did not share Destroy lifecycle")
	}

	presign := &Presign{state: &presignState{Consumed: NewAtomicBoolWire(false), attempt: newPresignAttemptBinding(false)}}
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
		Secret:             fillSecretScalar(t, 7),
		ChainCode:          []byte{1, 2},
		PaillierPrivateKey: privateKey,
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
	if internal.state.Secret.FixedLen() == 0 ||
		internal.state.ChainCode[0] == 0 ||
		privateKey.Lambda.FixedLen() == 0 {
		t.Fatal("destroying accessor result changed session-owned key share")
	}
}
