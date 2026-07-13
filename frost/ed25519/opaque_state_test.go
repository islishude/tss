package ed25519

import (
	"reflect"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
)

func TestFROSTLongLivedStateTypesHaveNoExportedFields(t *testing.T) {
	t.Parallel()
	for _, typ := range []reflect.Type{
		reflect.TypeFor[KeyShare](),
		reflect.TypeFor[SecretKey](),
		reflect.TypeFor[TrustedDealerImportPlan](),
		reflect.TypeFor[TrustedDealerContribution](),
	} {
		for field := range typ.Fields() {
			if field.IsExported() {
				t.Errorf("%s has exported field %s", typ.Name(), field.Name)
			}
		}
	}
}

func TestFROSTKeyShareGettersReturnOwnedSnapshots(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.state.Parties = tss.NewPartySet(1, 2)
	k.state.GroupCommitments = groupCommitments{points: []*fed.Point{
		fed.NewGeneratorPoint(),
		fed.NewIdentityPoint(),
	}}
	k.state.PartyData = map[tss.PartyID]keySharePartyData{
		1: {VerificationShare: verificationSharePoint{p: fed.NewGeneratorPoint()}, KeygenConfirmation: &KeygenConfirmation{Sender: 1}},
		2: {VerificationShare: verificationSharePoint{p: fed.NewIdentityPoint()}, KeygenConfirmation: &KeygenConfirmation{Sender: 2}},
	}
	groupBefore := k.state.GroupCommitments.BytesList()
	shareBefore := k.state.PartyData[1].VerificationShare.Bytes()

	metadata := mustKeyShareMetadata(t, k)
	metadata.Parties[0] = 99
	metadata.GroupCommitments[0][0] = 99
	verificationShare, ok := k.VerificationShare(1)
	if !ok {
		t.Fatal("missing verification share")
	}
	verificationShare.PublicKey.p.Set(fed.NewIdentityPoint())
	confirmation, ok := k.KeygenConfirmation(1)
	if !ok {
		t.Fatal("missing keygen confirmation")
	}
	confirmation.Sender = 99

	if k.state.Parties[0] != 1 ||
		!reflect.DeepEqual(k.state.GroupCommitments.BytesList(), groupBefore) ||
		!reflect.DeepEqual(k.state.PartyData[1].VerificationShare.Bytes(), shareBefore) ||
		k.state.PartyData[1].KeygenConfirmation.Sender != 1 {
		t.Fatal("KeyShare getter snapshot aliases internal state")
	}
}

func TestFROSTShallowKeyShareCopiesShareDestroyLifecycle(t *testing.T) {
	t.Parallel()
	secretBytes := make([]byte, 32)
	secretBytes[0] = 1
	secretScalar, err := newEdSecretScalar(secretBytes)
	if err != nil {
		t.Fatal(err)
	}
	key := &KeyShare{state: &keyShareState{
		Secret:    secretScalar,
		ChainCode: []byte{1, 2},
	}}
	handle := *key
	handle.Destroy()
	if key.state.Secret.FixedLen() != 0 || key.state.ChainCode[0] != 0 {
		t.Fatal("shallow KeyShare copy did not share Destroy lifecycle")
	}
}
