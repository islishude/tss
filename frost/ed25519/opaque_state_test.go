package ed25519

import (
	"reflect"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
)

func TestFROSTKeyShareHasNoExportedFields(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeFor[KeyShare]()
	for field := range typ.Fields() {
		if field.IsExported() {
			t.Errorf("KeyShare has exported field %s", field.Name)
		}
	}
}

func TestFROSTKeyShareGettersReturnOwnedSnapshots(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.state.parties = tss.NewPartySet(1, 2)
	k.state.groupCommitments = groupCommitments{points: []*fed.Point{
		fed.NewGeneratorPoint(),
		fed.NewIdentityPoint(),
	}}
	k.state.partyData = map[tss.PartyID]keySharePartyData{
		1: {verificationShare: verificationSharePoint{p: fed.NewGeneratorPoint()}, keygenConfirmation: &KeygenConfirmation{Sender: 1}},
		2: {verificationShare: verificationSharePoint{p: fed.NewIdentityPoint()}, keygenConfirmation: &KeygenConfirmation{Sender: 2}},
	}
	groupBefore := k.state.groupCommitments.BytesList()
	shareBefore := k.state.partyData[1].verificationShare.Bytes()

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

	if k.state.parties[0] != 1 ||
		!reflect.DeepEqual(k.state.groupCommitments.BytesList(), groupBefore) ||
		!reflect.DeepEqual(k.state.partyData[1].verificationShare.Bytes(), shareBefore) ||
		k.state.partyData[1].keygenConfirmation.Sender != 1 {
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
		secret:    secretScalar,
		chainCode: []byte{1, 2},
	}}
	handle := *key
	handle.Destroy()
	if key.state.secret.FixedLen() != 0 || key.state.chainCode[0] != 0 {
		t.Fatal("shallow KeyShare copy did not share Destroy lifecycle")
	}
}
