package ed25519

import (
	"reflect"
	"testing"

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
	k.state.groupCommitments = [][]byte{{1}, {2}}
	k.state.verificationShares = []VerificationShare{{Party: 1, PublicKey: []byte{3}}}
	k.state.keygenConfirmations = [][]byte{{4}}

	parties := k.Parties()
	parties[0] = 99
	commitments := k.GroupCommitments()
	commitments[0][0] = 99
	verificationShares := k.VerificationShares()
	verificationShares[0].PublicKey[0] = 99
	confirmations := k.KeygenConfirmations()
	confirmations[0][0] = 99

	if k.state.parties[0] != 1 ||
		k.state.groupCommitments[0][0] != 1 ||
		k.state.verificationShares[0].PublicKey[0] != 3 ||
		k.state.keygenConfirmations[0][0] != 4 {
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
