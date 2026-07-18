package tss

import "testing"

func TestSignIntentCopiesCallerOwnedState(t *testing.T) {
	t.Parallel()
	intent := SignIntent{
		SessionID: SessionID{1},
		Context: SigningContext{
			KeyID:   "key",
			ChainID: "chain",
			Derivation: DerivationRequest{
				Path:         DerivationPath{1, 2},
				ResolvedPath: DerivationPath{1, 3},
			},
			PolicyDomain:  "policy",
			MessageDomain: "message",
		},
		Message: []byte("payload"),
		Signers: NewPartySet(1, 2),
	}

	clone := intent.Clone()
	request := intent.Request()
	intent.Context.Derivation.Path[0] = 9
	intent.Message[0] = 'x'
	intent.Signers[0] = 9

	if clone.Context.Derivation.Path[0] != 1 || clone.Message[0] != 'p' || clone.Signers[0] != 1 {
		t.Fatal("SignIntent.Clone did not return independent state")
	}
	if request.Context.Derivation.Path[0] != 1 || request.Message[0] != 'p' {
		t.Fatal("SignIntent.Request did not return independent state")
	}
}
